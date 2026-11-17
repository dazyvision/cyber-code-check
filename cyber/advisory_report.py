"""Rapports locaux de correspondances OSV, distincts d'un test d'exploitation."""

import json
import os
import tempfile
from pathlib import Path

from .report_style import CSS, _h, _md, _source_link
from .scan_report import validate_output_location


LIMITATIONS = [
    "Une correspondance de version avec un avis ne prouve pas son exploitabilité dans l'application.",
    "Une réponse sans avis n'exclut ni une vulnérabilité inconnue, ni un paquet malveillant, ni un défaut de configuration.",
    "Le résultat est daté : les bases d'avis évoluent. Aucun suivi périodique n'est installé.",
    "Le lockfile décrit des dépendances prévues ; leur chargement effectif, les binaires déployés et les runtimes hébergés ne sont pas inspectés.",
    "Les exclusions et les erreurs restent visibles. Les dépendances de développement et optionnelles sont conservées dans le périmètre admissible.",
    "L'API reçoit uniquement les noms et versions admissibles de paquets npm, pas le code, les valeurs de secrets ou les chemins locaux.",
    "Une URL registry.npmjs.org ne prouve pas qu'un paquet scoped est public : examiner l'inventaire avec --inventory-only avant d'autoriser --online.",
]


def advisory_exit_code(report, fail_on="any"):
    if not report["coverage"]["complete"]:
        return 2
    return int(fail_on == "any" and bool(report["findings"]))


def render_advisory_html(report):
    coverage, inventory = report["coverage"], report["inventory"]
    findings = report["findings"]
    label = "Consultation terminée dans le périmètre" if coverage["complete"] else "Consultation incomplète"
    parts = [
        '<!doctype html><html lang="fr"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">',
        f'<title>CYBER · Avis de sécurité des dépendances</title><style>{CSS} code,td,dd{{overflow-wrap:anywhere}} table{{width:100%;border-collapse:collapse}}th,td{{padding:12px;text-align:left;border-bottom:1px solid #d8dfdc}}th{{font-size:13px}}</style></head><body>',
        '<header><div class="top"><span class="brand">CYBER / 03</span><span>AVIS DE SÉCURITÉ</span></div>',
        '<p class="eyebrow">Lecture du lockfile · base publique OSV</p><h1>Dépendances : état de référence</h1>',
        '<p>Relier les versions exactes aux avis publiés, puis qualifier les conditions qui concernent réellement l’application.</p>',
        f'<span class="scope">{_h(label)} · aucun code cible exécuté</span></header><main><div class="stats">',
    ]
    counts = [(len(inventory["packages"]), "couples nom/version admissibles"),
              (coverage["queried_packages"], "consultations entièrement terminées"),
              (len(findings), "correspondances paquet / avis")]
    for count, title in counts:
        parts.append(f'<div class="stat"><strong>{count}</strong><span>{_h(title)}</span></div>')
    parts += ['</div><p class="note">Un avis correspondant est une piste à qualifier, pas une exploitation démontrée. Le statut incomplet interdit une conclusion globale favorable.</p>',
              f'<p class="muted">Consultation : {_h(report["generated_at"])} · empreinte SHA-256 du lockfile : <code>{_h(inventory["lockfile_sha256"])}</code></p>',
              '<nav><a href="#findings">Correspondances</a><a href="#coverage">Couverture</a><a href="#limits">Limites</a></nav>',
              '<section id="findings"><h2>Avis correspondant aux versions</h2>']
    if not findings:
        parts.append('<p>Aucun avis retourné pour les consultations terminées. Les exclusions et erreurs ci-dessous restent hors de cette conclusion.</p>')
    else:
        parts.append('<table><thead><tr><th>Paquet / version</th><th>Avis</th><th>Dernière modification de l’avis</th></tr></thead><tbody>')
        for item in findings:
            parts.append(f'<tr><td><code>{_h(item["package"])}@{_h(item["version"])}</code></td><td>{_h(item["advisory_id"])}<br>{_source_link(item["source_url"])}</td><td>{_h(item.get("modified", "Non fournie"))}</td></tr>')
        parts.append('</tbody></table><p>Étape suivante : lire l’avis, ses versions corrigées, ses préconditions et les protections de l’hébergement avant de décider du correctif.</p>')
    parts += ['</section><section id="coverage"><h2>Couverture et incidents</h2>']
    for notice in report.get("notices", []):
        parts.append(f'<div class="flow"><strong>{_h(notice["code"])}</strong><p>{_h(notice["message"])}</p></div>')
    if not report.get("notices"):
        parts.append('<p>Aucun incident ou exclusion signalé dans le périmètre prévu.</p>')
    parts += ['<details><summary>Inventaire des paquets admissibles</summary><div class="result-body"><ul>']
    for package in inventory["packages"]:
        kind = "développement" if package["dev"] else "application ou usage mixte"
        parts.append(f'<li><code>{_h(package["name"])}@{_h(package["version"])}</code> · {_h(kind)} · {len(package["paths"])} emplacement(s)</li>')
    parts += ['</ul></div></details></section><section id="limits"><h2>Limites</h2><ul>']
    parts.extend(f'<li>{_h(x)}</li>' for x in dict.fromkeys(report.get("limitations", []) + LIMITATIONS))
    parts += ['</ul></section><footer>Usage interne · Diffusion restreinte<br>Rapport local autonome, sans script ni ressource distante. ',
              '<a href="https://google.github.io/osv.dev/post-v1-querybatch/">Méthode OSV querybatch</a></footer></main></body></html>']
    return ''.join(parts)


def render_advisory_markdown(report):
    coverage = report["coverage"]
    parts = ['# CYBER — avis de sécurité des dépendances', '', '**Usage interne — diffusion restreinte.**', '',
             f'Consultation : {report["generated_at"]}. Couverture complète du périmètre admissible et prévu : {coverage["complete"]}.',
             f'Couples nom/version dont la consultation est terminée : {coverage["queried_packages"]}.',
             f'Empreinte SHA-256 du lockfile : `{report["inventory"]["lockfile_sha256"]}`.', '',
             'Une correspondance de version ne démontre pas une exploitation. Un résultat vide ne constitue pas un certificat de sécurité.', '', '## Correspondances', '']
    for item in report["findings"]:
        parts.append(f'- {_md(item["package"])}@{_md(item["version"])} : [{_md(item["advisory_id"])}]({item["source_url"]}) ; avis modifié le {_md(item.get("modified", "date non fournie"))}.')
    if not report["findings"]:
        parts.append('Aucun avis retourné pour les consultations terminées. Les erreurs et exclusions restent hors de cette conclusion.')
    parts += ['', '## Couverture', '']
    parts += [f'- {_md(x["code"])} : {_md(x["message"])}' for x in report.get("notices", [])]
    parts += ['', '## Limites', ''] + ['- '+x for x in dict.fromkeys(report.get("limitations", []) + LIMITATIONS)]
    parts += ['', '[Documentation OSV querybatch](https://google.github.io/osv.dev/post-v1-querybatch/)', '']
    return '\n'.join(parts)


def write_advisory_report(report, output, *, lockfile):
    destination = validate_output_location(Path(lockfile).parent, output)
    documents = {'index.html': render_advisory_html(report), 'report.md': render_advisory_markdown(report),
                 'report.json': json.dumps({**report, "limitations": list(dict.fromkeys(report.get("limitations", []) + LIMITATIONS))}, ensure_ascii=False, indent=2)+'\n'}
    for name in documents:
        if (destination/name).is_symlink():
            raise ValueError('Un fichier de sortie est un lien symbolique ; écriture refusée.')
    destination.mkdir(parents=True, exist_ok=True)
    for name, text in documents.items():
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=destination, delete=False) as handle:
                temporary = Path(handle.name)
                handle.write(text)
            os.replace(temporary, destination/name)
        finally:
            if temporary and temporary.exists():
                temporary.unlink()

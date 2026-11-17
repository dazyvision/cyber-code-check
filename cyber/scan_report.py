"""Exports locaux expurgés et SARIF 2.1.0 pour la revue de dépôts."""

import json
import os
import tempfile
from pathlib import Path
from urllib.parse import quote

from .report_style import CSS, _h, _md, _source_link

SEVERITIES = {'high': 'Haute', 'medium': 'Modérée', 'low': 'Basse', 'info': 'Information'}
CONFIDENCE = {'high': 'Élevée', 'medium': 'Moyenne', 'low': 'Faible'}


def render_scan_html(report):
    coverage = report['coverage']
    coverage_label = 'Périmètre prévu parcouru' if coverage['complete_within_scope'] else 'Analyse incomplète'
    parts = ['<!doctype html><html lang="fr"><head><meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width,initial-scale=1">',
             '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">',
             f'<title>CYBER · Scan de dépôt</title><style>{CSS} h1,footer,code{{overflow-wrap:anywhere}}</style></head><body>',
             '<header><div class="top"><span class="brand">CYBER / 02</span><span>CODE &amp; CHAÎNE LOGICIELLE</span></div>',
             f'<p class="eyebrow">Inspection statique locale</p><h1>{_h(Path(report["root"]).name)}</h1>',
             '<p>Repérer les comportements et configurations à examiner avant d’installer, d’exécuter ou de confier le dépôt à un agent.</p>',
             f'<span class="scope">{_h(coverage_label)} · aucun code cible exécuté</span></header><main><div class="stats">']
    for severity, label in SEVERITIES.items():
        parts.append(f'<div class="stat"><strong>{report["summary"][severity]}</strong><span>Priorité {label.lower()}</span></div>')
    parts += ['</div><nav><a href="#findings">Signaux détectés</a><a href="#coverage">Couverture</a><a href="#limits">Limites</a></nav>',
              '<p class="note">Un signal est un motif à examiner, pas une preuve de malware. Un rapport sans signal ne certifie pas la sûreté du code. Les valeurs de secrets et les lignes source ne sont pas recopiées dans ce rapport.</p>',
              f'<p class="muted">{coverage["files_analyzed"]} fichiers analysés · {coverage["bytes_read"]:,} octets lus · {_h(report["generated_at"])}</p>',
              '<section id="findings"><p class="eyebrow">01 / Décider avant exécution</p><h2>Signaux détectés</h2>']
    if not report['findings']:
        parts.append('<p>Aucun motif couvert par ces règles n’a été relevé dans les fichiers analysés. Consulter les limites et la couverture avant toute décision.</p>')
    for f in report['findings']:
        badge = 'fail' if f['severity'] == 'high' else 'unknown' if f['severity'] == 'medium' else 'not_applicable'
        opened = ' open' if f['severity'] == 'high' else ''
        parts.append(f'<details{opened}><summary><span class="badge {badge}">{SEVERITIES[f["severity"]]}</span><strong>{_h(f["title"])}</strong><span class="muted">{_h(f["path"])}:{f["line"]} · {_h(f["rule_id"])}</span></summary><div class="result-body"><dl>')
        for label, value in [('Motif relevé', f['evidence']), ('Action proposée', f['recommendation']),
                             ('Confiance dans le motif', CONFIDENCE[f['confidence']]), ('Famille', f['category'])]:
            parts.append(f'<dt>{label}</dt><dd>{_h(value)}</dd>')
        parts.append(f'<dt>Référence</dt><dd>{_source_link(f["source_url"])}</dd></dl></div></details>')
    parts += ['</section><section id="coverage"><p class="eyebrow">02 / Savoir ce qui a été lu</p>',
              f'<h2>{_h(coverage_label)}</h2><p>La couverture concerne les fichiers locaux sélectionnés. Elle ne mesure pas la proportion de menaces détectables.</p>',
              f'<p>Dossiers exclus par politique : {_h(", ".join(coverage["excluded_directory_names"]))}. {coverage["non_text_extensions"]} fichier(s) d’extensions hors périmètre.</p>']
    for n in report['notices']:
        parts.append(f'<div class="flow"><strong>{_h(n["code"])}</strong><p>{_h(n["path"])}</p><p>{_h(n["message"])}</p></div>')
    if not report['notices']:
        parts.append('<p>Aucun incident de lecture ou de parsing signalé dans le périmètre prévu.</p>')
    parts += ['</section><section id="limits"><p class="eyebrow">03 / Interpréter le résultat</p><h2>Limites explicites</h2><ul>']
    parts.extend(f'<li>{_h(item)}</li>' for item in report['limitations'])
    parts.append(f'</ul></section><footer>CYBER {_h(report["engine_version"])} · Empreinte du contenu lu : <code>{_h(report["tree_fingerprint"])}</code><br>Rapport autonome, sans JavaScript ni ressource distante.</footer></main></body></html>')
    return ''.join(parts)


def render_scan_markdown(report):
    parts = [f'# CYBER — scan de {_md(Path(report["root"]).name)}', '',
             f'Date : {report["generated_at"]}. Mode : inspection statique locale.', '',
             '**Un signal n’est pas une preuve de malware. Aucun signal ne signifie pas code sûr.**', '',
             f'Fichiers analysés : {report["coverage"]["files_analyzed"]}. Périmètre parcouru sans incident : {report["coverage"]["complete_within_scope"]}.', '',
             '## Signaux', '']
    for f in report['findings']:
        parts += [f'### {f["rule_id"]} — {_md(f["title"])}', '',
                  f'Priorité : {SEVERITIES[f["severity"]]} · Confiance : {CONFIDENCE[f["confidence"]]}', '',
                  f'Localisation : {_md(f["path"])}:{f["line"]}', '', _md(f['evidence']), '',
                  f'Action : {_md(f["recommendation"])}', '', f'[Source]({f["source_url"]})', '']
    if not report['findings']:
        parts += ['Aucun motif couvert par les règles dans les fichiers lus. Voir les limites ci-dessous.', '']
    parts += ['## Couverture et incidents', '']
    parts += [f'- {n["code"]} · {_md(n["path"])} : {_md(n["message"])}' for n in report['notices']]
    parts += ['', '## Limites', '']
    parts += ['- ' + _md(item) for item in report['limitations']]
    return '\n'.join(parts) + '\n'


def render_sarif(report):
    rules = {}
    for f in report['findings']:
        rules.setdefault(f['rule_id'], {'id': f['rule_id'], 'shortDescription': {'text': f['title']},
                                       'helpUri': f['source_url'], 'help': {'text': f['recommendation']},
                                       'properties': {'tags': ['security', f['category']]}})
    notifications = [{'level': 'warning' if n['incomplete'] else 'note',
                      'descriptor': {'id': n['code']},
                      'message': {'text': f"{n['path']}: {n['message']}"}} for n in report['notices']]
    return {'$schema': 'https://json.schemastore.org/sarif-2.1.0.json', 'version': '2.1.0', 'runs': [{
        'tool': {'driver': {'name': 'CYBER', 'version': report['engine_version'], 'rules': list(rules.values())}},
        'invocations': [{'executionSuccessful': report['coverage']['complete_within_scope'],
                         'toolExecutionNotifications': notifications}],
        'results': [{'ruleId': f['rule_id'],
                     'level': {'high': 'error', 'medium': 'warning', 'low': 'note', 'info': 'note'}[f['severity']],
                     'message': {'text': f["evidence"] + '\n' + f['recommendation']},
                     'locations': [{'physicalLocation': {'artifactLocation': {'uri': quote(f['path'], safe='/')},
                                                         'region': {'startLine': f['line']}}}],
                     'partialFingerprints': {'cyber/v1': f['fingerprint']},
                     'properties': {'confidence': f['confidence'], 'heuristic': True}}
                    for f in report['findings']],
        'properties': {'scope': report['scope'], 'limitations': report['limitations'],
                       'treeFingerprint': report['tree_fingerprint']}}]}


def validate_output_location(root, output):
    root = Path(root).expanduser().resolve(strict=True)
    output = Path(output).expanduser()
    destination = output.resolve()
    if destination == root or root in destination.parents:
        raise ValueError('Placer les rapports hors du dépôt audité pour préserver son contenu.')
    # Canonicalize ancestor directories, but refuse the output directory
    # itself as a symlink. The canonical target must stay
    # outside the source tree, checked above.
    if output.is_symlink():
        raise ValueError('Le dossier de destination ne doit pas être un lien symbolique.')
    return destination


def write_scan_report(report, output):
    destination = validate_output_location(report['root'], output)
    documents = {'index.html': render_scan_html(report), 'report.md': render_scan_markdown(report),
                 'report.json': json.dumps(report, ensure_ascii=False, indent=2) + '\n',
                 'report.sarif': json.dumps(render_sarif(report), ensure_ascii=False, indent=2) + '\n'}
    for name in documents:
        if (destination / name).is_symlink():
            raise ValueError('Un fichier de sortie est un lien symbolique ; écriture refusée.')
    destination.mkdir(parents=True, exist_ok=True)
    for name, text in documents.items():
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=destination, delete=False) as handle:
                temporary = Path(handle.name)
                handle.write(text)
            os.replace(temporary, destination / name)
        finally:
            if temporary and temporary.exists():
                temporary.unlink()

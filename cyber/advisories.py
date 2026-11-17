"""Avis OSV sur des versions npm verrouillées, sans installation ni code cible.

Le mode réseau est explicite. Seuls les couples nom/version dont le chemin
node_modules et l'URL de registry.npmjs.org concordent sont transmis à OSV.
Les URL, chemins locaux, manifestes, secrets et instructions ne sont pas envoyés.
Cette cohérence vérifie la provenance déclarée, pas la visibilité réelle d'un
paquet scoped : l'appelant doit vérifier les noms avant d'autoriser le réseau.
"""

import hashlib
import json
import os
import re
import stat
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

from . import __version__

OSV_QUERY_URL = 'https://api.osv.dev/v1/querybatch'
MAX_LOCKFILE_BYTES = 8 * 1024 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_PACKAGES = 10000
BATCH_SIZE = 100
MAX_PAGES = 10
MAX_VULNS_PER_RESULT = 5000
MAX_FINDINGS = 20000
MAX_NOTICES = 200
NAME_PART = re.compile(r'[a-z0-9][a-z0-9._-]*\Z')
SEMVER = re.compile(
    r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)'
    r'(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?'
    r'(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z'
)
ADVISORY_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,159}\Z')


def _notice(code, message):
    return {'code': code, 'message': message}


class _Notices(list):
    """Borner les diagnostics sans effacer le statut incomplet."""
    def append(self, item):
        if len(self) < MAX_NOTICES:
            super().append(item)
        elif not self or self[-1]['code'] != 'NOTICE_LIMIT':
            super().append(_notice('NOTICE_LIMIT', 'Limite de diagnostics atteinte ; des incidents supplémentaires ne sont pas détaillés.'))


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Clé JSON dupliquée ; interprétation ambiguë refusée.')
        result[key] = value
    return result


def _read_lockfile(path):
    if not all(hasattr(os, key) for key in ('O_NOFOLLOW', 'O_NONBLOCK')):
        raise ValueError('Le lecteur protégé nécessite macOS ou Linux.')
    path = Path(path).expanduser()
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('Le lockfile doit être un fichier régulier, sans lien symbolique.')
        if before.st_size > MAX_LOCKFILE_BYTES:
            raise ValueError('Lockfile trop volumineux ; limite de lecture atteinte.')
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise ValueError('Le type du lockfile a changé ; lecture refusée.')
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise ValueError('Lockfile remplacé pendant son ouverture.')
            raw = handle.read(MAX_LOCKFILE_BYTES + 1)
            after = os.fstat(handle.fileno())
        if len(raw) > MAX_LOCKFILE_BYTES:
            raise ValueError('Lockfile agrandi au-delà de la limite de lecture.')
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('Lockfile modifié pendant sa lecture ; résultat refusé.')
        return raw
    except OSError:
        raise ValueError('Lockfile inaccessible ou changé pendant la lecture.') from None


def _parse_json(raw, context):
    try:
        return json.loads(raw.decode('utf-8-sig'), object_pairs_hook=_unique_keys)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError(f'{context} : JSON UTF-8 invalide ou trop imbriqué.') from None


def _package_name(path):
    """Reconnaître une chaîne npm node_modules, y compris les paquets imbriqués."""
    if not isinstance(path, str) or len(path) > 4096:
        return None
    parts = path.split('/')
    pos, name = 0, None
    while pos < len(parts):
        if parts[pos] != 'node_modules' or pos + 1 >= len(parts):
            return None
        pos += 1
        first = parts[pos]
        if first.startswith('@'):
            if not NAME_PART.fullmatch(first[1:]) or pos + 1 >= len(parts):
                return None
            second = parts[pos + 1]
            if not NAME_PART.fullmatch(second):
                return None
            name = first + '/' + second
            pos += 2
        else:
            if not NAME_PART.fullmatch(first):
                return None
            name = first
            pos += 1
        if len(name) > 214:
            return None
    return name


def _public_resolution(name, version, resolved):
    if not isinstance(resolved, str) or len(resolved) > 4096:
        return False
    try:
        url = urlsplit(resolved)
        if (url.scheme != 'https' or url.netloc != 'registry.npmjs.org'
                or url.query or url.fragment):
            return False
        expected = '/' + name + '/-/' + name.rsplit('/', 1)[-1] + '-' + version + '.tgz'
        return unquote(url.path, errors='strict') == expected
    except (ValueError, UnicodeError):
        return False


def build_inventory(lockfile):
    """Lire un package-lock v2/v3 et valider les résolutions registry.npmjs.org.

    Une entrée exclue rend l'inventaire incomplet. Un champ resolved absent est
    conservateur : même un paquet vraisemblablement public n'est pas envoyé.
    """
    raw = _read_lockfile(lockfile)
    data = _parse_json(raw, 'Lockfile')
    if (not isinstance(data, dict) or type(data.get('lockfileVersion')) is not int
            or data['lockfileVersion'] not in (2, 3) or not isinstance(data.get('packages'), dict)):
        raise ValueError('Seuls les package-lock npm v2/v3 avec objet packages sont pris en charge.')
    entries = data['packages']
    if len(entries) - (1 if '' in entries else 0) > MAX_PACKAGES:
        raise ValueError('Trop d’entrées dans le lockfile ; inventaire refusé.')
    packages, notices = {}, _Notices()
    for path, entry in entries.items():
        if path == '':
            continue
        if not isinstance(entry, dict):
            notices.append(_notice('INVALID_ENTRY', 'Une entrée de paquet n’est pas un objet JSON.'))
            continue
        if entry.get('link'):
            notices.append(_notice('LINK_EXCLUDED', 'Un lien de workspace ou de paquet local n’a pas été transmis.'))
            continue
        name = _package_name(path)
        version = entry.get('version')
        if not name or not isinstance(version, str) or len(version) > 160 or not SEMVER.fullmatch(version):
            notices.append(_notice('IDENTITY_UNSUPPORTED', 'Un chemin npm ou une version exacte n’a pas pu être validé.'))
            continue
        if 'name' in entry and entry['name'] != name:
            notices.append(_notice('ALIAS_EXCLUDED', 'Une identité de paquet différente du chemin npm n’a pas été transmise.'))
            continue
        if not _public_resolution(name, version, entry.get('resolved')):
            notices.append(_notice('RESOLUTION_EXCLUDED', 'Une résolution absente, hors registre npm ou incohérente n’a pas été transmise.'))
            continue
        key = (name, version)
        if key not in packages:
            packages[key] = {'name': name, 'version': version, 'paths': [], 'dev': True}
        packages[key]['paths'].append(path)
        packages[key]['dev'] = packages[key]['dev'] and entry.get('dev') is True
    result = []
    for key in sorted(packages):
        package = packages[key]
        package['paths'].sort()
        result.append(package)
    if not result:
        notices.append(_notice('NO_PUBLIC_PACKAGES', 'Aucun couple npm admissible ; aucune conclusion possible.'))
    return {'lockfile_sha256': hashlib.sha256(raw).hexdigest(), 'packages': result,
            'notices': notices, 'complete': not notices}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _transport(payload):
    body = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    req = urllib.request.Request(OSV_QUERY_URL, data=body, method='POST', headers={
        'Content-Type': 'application/json', 'Accept': 'application/json',
        'User-Agent': 'CYBER/' + __version__,
    })
    # HTTPSHandler's default context verifies certificates and hostnames.
    opener = urllib.request.build_opener(_NoRedirect())
    with opener.open(req, timeout=20) as response:
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError('Réponse OSV au-delà de la limite de lecture.')
    return _parse_json(raw, 'Réponse OSV')


def _valid_modified(value):
    if value is None:
        return True
    if not isinstance(value, str) or len(value) > 64:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return parsed.tzinfo is not None
    except ValueError:
        return False


def audit_lockfile(lockfile, *, online=False, transport=None):
    """Interroger OSV, conserver les constats partiels et expliciter les erreurs.

    coverage.queried_packages compte les couples ayant terminé toutes les pages
    sans anomalie. attempted_packages compte les couples au moins interrogés.
    Une correspondance de version n'établit pas l'exploitabilité de l'application.
    """
    if online is not True:
        raise ValueError('Le mode réseau exige --online ; les noms et versions résolus sur registry.npmjs.org seront envoyés à OSV.')
    inventory = build_inventory(lockfile)
    transport = transport or _transport
    packages = inventory['packages']
    notices = _Notices(inventory['notices'])
    findings, completed, attempted = {}, set(), set()
    budget_exhausted = False
    for start in range(0, len(packages), BATCH_SIZE):
        pending = [(index, None) for index in range(start, min(start + BATCH_SIZE, len(packages)))]
        tokens = {index: set() for index, _ in pending}
        invalid = set()
        for page in range(MAX_PAGES):
            if not pending:
                break
            queries = []
            for index, token in pending:
                item = packages[index]
                query = {'package': {'name': item['name'], 'ecosystem': 'npm'}, 'version': item['version']}
                if token is not None:
                    query['page_token'] = token
                queries.append(query)
                attempted.add(index)
            try:
                response = transport({'queries': queries})
            except Exception:
                # Exceptions may embed credentials, endpoints or untrusted response
                # bodies. Keep reports useful without reflecting those details.
                notices.append(_notice('OSV_REQUEST_FAILED', 'Un lot OSV a échoué ; ses résultats restants sont inconnus.'))
                break
            if (not isinstance(response, dict) or set(response) != {'results'}
                    or not isinstance(response['results'], list) or len(response['results']) != len(pending)):
                notices.append(_notice('OSV_RESPONSE_INVALID', 'Un lot OSV a une structure inattendue ; aucune absence d’avis ne peut en être déduite.'))
                break
            next_pending = []
            for (index, _), result in zip(pending, response['results']):
                package = packages[index]
                if not isinstance(result, dict) or not set(result) <= {'vulns', 'next_page_token'}:
                    notices.append(_notice('OSV_RESULT_INVALID', 'Un résultat OSV a une structure inattendue.'))
                    continue
                vulns = result.get('vulns', [])
                if not isinstance(vulns, list) or len(vulns) > MAX_VULNS_PER_RESULT:
                    notices.append(_notice('OSV_RESULT_INVALID', 'La liste d’avis OSV est invalide ou dépasse la limite.'))
                    continue
                for vuln in vulns:
                    if (not isinstance(vuln, dict) or not set(vuln) <= {'id', 'modified'}
                            or not isinstance(vuln.get('id'), str) or not ADVISORY_ID.fullmatch(vuln['id'])
                            or not _valid_modified(vuln.get('modified'))):
                        invalid.add(index)
                        notices.append(_notice('OSV_ADVISORY_INVALID', 'Un identifiant ou une date d’avis OSV n’est pas valide.'))
                        continue
                    ident = vuln['id']
                    if (index, ident) not in findings and len(findings) >= MAX_FINDINGS:
                        notices.append(_notice('OSV_FINDING_LIMIT', 'Limite globale de correspondances atteinte ; collecte interrompue et incomplète.'))
                        invalid.add(index)
                        budget_exhausted = True
                        break
                    findings[(index, ident)] = {
                        'package': package['name'], 'version': package['version'], 'paths': list(package['paths']),
                        'advisory_id': ident, 'modified': vuln.get('modified'),
                        'source_url': 'https://osv.dev/vulnerability/' + quote(ident, safe=''),
                    }
                if budget_exhausted:
                    break
                token = result.get('next_page_token')
                if token is None or token == '':
                    if index not in invalid:
                        completed.add(index)
                    continue
                if not isinstance(token, str) or len(token) > 4096 or token in tokens[index]:
                    notices.append(_notice('OSV_PAGINATION_INVALID', 'Un jeton de pagination est invalide ou répété ; collecte incomplète.'))
                    continue
                tokens[index].add(token)
                next_pending.append((index, token))
            pending = next_pending
            if budget_exhausted:
                break
        else:
            if pending:
                notices.append(_notice('OSV_PAGE_LIMIT', 'Limite de pages OSV atteinte ; des avis supplémentaires peuvent manquer.'))
        if budget_exhausted:
            break
    complete = inventory['complete'] and len(completed) == len(packages) and not notices
    return {
        'schema_version': 1, 'kind': 'dependency_advisories', 'engine_version': __version__,
        'generated_at': datetime.now(timezone.utc).isoformat(), 'source': OSV_QUERY_URL,
        'inventory': inventory,
        'coverage': {'complete': complete, 'queried_packages': len(completed), 'attempted_packages': len(attempted)},
        'findings': [findings[key] for key in sorted(findings)], 'notices': notices,
        'limitations': [
            'Correspondances OSV pour les versions verrouillées ; exploitabilité et présence effective au runtime non établies.',
            'Dépendances directes et transitives, de développement et optionnelles incluses si leur résolution déclarée registry.npmjs.org concorde.',
            'Résolutions hors registry.npmjs.org, locales, absentes, aliases et formats autres que package-lock v2/v3 exclus et signalés.',
            'Une URL registry.npmjs.org ne prouve pas la visibilité publique d’un paquet scoped ; vérifier les noms avant --online.',
            'Données OSV consultées à la date du rapport ; absence d’avis ne signifie pas absence de vulnérabilité ou de code malveillant.',
            'Aucune installation, exécution, correction ou modification du dépôt cible ; aucune valeur de secret transmise.',
        ],
    }

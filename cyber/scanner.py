"""Lecture bornée d'un arbre non fiable, sans commande ni import du dépôt cible."""

import hashlib
import os
import stat
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .scan_types import SourceFile, notice

EXCLUDED_DIRS = frozenset({".git", "node_modules", ".venv", "venv", "__pycache__", ".next",
                           "dist", "build", "coverage", ".cache", ".turbo", ".tox"})
TEXT_EXTENSIONS = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".sh", ".bash",
                             ".zsh", ".ps1", ".json", ".jsonc", ".yaml", ".yml", ".toml", ".md", ".mdc",
                             ".mdx", ".txt", ".html", ".htm", ".xml", ".ini", ".cfg", ".conf",
                             ".env", ".lock", ".sql", ".rb", ".go", ".rs", ".php", ".c", ".h",
                             ".cpp", ".java", ".gradle", ".properties", ".tf", ".hcl"})
TEXT_NAMES = frozenset({"Dockerfile", "Containerfile", "Makefile", "Gemfile", "Rakefile",
                        "Justfile", "Procfile", ".npmrc", ".yarnrc", ".yarnrc.yml", ".pypirc",
                        ".gitmodules", ".gitattributes", ".cursorrules", ".bashrc", ".zshrc", "bun.lockb"})
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
LIMITATIONS = [
    "Analyse statique heuristique du contenu local présent ; aucun code cible exécuté, aucun réseau.",
    "Absence de signal ne signifie pas code sûr. Les motifs peuvent produire des faux positifs et faux négatifs.",
    "Aucune base CVE/advisory consultée : les vulnérabilités connues des versions ne sont pas évaluées.",
    "Aucun téléchargement de dépendances, tarball, sous-module, Git LFS, image Docker ou action transitive.",
    "Les fichiers d'extension non textuelle sont hors périmètre, y compris du code qui s'y dissimulerait.",
    "L'acquisition initiale (clone/checkout) n'est pas réalisée ni sécurisée par ce scan après lecture locale.",
    "Historique Git, commits supprimés, réglages de l’hébergeur, signatures et identité des mainteneurs non vérifiés.",
    "Arbre de travail lu, y compris fichiers locaux non suivis ; un secret signalé n'est pas forcément versionné.",
    "Les directives du dépôt, .gitignore et fichiers de suppression ne sont jamais appliqués comme consignes.",
    "Les détections de code sont surtout adaptées à JavaScript/TypeScript, Python et shell ; pas d'analyse sémantique complète.",
]


class ScanError(ValueError):
    pass


def _candidate(name):
    return (Path(name).suffix.lower() in TEXT_EXTENSIONS or name in TEXT_NAMES
            or name.startswith('.env') or '.' not in name)


def collect_files(root, *, max_files=10000, max_file_bytes=2 * 1024 * 1024,
                  max_total_bytes=64 * 1024 * 1024, max_entries=50000, max_depth=40):
    """Traverser via des descripteurs de dossiers et O_NOFOLLOW (POSIX).

    Chaque ouverture de composant refuse les symlinks, même en cas de remplacement
    pendant le parcours. FIFO, devices et sockets ne sont jamais lus. Un arbre qui
    change pendant la lecture n'est pas un snapshot atomique : une notice l'indique.
    """
    if not all(type(v) is int and v > 0 for v in (max_files, max_file_bytes, max_total_bytes, max_entries, max_depth)):
        raise ScanError('Les limites de lecture doivent être des entiers strictement positifs.')
    if not hasattr(os, 'O_NOFOLLOW') or not hasattr(os, 'O_DIRECTORY'):
        raise ScanError('Ce lecteur protégé nécessite un système POSIX (macOS/Linux).')
    root = Path(root).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ScanError('La cible doit être un dossier local.')
    files, notices = {}, []
    counts = {'entries_seen': 0, 'files_analyzed': 0, 'bytes_read': 0,
              'excluded_directories': 0, 'non_text_extensions': 0, 'unread_files': 0}
    stopped = False

    def problem(code, path, message):
        counts['unread_files'] += 1
        notices.append(notice(code, path, message))

    def walk(directory_fd, prefix='', depth=0):
        nonlocal stopped
        if stopped:
            return
        if depth > max_depth:
            problem('DEPTH_LIMIT', prefix, 'Profondeur maximale atteinte ; sous-arbre non inspecté.')
            return
        try:
            # Do not materialize an unbounded directory before applying limits.
            with os.scandir(directory_fd) as iterator:
                names = []
                for entry in iterator:
                    counts['entries_seen'] += 1
                    if counts['entries_seen'] > max_entries:
                        problem('ENTRY_LIMIT', prefix, 'Limite d’entrées atteinte ; scan arrêté.')
                        stopped = True
                        break
                    names.append(entry.name)
        except OSError:
            problem('DIRECTORY_UNREADABLE', prefix, 'Dossier illisible ; son contenu reste inconnu.')
            return
        for name in sorted(names):
            if stopped:
                return
            relative = f'{prefix}/{name}' if prefix else name
            try:
                relative.encode('utf-8')
            except UnicodeEncodeError:
                problem('FILENAME_ENCODING', repr(relative), 'Nom de fichier non UTF-8 ; fichier ignoré.')
                continue
            try:
                before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISLNK(before.st_mode):
                    problem('SYMLINK_SKIPPED', relative, 'Lien symbolique non suivi.')
                    continue
                if stat.S_ISDIR(before.st_mode):
                    if name in EXCLUDED_DIRS:
                        counts['excluded_directories'] += 1
                        continue
                    child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
                    try:
                        walk(child_fd, relative, depth + 1)
                    finally:
                        os.close(child_fd)
                    continue
                if not stat.S_ISREG(before.st_mode):
                    problem('SPECIAL_FILE_SKIPPED', relative, 'Fichier spécial non lu.')
                    continue
                if not _candidate(name):
                    counts['non_text_extensions'] += 1
                    continue
                if len(files) >= max_files:
                    problem('FILE_LIMIT', relative, 'Limite de fichiers analysables atteinte ; scan arrêté.')
                    stopped = True
                    return
                if before.st_size > max_file_bytes:
                    problem('FILE_TOO_LARGE', relative, 'Fichier au-delà de la limite ; contenu non analysé.')
                    continue
                remaining = max_total_bytes - counts['bytes_read']
                if before.st_size > remaining:
                    problem('BYTE_LIMIT', relative, 'Budget total de lecture atteint ; scan arrêté.')
                    stopped = True
                    return
                descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
                with os.fdopen(descriptor, 'rb') as handle:
                    opened = os.fstat(handle.fileno())
                    if not stat.S_ISREG(opened.st_mode):
                        problem('FILE_CHANGED', relative, 'Le type du fichier a changé ; lecture ignorée.')
                        continue
                    if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                        problem('FILE_CHANGED', relative, 'Fichier remplacé pendant le scan ; lecture ignorée.')
                        continue
                    raw = handle.read(min(max_file_bytes, remaining) + 1)
                    after = os.fstat(handle.fileno())
                counts['bytes_read'] += len(raw)
                if len(raw) > max_file_bytes or len(raw) > remaining:
                    problem('FILE_GREW', relative, 'Fichier agrandi au-delà des limites pendant la lecture.')
                    continue
                if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    problem('FILE_CHANGED', relative, 'Fichier modifié pendant le scan ; résultat non retenu.')
                    continue
                if b'\0' in raw:
                    if name == 'bun.lockb':
                        files[relative] = SourceFile(relative, '', hashlib.sha256(raw).hexdigest(), len(raw))
                        problem('BINARY_LOCKFILE', relative, 'Lockfile binaire présent ; contenu non interprété, métadonnées seulement.')
                    else:
                        problem('BINARY_CONTENT', relative, 'Contenu binaire dans un fichier candidat ; non analysé.')
                    continue
                try:
                    content = raw.decode('utf-8-sig')
                except UnicodeDecodeError:
                    problem('ENCODING_UNSUPPORTED', relative, 'Encodage non UTF-8 ; contenu non analysé.')
                    continue
                files[relative] = SourceFile(relative, content, hashlib.sha256(raw).hexdigest(), len(raw))
            except OSError:
                problem('FILE_UNREADABLE', relative, 'Accès impossible ou fichier changé ; aucune lecture fiable.')

    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        walk(root_fd)
    finally:
        os.close(root_fd)
    counts['files_analyzed'] = len(files)
    if not files:
        notices.append(notice('NO_ANALYZABLE_FILES', '', 'Aucun fichier analysable trouvé ; aucune conclusion possible.'))
    return root, files, counts, notices


def scan_repository(root, **limits):
    from .scan_content import analyze as analyze_content
    from .scan_workflows import analyze as analyze_workflows

    root, files, counts, notices = collect_files(root, **limits)
    findings = []
    for analyzer in (analyze_content, analyze_workflows):
        hits, warnings = analyzer(files)
        findings.extend(hits)
        notices.extend(warnings)
    # Same location + rule represents one signal, even when patterns overlap.
    findings = list({(f['rule_id'], f['path'], f['line']): f for f in findings}.values())
    findings.sort(key=lambda f: (SEVERITY_ORDER[f['severity']], f['path'], f['line'], f['rule_id']))
    notices.sort(key=lambda n: (n['path'], n['code']))
    digest = hashlib.sha256()
    manifest = []
    for path, file in sorted(files.items()):
        digest.update(path.encode('utf-8', errors='surrogateescape') + b'\0' + file.sha256.encode() + b'\n')
        manifest.append({'path': path, 'sha256': file.sha256, 'bytes': file.size})
    return {'report_version': 1, 'engine_version': __version__, 'mode': 'static-repository',
            'generated_at': datetime.now(timezone.utc).isoformat(), 'root': str(root),
            'scope': 'local-working-tree', 'tree_fingerprint': digest.hexdigest(),
            'coverage': {**counts, 'complete_within_scope': not any(n['incomplete'] for n in notices),
                         'excluded_directory_names': sorted(EXCLUDED_DIRS),
                         'max_files': limits.get('max_files', 10000),
                         'max_file_bytes': limits.get('max_file_bytes', 2 * 1024 * 1024)},
            'summary': {s: sum(f['severity'] == s for f in findings) for s in SEVERITY_ORDER},
            'findings': findings, 'notices': notices, 'files': manifest, 'limitations': LIMITATIONS}


def scan_exit_code(report, fail_on='high'):
    if fail_on not in (*SEVERITY_ORDER, 'none'):
        raise ScanError('Seuil de gravité inconnu.')
    # An incomplete scan is never a successful CI gate, including --fail-on none.
    if not report['coverage']['complete_within_scope']:
        return 2
    if fail_on != 'none' and any(SEVERITY_ORDER[f['severity']] <= SEVERITY_ORDER[fail_on] for f in report['findings']):
        return 1
    return 0

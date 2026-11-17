"""Heuristiques de contenu et manifestes, sans charger ni exécuter le dépôt.

Les constats signalent une surface d'exécution ou un motif à relire. Ils ne
prouvent ni une exfiltration, ni un logiciel malveillant, ni l'absence de CVE.
Les fichiers source ne sont jamais recopiés dans les preuves.
"""

import json
import re
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from .scan_types import SourceFile, finding, notice

NPM_SCRIPTS = "https://docs.npmjs.com/cli/v11/using-npm/scripts/"
NPM_LOCK = "https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/"
NPM_DEPENDENCIES = "https://docs.npmjs.com/cli/v11/configuring-npm/package-json/#dependencies"
SECRETS = "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html#8-detection"
SUPPLY_CHAIN = "https://github.blog/security/supply-chain-security/disrupting-supply-chain-attacks-on-npm-and-github-actions/"

RULE_CATALOG = {
    "PKG-001": {"title": "Script de cycle d’installation", "severity": "medium", "confidence": "high", "category": "installation", "source_url": NPM_SCRIPTS,
                "recommendation": "Relire le script et ses appels avant installation ; installer initialement sans scripts dans un environnement isolé. Un hook peut être légitime."},
    "PKG-002": {"title": "Dépendance distante à vérifier", "severity": "medium", "confidence": "high", "category": "dependencies", "source_url": NPM_DEPENDENCIES,
                "recommendation": "Vérifier propriétaire, référence exacte et intégrité dans le lockfile. Pour Git, verrouiller un commit complet revu ; ne pas déduire la sûreté du seul hash."},
    "PKG-003": {"title": "Aucun lockfile Node visible", "severity": "medium", "confidence": "medium", "category": "dependencies", "source_url": NPM_LOCK,
                "recommendation": "Versionner un lockfile cohérent avec le gestionnaire utilisé et le contrôler en CI. Vérifier d’abord le périmètre du workspace et les fichiers exclus du scan."},
    "PKG-004": {"title": "Scripts d’installation dans les dépendances verrouillées", "severity": "medium", "confidence": "high", "category": "installation", "source_url": NPM_LOCK,
                "recommendation": "Identifier ces dépendances dans le lockfile et examiner leurs scripts avant de les autoriser ; les compilations natives peuvent nécessiter un script légitime."},
    "PKG-005": {"title": "Origine d’artefact hors registres publics attendus", "severity": "low", "confidence": "high", "category": "dependencies", "source_url": NPM_LOCK,
                "recommendation": "Vérifier que chaque origine directe ou registre privé est voulu et que son intégrité est verrouillée. Une origine différente n’est pas une preuve de compromission."},
    "CODE-001": {"title": "Téléchargement directement transmis à un interpréteur", "severity": "high", "confidence": "medium", "category": "execution", "source_url": SUPPLY_CHAIN,
                 "recommendation": "Examiner l’étape avant exécution ; télécharger séparément, vérifier la provenance et l’intégrité, puis exécuter seulement dans un environnement contrôlé."},
    "CODE-002": {"title": "Décodage associé à une exécution dynamique", "severity": "high", "confidence": "medium", "category": "obfuscation", "source_url": SUPPLY_CHAIN,
                 "recommendation": "Relire la donnée décodée et sa provenance sans l’exécuter. Justifier les générateurs légitimes et refuser une charge dont le comportement reste opaque."},
    "CODE-003": {"title": "Lecture d’identifiants locaux proche d’un appel réseau", "severity": "high", "confidence": "medium", "category": "credentials", "source_url": SECRETS,
                 "recommendation": "Vérifier manuellement le flux des données et la destination. Ce rapprochement textuel ne prouve pas un envoi ; isoler l’exécution des identifiants personnels."},
    "SECRET-001": {"title": "Bloc de clé privée potentiel", "severity": "high", "confidence": "high", "category": "secrets", "source_url": SECRETS,
                   "recommendation": "Vérifier localement s’il s’agit d’une clé réelle ou d’un exemple de test. Si elle a été exposée, la révoquer et examiner l’historique ; supprimer le fichier seul ne suffit pas."},
    "SECRET-002": {"title": "Format de jeton sensible potentiel", "severity": "high", "confidence": "medium", "category": "secrets", "source_url": SECRETS,
                   "recommendation": "Valider l’usage sans envoyer le jeton à un service de test. Révoquer et remplacer toute valeur réelle exposée, puis examiner son historique et sa portée."},
}

HOOKS = ("preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare")
DEPENDENCY_FIELDS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb")
CODE_SUFFIXES = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".py", ".sh", ".bash", ".zsh", ".ps1"}
NON_EXECUTION_DIRS = {"test", "tests", "__tests__", "fixture", "fixtures", "example", "examples", "docs", "documentation", "vendor"}
MAX_FINDINGS_PER_FILE = 100
MAX_FINDINGS = 5000
MAX_MATCHES_PER_PATTERN = 1000
MAX_MANIFEST_DEPENDENCIES = 1000


class _FindingBuffer(list):
    """Bounded accumulation also protects callers using analyze directly."""

    def __init__(self, limit=MAX_FINDINGS_PER_FILE):
        super().__init__()
        self.limit = limit
        self.truncated = False
        self.scan_limited = False
        self._seen = set()

    def append(self, item):
        key = (item['rule_id'], item['path'], item['line'])
        if key in self._seen:
            return
        if len(self) >= self.limit:
            self.truncated = True
            return
        self._seen.add(key)
        super().append(item)

    def extend(self, items):
        for item in items:
            self.append(item)


class _NoticeBuffer(list):
    def __init__(self):
        super().__init__()
        self._seen = set()
        self.truncated = False

    def append(self, item):
        key = (item['code'], item['path'], item['message'])
        if key in self._seen:
            return
        if len(self) >= 2000:
            self.truncated = True
            return
        self._seen.add(key)
        super().append(item)


def _emit(rule_id, file, line, evidence, **changes):
    metadata = {**RULE_CATALOG[rule_id], **changes}
    return finding(rule_id, file, line, evidence=evidence, **metadata)


def _line(text, offset):
    return text.count("\n", 0, offset) + 1


def _located_matches(pattern, text, result):
    """Count each text segment once, including many matches on one source line."""
    line, offset = 1, 0
    for index, match in enumerate(pattern.finditer(text)):
        if index >= MAX_MATCHES_PER_PATTERN:
            result.scan_limited = True
            break
        line += text.count("\n", offset, match.start())
        offset = match.start()
        yield match, line


def _key_line(text, key, start=0):
    # JSON decoding decides semantics; this lookup is only a best-effort location.
    match = re.search(re.escape(json.dumps(key, ensure_ascii=False)) + r"\s*:", text[start:])
    if match is None:
        match = re.search(re.escape(json.dumps(key, ensure_ascii=True)) + r"\s*:", text[start:])
    return _line(text, start + match.start()) if match else 1


def _json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _json(file, notices):
    try:
        value = json.loads(file.text, object_pairs_hook=_json_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")))
        if not isinstance(value, dict):
            raise ValueError("root object required")
        return value
    except (ValueError, RecursionError):
        notices.append(notice("PKG-INVALID-JSON", file.path,
                              "Manifeste ou lockfile JSON invalide, dupliqué ou trop imbriqué ; analyse structurelle non réalisée."))
        return None


def _has_lock(path, files):
    current = PurePosixPath(path).parent
    while True:
        if any((current / name).as_posix() in files for name in LOCKFILES):
            return True
        if current == PurePosixPath("."):
            return False
        current = current.parent


def _remote_kind(spec):
    spec = spec.strip()
    if spec.startswith(("http://", "https://")):
        # A lockfile may make this URL integrity-pinned; this rule calls for review.
        return "url"
    is_git = spec.startswith(("git+", "git://", "git@", "github:", "gitlab:", "bitbucket:"))
    is_short_git = re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:#.*)?$", spec) is not None
    if is_git or is_short_git:
        fragment = spec.rsplit("#", 1)[-1] if "#" in spec else ""
        return None if re.fullmatch(r"(?:[a-fA-F0-9]{40}|[a-fA-F0-9]{64})", fragment) else "git"
    return None


def _manifest(file, files, notices):
    result = _FindingBuffer()
    model = _json(file, notices)
    if model is None:
        return result
    scripts = model.get("scripts", {})
    if not isinstance(scripts, dict):
        notices.append(notice("PKG-INVALID-SCRIPTS", file.path, "Le champ scripts n’est pas un objet ; couverture des hooks incomplète."))
    else:
        for hook in HOOKS:
            script = scripts.get(hook)
            if script is not None and not isinstance(script, str):
                notices.append(notice("PKG-INVALID-SCRIPT", file.path, "Un script de cycle n’est pas une chaîne ; couverture incomplète."))
            elif script and script.strip():
                result.append(_emit("PKG-001", file, _key_line(file.text, hook),
                                    f"Le manifeste définit le hook {hook}, susceptible d’être exécuté selon la version du gestionnaire et ses options. Son contenu n’est pas exécuté ni affiché ; sa présence ne prouve pas une intention malveillante."))
                # JSON script strings can carry escaped newlines, so analyze the
                # decoded command too. Every match points to the containing key.
                for rule_id in _command_signals(script):
                    result.append(_emit(rule_id, file, _key_line(file.text, hook),
                                        "Motif d’exécution repéré dans un script de cycle JSON ; commande expurgée."))
        for script_name, command in scripts.items():
            if result.truncated:
                break
            if script_name in HOOKS or not isinstance(command, str):
                continue
            for rule_id in _command_signals(command):
                result.append(_emit(rule_id, file, _key_line(file.text, script_name),
                                    "Motif d’exécution repéré dans une commande npm du manifeste ; commande expurgée. Son lancement automatique n’est pas établi."))
    needs_lock = False
    inspected_dependencies = 0
    for field in DEPENDENCY_FIELDS:
        if result.truncated or result.scan_limited:
            break
        dependencies = model.get(field, {})
        if not isinstance(dependencies, dict):
            notices.append(notice("PKG-INVALID-DEPENDENCIES", file.path, "Un champ de dépendances n’est pas un objet ; couverture incomplète."))
            continue
        needs_lock = needs_lock or bool(dependencies)
        for name, spec in dependencies.items():
            if result.truncated:
                break
            if inspected_dependencies >= MAX_MANIFEST_DEPENDENCIES:
                result.scan_limited = True
                break
            inspected_dependencies += 1
            if not isinstance(spec, str):
                notices.append(notice("PKG-INVALID-DEPENDENCY", file.path, "Une référence de dépendance n’est pas une chaîne ; couverture incomplète."))
                continue
            kind = _remote_kind(spec)
            if kind:
                message = ("Une dépendance utilise une URL directe ; son verrouillage par intégrité dans un lockfile n’est pas établi par ce motif."
                           if kind == "url" else "Une dépendance Git utilise une référence sans commit complet dans le manifeste ; référence et valeur expurgées.")
                result.append(_emit("PKG-002", file, _key_line(file.text, name), message))
    if needs_lock and not _has_lock(file.path, files):
        result.append(_emit("PKG-003", file, 1,
                            "Des dépendances sont déclarées, mais aucun lockfile Node reconnu n’a été fourni dans ce dossier ou ses parents du périmètre analysé."))
    return result


def _npm_lock(file, notices):
    result = _FindingBuffer()
    model = _json(file, notices)
    if model is None:
        return result
    if type(model.get("lockfileVersion")) is not int or model["lockfileVersion"] not in (2, 3):
        notices.append(notice("PKG-UNSUPPORTED-LOCK", file.path,
                              "Seuls les lockfiles npm v2/v3 sont analysés structurellement ; couverture transitive incomplète."))
        return result
    packages = model.get("packages")
    if not isinstance(packages, dict):
        notices.append(notice("PKG-INVALID-LOCK", file.path, "Le lockfile npm ne contient pas de table packages exploitable."))
        return result
    scripts_count = 0
    unusual_origins = 0
    first_origin_line = 1
    first_hook_line = 1
    for path, package in packages.items():
        if not isinstance(package, dict):
            notices.append(notice("PKG-INVALID-LOCK-ENTRY", file.path, "Une entrée de package n’est pas un objet ; couverture incomplète."))
            continue
        if not path or package.get("link") is True:
            continue
        if package.get("hasInstallScript") is True:
            if scripts_count == 0:
                first_hook_line = _key_line(file.text, path)
            scripts_count += 1
        if "hasInstallScript" in package and type(package["hasInstallScript"]) is not bool:
            notices.append(notice("PKG-INVALID-LOCK-SCRIPT", file.path, "Un marqueur hasInstallScript a un type inattendu ; couverture incomplète."))
        resolved = package.get("resolved")
        if resolved is not None and not isinstance(resolved, str):
            notices.append(notice("PKG-INVALID-RESOLVED", file.path, "Une origine resolved n’est pas une chaîne ; couverture incomplète."))
        elif resolved:
            try:
                url = urlsplit(resolved)
                unusual = (url.scheme in ("http", "https") and
                           (url.hostname not in ("registry.npmjs.org", "registry.yarnpkg.com") or
                            url.scheme != "https" or url.username is not None or url.password is not None))
                unusual = unusual or resolved.startswith(("git+", "git://", "git@"))
            except ValueError:
                notices.append(notice("PKG-INVALID-RESOLVED", file.path, "Une origine resolved ne peut pas être interprétée ; couverture incomplète."))
                continue
            if unusual:
                if unusual_origins == 0:
                    first_origin_line = _key_line(file.text, path)
                unusual_origins += 1
    if scripts_count:
        result.append(_emit("PKG-004", file, first_hook_line,
                            f"{scripts_count} entrée(s) de dépendances déclarent hasInstallScript=true. Les scripts de ces paquets n’ont pas été téléchargés ou inspectés."))
    if unusual_origins:
        result.append(_emit("PKG-005", file, first_origin_line,
                            f"{unusual_origins} entrée(s) utilisent une origine directe, Git, HTTP ou hors des registres npm/yarn attendus. URLs et éventuels identifiants expurgés."))
    return result


DOWNLOAD_EXEC = re.compile(
    r"\b(?:curl|wget)\b[^\r\n|;]{0,1500}(?:\\\s*\n\s*)?\|\s*(?:(?:sudo|env)\s+)?(?:bash|sh|zsh|python3?|node)\b", re.I)
DECODE_EXEC = re.compile(
    r"\b(?:eval|exec|Function)\s*\(\s*\(*\s*(?:base64\.b64decode|atob)\s*\("
    r"|\b(?:eval|exec|Function)\s*\(\s*\(*\s*Buffer\.from\s*\([^;\n]{0,1000}?,\s*['\"]base64['\"]"
    r"|\bbase64\s+(?:--decode|-d|-D)\b[^\n|]{0,100}\|\s*(?:bash|sh|zsh|python3?|node)\b", re.I)
CREDENTIAL_PATH = re.compile(r"(?:\.aws[/\\]credentials|\.ssh[/\\]id_(?:rsa|ed25519|ecdsa)|\.config[/\\]gcloud[/\\]application_default_credentials\.json|\.kube[/\\]config|~/\.npmrc)")
READ_CALL = re.compile(r"\b(?:readFileSync|readFile|open|read_text|read_bytes)\s*\(|\bcat\s+")
NETWORK_CALL = re.compile(r"\b(?:fetch\s*\(|(?:requests|axios)\.(?:post|put)\s*\(|https?\.request\s*\(|curl\s+[^\n]{0,300}(?:--data|-d\b|-F\b))")


def _command_signals(text):
    found = []
    if DOWNLOAD_EXEC.search(text):
        found.append("CODE-001")
    if DECODE_EXEC.search(text):
        found.append("CODE-002")
    return found


def _live_code(path):
    item = PurePosixPath(path)
    if any(part.lower() in NON_EXECUTION_DIRS for part in item.parts[:-1]):
        return False
    name = item.name.lower()
    if re.search(r"(?:^test[_.-]|[_.-](?:test|spec)\.)", name):
        return False
    # GitHub's YAML contains executable run blocks. Restrict this expansion to
    # workflow locations and action manifests rather than unrelated YAML data.
    if item.suffix.lower() in {".yml", ".yaml"}:
        return ((len(item.parts) == 3 and item.parts[:2] == (".github", "workflows"))
                or name in {"action.yml", "action.yaml"})
    return item.suffix.lower() in CODE_SUFFIXES or name in {"dockerfile", "makefile"}


def _code(file):
    if not _live_code(file.path):
        return []
    # Mask full-line comments while preserving offsets and line numbers.
    lines = file.text.splitlines(keepends=True)
    masked = [re.sub(r"[^\r\n]", " ", line) if line.lstrip().startswith(("#", "//", "/*", "*")) else line for line in lines]
    text = "".join(masked)
    result = _FindingBuffer()
    for rule_id, pattern, description in (
        ("CODE-001", DOWNLOAD_EXEC, "Pipeline téléchargement → interpréteur repéré textuellement ; destination et commande expurgées. Aucune exécution ni analyse de la réponse distante."),
        ("CODE-002", DECODE_EXEC, "Appel de décodage directement associé à une exécution dynamique repéré textuellement ; charge expurgée et non exécutée."),
    ):
        for match, line_number in _located_matches(pattern, text, result):
            result.append(_emit(rule_id, file, line_number, description))
            if result.truncated:
                return result
    code_lines = text.splitlines()
    for index, line in enumerate(code_lines):
        if CREDENTIAL_PATH.search(line) and READ_CALL.search("\n".join(code_lines[max(0, index-1):index+2])):
            window = "\n".join(code_lines[index:index+13])[:2500]
            if NETWORK_CALL.search(window):
                result.append(_emit("CODE-003", file, index+1,
                                    "Lecture d’un chemin d’identifiants et appel réseau présents dans une fenêtre de 13 lignes. Le lien entre les données lues et l’appel réseau n’est pas démontré."))
                if result.truncated:
                    return result
    return result


PRIVATE_KEY = re.compile(
    r"-----BEGIN (?P<kind>(?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY)-----\s+"
    r"[A-Za-z0-9+/=\r\n]{32,16384}?\s+-----END (?P=kind)-----")
TOKENS = re.compile(
    r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255}|npm_[A-Za-z0-9]{36,255}|"
    r"sk_live_[A-Za-z0-9]{24,255}|xox[baprs]-[A-Za-z0-9-]{20,255}|AKIA[A-Z0-9]{16})(?![A-Za-z0-9_])")


def _placeholder(token):
    lower = token.lower()
    if any(marker in lower for marker in ("placeholder", "changeme", "example", "dummy", "your_token", "yourtoken")):
        return True
    body = token.split("_", 1)[-1]
    # Common redacted/test values, not a general entropy test or validity check.
    return len(set(body)) < 7 or bool(re.fullmatch(r"(?:0123456789|1234567890|abcdefghijklmnopqrstuvwxyz|ABCDEFGHIJKLMNOPQRSTUVWXYZ)+", body))


def _secrets(file):
    result = _FindingBuffer()
    for match, line_number in _located_matches(PRIVATE_KEY, file.text, result):
        result.append(_emit("SECRET-001", file, line_number,
                            "Bloc au format d’une clé privée détecté. Valeur intégralement masquée ; validité, usage et éventuel caractère de test non vérifiés."))
        if result.truncated:
            return result
    for match, line_number in _located_matches(TOKENS, file.text, result):
        if not _placeholder(match.group()):
            result.append(_emit("SECRET-002", file, line_number,
                                "Chaîne correspondant à un format de jeton ou d’identifiant d’accès connu. Valeur intégralement masquée ; activation non vérifiée."))
            if result.truncated:
                return result
    return result


def analyze(files: dict[str, SourceFile]):
    """Retourner (constats, limites), dans un ordre déterministe.

    Le dictionnaire doit inclure les lockfiles présents, même lorsqu'ils ne sont
    pas npm. Aucun chemin absent de ce dictionnaire n'est ouvert ici. Les preuves
    ne contiennent ni commande, ni URL de dépendance, ni valeur de secret.
    """
    results, notices = _FindingBuffer(MAX_FINDINGS), _NoticeBuffer()
    for path in sorted(files):
        if results.truncated:
            break
        file = files[path]
        name = PurePosixPath(path).name
        findings = []
        if name == "package.json":
            findings.append(_manifest(file, files, notices))
        elif name in ("package-lock.json", "npm-shrinkwrap.json"):
            findings.append(_npm_lock(file, notices))
        elif name in ("pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"):
            notices.append(notice("PKG-UNSUPPORTED-LOCK", path,
                                  "Lockfile présent mais format non analysé structurellement ; scripts et origines des dépendances transitives non couverts."))
        findings.extend((_code(file), _secrets(file)))
        combined = _FindingBuffer()
        for group in findings:
            combined.extend(group)
        if combined.truncated or any(getattr(group, 'truncated', False) for group in findings):
            notices.append(notice("CONTENT-FINDING-LIMIT", path,
                                  "Limite de 100 constats par fichier atteinte ; d’autres motifs peuvent ne pas être rapportés."))
        if any(getattr(group, 'scan_limited', False) for group in findings):
            notices.append(notice("CONTENT-MATCH-LIMIT", path,
                                  "Limite de 1000 occurrences par motif ou dépendances de manifeste atteinte ; analyse de contenu partielle."))
        results.extend(combined)
    # Append completeness markers after bounded accumulation, so they cannot be
    # swallowed by a malicious number of malformed manifest entries.
    final_notices = list(notices)
    if results.truncated:
        final_notices.append(notice("CONTENT-TOTAL-LIMIT", "",
                                    "Limite globale de 5000 constats atteinte ; analyse de contenu partielle."))
    if notices.truncated:
        final_notices.append(notice("CONTENT-NOTICE-LIMIT", "",
                                    "Limite des messages de couverture atteinte ; d’autres limites ne sont pas détaillées."))
    return (sorted(results, key=lambda item: (item['rule_id'], item['path'], item['line'])),
            sorted(final_notices, key=lambda item: (item['code'], item['path'], item['message'])))

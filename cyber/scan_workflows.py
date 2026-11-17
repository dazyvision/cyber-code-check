"""Signaux statiques des workflows et configurations d'agents.

L'analyse YAML est volontairement lexicale : elle couvre les blocs usuels et
signale les constructions non résolues. Elle ne prouve ni exploitabilité ni
innocuité, et ne charge jamais de configuration comme du code exécutable.
"""

import io
import json
import re
from pathlib import PurePosixPath

from .scan_types import finding, notice

GITHUB = "https://docs.github.com/en/actions/reference/security/secure-use"
LOCKFILES = "https://docs.github.com/en/actions/concepts/security/workflow-dependency-lockfiles"
MCP = "https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/SECURITY.md"
INJECTION = "https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html"
TRUST = "https://code.visualstudio.com/docs/editing/workspaces/workspace-trust"
CLAUDE_HOOKS = "https://code.claude.com/docs/en/hooks"
CLAUDE_SETTINGS = "https://code.claude.com/docs/en/settings"
DEVCONTAINER = "https://github.com/devcontainers/spec/blob/main/docs/specs/devcontainerjson-reference.md"
MAX_PER_FILE = 100
MAX_TOTAL = 5000
MAX_LINES = 20000
MAX_CONFIG_ITEMS = 2000

RULE_CATALOG = {
    "WF-001": "Référence d'action ou workflow réutilisable mutable",
    "WF-002": "Permissions globales en écriture",
    "WF-003": "Déclencheur privilégié et checkout d'une référence non fiable",
    "WF-004": "Pull request sur runner auto-hébergé",
    "WF-005": "Interpolation d'une entrée non fiable dans un script",
    "WF-006": "Couverture du lockfile Actions à vérifier",
    "DEV-001": "Serveur MCP lancé depuis une dépendance non épinglée",
    "DEV-002": "Hooks d'agent exécutables dans le dépôt",
    "DEV-003": "Tâche exécutée à l'ouverture du dossier",
    "DEV-004": "Commandes de cycle de vie du devcontainer",
    "DEV-005": "Demande de mode sans permissions à contextualiser",
    "AI-001": "Instruction potentielle d'injection dans un document",
}


def _unquote(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _without_comment(line):
    quote = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
        elif char == "\\" and quote == '"':
            escaped = True
        elif quote:
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == "#" and (index == 0 or line[index-1].isspace()):
            return line[:index]
    return line


def _entries(text):
    """Retenir les clés simples et leurs parents ; préserver les blocs run."""
    entries, unsupported = [], []
    stack = []
    block = None
    step = 0
    for number, raw in enumerate(io.StringIO(text), 1):
        if number > MAX_LINES:
            unsupported.append(0)
            break
        raw = raw.rstrip("\r\n")
        if block is not None:
            indent = len(raw) - len(raw.lstrip())
            if not raw.strip() or indent > block["indent"]:
                if block["key"] == "run":
                    block["body"].append((number, raw))
                continue
            block = None
        line = _without_comment(raw)
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if "\t" in line[:len(line)-len(line.lstrip())]:
            unsupported.append(number)
        # Aliases, tags and flow mappings require a real YAML interpretation.
        if re.search(r"(?:^|:\s+|\s)(?:[&*][\w-]+|![\w!])", line) or re.search(r":\s*\{", line):
            unsupported.append(number)
        match = re.match(r"^(\s*)(-\s+)?(?:([\w-]+)|[\"']([\w-]+)[\"'])\s*:\s*(.*)$", line)
        if not match:
            scalar = re.match(r"^(\s*)-\s+([\w-]+)\s*$", line)
            if scalar and stack and stack[-1][1] in ("on", "runs-on"):
                entries.append({"line": number, "indent": len(scalar.group(1)),
                                "key": stack[-1][1], "value": scalar.group(2),
                                "parents": tuple(k for _, k in stack[:-1]),
                                "step": step, "body": []})
            if line.lstrip().startswith(("? ", "<<:")):
                unsupported.append(number)
            if line.lstrip().startswith(("{", "[")):
                unsupported.append(number)
            elif not scalar and line.strip() not in ("---", "..."):
                unsupported.append(number)
            continue
        if match.group(2):
            step += 1
        indent = len(match.group(1)) + len(match.group(2) or "")
        key, value = match.group(3) or match.group(4), match.group(5).strip()
        if value[:1] in ("'", '"') and (len(value) < 2 or value[-1:] != value[:1]):
            unsupported.append(number)
        while stack and stack[-1][0] >= indent:
            stack.pop()
        entry = {"line": number, "indent": indent, "key": key,
                 "value": _unquote(value), "parents": tuple(k for _, k in stack),
                 "step": step, "body": []}
        entries.append(entry)
        if re.fullmatch(r"[|>][+-]?[1-9]?", value):
            block = entry
            if key != "run":
                unsupported.append(number)
        elif value == "":
            stack.append((indent, key))
        elif key == "run":
            entry["body"].append((number, value))
    return entries, unsupported


def _workflow(file, files):
    findings, notices = [], []
    entries, unsupported = _entries(file.text)
    def emit(id, entry, severity, confidence, evidence, action, source=GITHUB):
        if len(findings) >= MAX_PER_FILE:
            if not any(n["code"] == "workflow-findings-limit" for n in notices):
                notices.append(notice("workflow-findings-limit", file.path,
                                      "Limite de 100 signaux pour ce fichier atteinte ; des résultats supplémentaires sont omis."))
            return
        findings.append(finding(id, file, entry["line"], RULE_CATALOG[id], severity,
                                confidence, evidence, action, source, "workflow"))
    if any(unsupported):
        notices.append(notice("yaml-lexical-limit", file.path,
                              "YAML complexe ou valeur multiligne hors run : ancres, tags, mappings compacts ou scalaires non résolus. Revue complète nécessaire."))
    if 0 in unsupported:
        notices.append(notice("yaml-line-budget", file.path,
                              "Limite de 20 000 lignes atteinte ; le reste du workflow n'est pas analysé."))
    if not entries and file.text.strip():
        notices.append(notice("yaml-unparsed", file.path,
                              "Aucune structure YAML usuelle reconnue dans ce fichier ; analyse du workflow incomplète."))
    triggers = set()
    for entry in entries:
        if entry["key"] == "on" and not entry["parents"]:
            triggers.update(re.findall(r"\b(?:pull_request_target|pull_request|workflow_run)\b", entry["value"]))
        elif entry["parents"] == ("on",):
            triggers.add(entry["key"])
    lock_present = ".github/workflows/actions.lock" in files
    uncertain_lock = False
    def job_property(entry):
        return len(entry["parents"]) == 2 and entry["parents"][0] == "jobs"
    def step_property(entry):
        return bool(entry["parents"]) and entry["parents"][-1] == "steps"
    uses = [e for e in entries if e["key"] == "uses" and (step_property(e) or job_property(e))]
    for entry in uses:
        value = entry["value"]
        if value.startswith("./"):
            continue
        immutable = (re.fullmatch(r"[^\s@]+@[a-fA-F0-9]{40}", value)
                     or re.fullmatch(r"docker://[^\s@]+@sha256:[a-fA-F0-9]{64}", value))
        if immutable:
            continue
        if "${{" in value or not value or value[0:1] in "|>*&":
            if not any(n["code"] == "dynamic-action-reference" for n in notices):
                notices.append(notice("dynamic-action-reference", file.path,
                                      "Une référence uses ne peut pas être résolue par l'analyse lexicale."))
        reusable = "/.github/workflows/" in value or "steps" not in entry["parents"]
        if lock_present and not reusable and not value.startswith("docker://"):
            uncertain_lock = True
            emit("WF-006", entry, "info", "high",
                 "Référence non épinglée dans le workflow et actions.lock présent ; sa couverture exacte n'est pas interprétée.",
                 "Vérifier que ce workflow et cette action sont enregistrés dans actions.lock, avec commit et identité du dépôt. Le lockfile n'est pas validé par ce détecteur.", LOCKFILES)
        else:
            emit("WF-001", entry, "medium", "high",
                 "La référence uses examinée n'est pas un SHA complet ni un digest Docker immuable.",
                 "Verrouiller les actions avec un lockfile vérifié ou un SHA complet ; épingler séparément les workflows réutilisables. Examiner aussi le code retenu.")
    if uncertain_lock:
        notices.append(notice("actions-lock-unverified", file.path,
                              "Un lockfile Actions existe mais sa couverture par workflow et action n'a pas été validée ; aucune conclusion de verrouillage."))
    for entry in entries:
        if entry["key"] == "permissions" and entry["value"] == "write-all" and (not entry["parents"] or job_property(entry)):
            emit("WF-002", entry, "high", "high", "Une déclaration permissions donne tous les droits en écriture.",
                 "Définir les permissions minimales au niveau du workflow, puis augmenter seulement celles des jobs qui en ont besoin.")
        if entry["key"] == "runs-on" and job_property(entry) and "self-hosted" in entry["value"] and triggers.intersection({"pull_request", "pull_request_target"}):
            emit("WF-004", entry, "high", "medium",
                 "Un déclencheur pull request et un runner self-hosted coexistent ; les conditions d'accès ne sont pas évaluées.",
                 "Vérifier qui peut soumettre du code au runner, isoler les jobs et utiliser des environnements éphémères sans secrets pour le code non fiable.")
        if entry["key"] == "run" and step_property(entry):
            for number, command in entry["body"]:
                if re.search(r"\$\{\{\s*(?:github\.(?:head_ref|event\.(?:(?:pull_request|issue|discussion|comment)\.(?:title|body)|pull_request\.head\.ref|workflow_run\.head_branch)))\b", command):
                    location = {**entry, "line": number}
                    emit("WF-005", location, "high", "medium",
                         "Une expression GitHub alimentée par une contribution apparaît directement dans un bloc run ; son contexte shell doit être revu.",
                         "Passer les données non fiables via une variable d'environnement correctement citée, ou via une action qui les traite comme données, puis tester leur usage.")
    if triggers.intersection({"pull_request_target", "workflow_run"}):
        checkout_steps = {e["step"] for e in uses if e["value"].lower().startswith("actions/checkout@")}
        for entry in entries:
            if entry["key"] == "ref" and entry["step"] in checkout_steps and "with" in entry["parents"]:
                if re.search(r"github\.event\.(?:pull_request\.head\.(?:sha|ref)|workflow_run\.(?:head_sha|head_branch))", entry["value"]):
                    emit("WF-003", entry, "high", "medium",
                         "Déclencheur privilégié et checkout d'une tête de contribution coexistent ; les conditions et transferts de privilèges ne sont pas analysés.",
                         "Séparer l'exécution du code non fiable des jobs privilégiés, et vérifier les permissions, secrets, caches et artefacts accessibles.")
    return findings, notices


def _json(file):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate key")
            value[key] = item
        return value
    try:
        obj = json.loads(file.text, object_pairs_hook=unique,
                         parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")))
        if not isinstance(obj, dict):
            raise ValueError("object required")
        return obj, []
    except (ValueError, RecursionError):
        return None, [notice("invalid-agent-config", file.path,
                             "Configuration non analysée : objet JSON strict attendu ; JSONC, clés dupliquées ou structure invalide non pris en charge.")]


def _line(text, key):
    match = re.search(r'"' + re.escape(key) + r'"\s*:', text)
    return text.count("\n", 0, match.start()) + 1 if match else 1


def _exact_package(argument, command):
    if not isinstance(argument, str):
        return False
    if command == "uvx":
        return bool(re.fullmatch(r"[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[0-9]+(?:\.[0-9A-Za-z]+)+(?:[+.-][\w.-]+)?", argument))
    return bool(re.fullmatch(r"(?:@[\w.-]+/)?[\w.-]+@[0-9]+\.[0-9]+\.[0-9]+(?:-[\w.-]+)?(?:\+[\w.-]+)?", argument))


def _command_package(command, args):
    if not isinstance(command, str) or not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        return None, False
    command = PurePosixPath(command.replace("\\", "/")).name.removesuffix(".cmd").removesuffix(".exe")
    if command not in ("npx", "uvx"):
        return None, True
    if command == "uvx" and "--from" in args:
        index = args.index("--from")
        return command, index + 1 < len(args) and _exact_package(args[index+1], command)
    package_args = []
    for index, arg in enumerate(args):
        if arg in ("--package", "-p") and command == "npx":
            if index + 1 >= len(args):
                return command, False
            package_args.append(args[index+1])
        elif arg.startswith("--package=") and command == "npx":
            package_args.append(arg.partition("=")[2])
    if package_args:
        return command, all(_exact_package(arg, command) for arg in package_args)
    candidate = next((arg for arg in args if not arg.startswith("-")), "")
    return command, _exact_package(candidate, command)


def _agent_config(file):
    findings, notices = [], []
    obj, errors = _json(file)
    notices += errors
    if obj is None:
        return findings, notices
    def emit(id, key, evidence, action, source=TRUST, severity="medium"):
        if len(findings) >= MAX_PER_FILE:
            if not any(n["code"] == "agent-findings-limit" for n in notices):
                notices.append(notice("agent-findings-limit", file.path,
                                      "Limite de signaux atteinte pour cette configuration ; résultats supplémentaires omis."))
            return
        findings.append(finding(id, file, _line(file.text, key), RULE_CATALOG[id], severity,
                                "high", evidence, action, source, "agent-config"))
    path = file.path.lower()
    if path.endswith("mcp.json") or path.endswith(".mcp.json"):
        servers = obj.get("mcpServers", obj.get("servers", {}))
        if not isinstance(servers, dict):
            notices.append(notice("mcp-shape", file.path, "Le dictionnaire de serveurs MCP n'a pas la structure attendue."))
        else:
            for index, config in enumerate(servers.values()):
                if index >= MAX_CONFIG_ITEMS:
                    notices.append(notice("mcp-config-budget", file.path,
                                          "Limite de 2 000 entrées MCP atteinte ; entrées suivantes non analysées."))
                    break
                if not isinstance(config, dict):
                    if not any(n["code"] == "mcp-server-shape" for n in notices):
                        notices.append(notice("mcp-server-shape", file.path, "Une entrée de serveur MCP n'est pas un objet."))
                    continue
                command, pinned = _command_package(config.get("command"), config.get("args", []))
                if command and not pinned:
                    emit("DEV-001", "command", "Un serveur MCP utilise npx ou uvx sans version exacte reconnue pour sa dépendance.",
                         "Examiner le paquet et son origine, retenir une version exacte contrôlée et lancer le serveur avec des droits limités. L'épinglage ne garantit pas que le paquet est sain.", MCP)
    if ".claude/" in path or PurePosixPath(path).name == "settings.json":
        if obj.get("hooks"):
            emit("DEV-002", "hooks", "Une configuration d'agent déclare des hooks ; leur activation dépend notamment de la confiance accordée au workspace, du mode de session et de la version du client.",
                 "Relire les hooks avant de faire confiance au dépôt. La documentation actuelle distingue le mode interactif des sessions -p/SDK, où le dossier est traité comme approuvé ; désactiver les hooks pour inspecter un dépôt inconnu.", CLAUDE_HOOKS)
        permissions = obj.get("permissions")
        if isinstance(permissions, dict) and permissions.get("defaultMode") == "bypassPermissions":
            emit("DEV-005", "defaultMode", "Le fichier demande bypassPermissions. La documentation actuelle indique que ce mode est ignoré dans les réglages de projet/local ; son activation n'est pas démontrée.",
                 "Vérifier la version du client, la portée et les réglages effectivement chargés. Conserver l'isolation du système et des secrets.", CLAUDE_SETTINGS, severity="info")
    if path.endswith(".vscode/tasks.json"):
        tasks = obj.get("tasks", [])
        if not isinstance(tasks, list):
            notices.append(notice("vscode-task-shape", file.path, "Liste tasks non analysable."))
        else:
            if len(tasks) > MAX_CONFIG_ITEMS:
                notices.append(notice("vscode-config-budget", file.path,
                                      "Limite de 2 000 tâches atteinte ; tâches suivantes non analysées."))
            if any(isinstance(t, dict) and isinstance(t.get("runOptions"), dict) and t["runOptions"].get("runOn") == "folderOpen" for t in tasks[:MAX_CONFIG_ITEMS]):
                emit("DEV-003", "runOn", "Une tâche VS Code peut être lancée automatiquement à l'ouverture du dossier après accord de confiance de l'éditeur.",
                     "Relire sa commande avant d'autoriser l'exécution automatique ou d'accorder la confiance au workspace.")
    if PurePosixPath(path).name in ("devcontainer.json", ".devcontainer.json"):
        keys = ("initializeCommand", "onCreateCommand", "updateContentCommand", "postCreateCommand", "postStartCommand", "postAttachCommand")
        for key in keys:
            if obj.get(key):
                emit("DEV-004", key, "Le devcontainer déclare une commande de cycle de vie ; initializeCommand peut notamment s'exécuter sur l'hôte.",
                     "Relire la commande, l'image et les mounts avant d'ouvrir le conteneur ; réduire les accès hôte, réseau et secrets.", DEVCONTAINER)
    return findings, notices


def _prompt_document(file):
    findings, notices = [], []
    for number, raw in enumerate(io.StringIO(file.text), 1):
        if number > MAX_LINES:
            notices.append(notice("prompt-line-budget", file.path,
                                  "Limite de 20 000 lignes atteinte ; passages suivants non analysés."))
            break
        line = raw.lower()
        # Contexts teaching people not to obey attacks are not positive evidence.
        if re.search(r"\b(?:never|do not follow|don't follow|n'obéi|ne jamais|n’exécute|ne pas suivre|example|exemple|attack example)\b", line):
            continue
        override = re.search(r"\b(?:ignore|disregard|override)\s+(?:(?:all|any|the|your)\s+)*(?:previous|prior|system|developer|safety)\s+(?:instructions?|rules?|polic(?:y|ies))\b", line)
        override_fr = re.search(r"\bignor(?:e|ez|er)\s+(?:(?:toutes?|les|vos)\s+)*instructions?\s+(?:précédentes?|systèmes?|de sécurité)\b", line)
        exfil = re.search(r"\b(?:send|upload|exfiltrate|envoy(?:e|ez|er)|transmets?|transférez)\b.{0,120}(?:\.env\b|private keys?|clés? privées?|credentials|identifiants? secrets?|api[_ -]?keys?|tokens?)\b", line)
        if re.search(r"(?:do not|don't|ne pas|n['’]envoy|ne\s+(?:transmet|transf|partag)).{0,50}(?:send|upload|exfiltrate|jamais|pas)", line):
            exfil = None
        conceal = re.search(r"(?:do not|don't)\s+(?:tell|inform|notify)\s+(?:the\s+)?user", line) and re.search(r"\b(?:execute|run|send|upload|secret|token)\b", line)
        if override or override_fr or exfil or conceal:
            if len(findings) >= MAX_PER_FILE:
                notices.append(notice("prompt-findings-limit", file.path,
                                      "Limite de signaux de texte atteinte ; autres passages non analysés."))
                break
            findings.append(finding("AI-001", file, number, RULE_CATALOG["AI-001"], "medium", "low",
                                    "Une phrase ressemble à une demande de contourner les instructions, de cacher une action ou de transmettre des secrets. Le contexte et l'intention ne sont pas établis.",
                                    "Relire le passage comme une donnée non fiable, sans suivre ses directives ; limiter les permissions de l'agent et valider les actions sensibles hors de ce document.",
                                    INJECTION, "prompt-injection"))
    return findings, notices


def analyze(files):
    """Analyser les fichiers déjà lus et bornés par le collecteur parent."""
    findings, notices = [], []
    for path, file in sorted(files.items()):
        if len(findings) >= MAX_TOTAL:
            notices.append(notice("workflow-total-findings-limit", path,
                                  "Budget global de résultats atteint ; workflows et configurations restants non analysés."))
            break
        lower = path.lower()
        name = PurePosixPath(lower).name
        workflow = (lower.startswith(".github/workflows/") and lower.endswith((".yml", ".yaml"))) or name in ("action.yml", "action.yaml")
        if workflow:
            found, issues = _workflow(file, files)
            findings += found
            notices += issues
        if (name in ("mcp.json", ".mcp.json", "devcontainer.json", ".devcontainer.json")
                or lower.endswith(".vscode/tasks.json")
                or (".claude/" in lower and name in ("settings.json", "settings.local.json"))):
            found, issues = _agent_config(file)
            findings += found
            notices += issues
        if (name in ("agents.md", "claude.md", ".cursorrules") or name.startswith("readme")
                or (".cursor/rules/" in lower and lower.endswith((".md", ".mdc")))):
            found, issues = _prompt_document(file)
            findings += found
            notices += issues
    # Multiple server entries can resolve to the same metadata line: one alert
    # per rule/location is enough, without retaining names or configuration data.
    unique = {(f["rule_id"], f["path"], f["line"]): f for f in findings}
    if len(unique) > MAX_TOTAL:
        notices.append(notice("workflow-total-findings-limit", ".",
                              "Budget global de résultats atteint ; résultats supplémentaires omis."))
    notice_unique = {(n["code"], n["path"]): n for n in notices}
    return list(unique.values())[:MAX_TOTAL], list(notice_unique.values())

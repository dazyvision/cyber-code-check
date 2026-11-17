"""Entrée CLI : python3 -m cyber."""

import argparse
import json
import sys
from pathlib import Path

from . import __version__


def main(argv=None):
    parser = argparse.ArgumentParser(description="CYBER · Inspection statique de dépôts")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan-repo", help="Inspecter un dépôt local sans exécuter son code")
    scan.add_argument("repository", type=Path)
    scan.add_argument("--output", type=Path, default=Path("reports/repository"),
                      help="Dossier des rapports, obligatoirement hors du dépôt inspecté")
    scan.add_argument("--fail-on", choices=("high", "medium", "low", "info", "none"), default="high",
                      help="Seuil des signaux retournant le code 1 ; un scan incomplet retourne toujours 2")
    scan.add_argument("--max-files", type=int, default=10000)
    scan.add_argument("--max-file-bytes", type=int, default=2 * 1024 * 1024)
    scan.add_argument("--max-total-bytes", type=int, default=64 * 1024 * 1024)
    advisories = commands.add_parser("advisories", help="Comparer un lockfile npm aux avis OSV, sans installer de code")
    advisories.add_argument("lockfile", type=Path)
    advisory_mode = advisories.add_mutually_exclusive_group()
    advisory_mode.add_argument("--online", action="store_true",
                            help="Autoriser l'envoi des seuls noms/versions npm admissibles à api.osv.dev")
    advisory_mode.add_argument("--inventory-only", action="store_true",
                               help="Afficher les noms/versions et exclusions en JSON, sans réseau ni écriture")
    advisories.add_argument("--output", type=Path, default=Path("reports/advisories"),
                            help="Dossier local hors du dossier contenant le lockfile")
    advisories.add_argument("--fail-on", choices=("any", "none"), default="any",
                            help="any: code 1 si avis correspondant ; une couverture incomplète retourne toujours 2")
    args = parser.parse_args(argv)
    try:
        if args.command == "advisories":
            from .advisories import audit_lockfile, build_inventory
            from .advisory_report import advisory_exit_code, write_advisory_report
            from .scan_report import validate_output_location
            if args.inventory_only:
                inventory = build_inventory(args.lockfile)
                print(json.dumps(inventory, ensure_ascii=False, indent=2))
                return 0 if inventory['complete'] else 2
            validate_output_location(args.lockfile.parent, args.output)
            report = audit_lockfile(args.lockfile, online=args.online)
            write_advisory_report(report, args.output, lockfile=args.lockfile)
            print(f"{report['coverage']['queried_packages']} consultations de versions terminées · "
                  f"{len(report['findings'])} correspondance(s) paquet / avis.")
            if not report['coverage']['complete']:
                print("Couverture incomplète : consulter les exclusions et incidents du rapport.")
            print(f"Rapport : {(args.output.resolve() / 'index.html')}")
            print("Une correspondance ne démontre pas une exploitation ; aucun avis ne signifie pas code sûr.")
            return advisory_exit_code(report, args.fail_on)
        if args.command == "scan-repo":
            from .scanner import scan_repository, scan_exit_code
            from .scan_report import validate_output_location, write_scan_report
            validate_output_location(args.repository, args.output)
            report = scan_repository(args.repository, max_files=args.max_files,
                                     max_file_bytes=args.max_file_bytes, max_total_bytes=args.max_total_bytes)
            write_scan_report(report, args.output)
            counts = report['summary']
            print(f"{report['coverage']['files_analyzed']} fichiers analysés · "
                  f"{counts['high']} haute priorité · {counts['medium']} modérée · "
                  f"{counts['low']} basse · {counts['info']} information.")
            if not report['coverage']['complete_within_scope']:
                print("Analyse incomplète : consulter les incidents de lecture ou de parsing dans le rapport.")
            print(f"Rapport : {(args.output.resolve() / 'index.html')}")
            print("Un signal n’est pas une preuve de malware ; aucun signal ne signifie pas code sûr.")
            return scan_exit_code(report, args.fail_on)
    except (OSError, ValueError) as error:
        print(f"Erreur : {error}", file=sys.stderr)
        return 2


def mcp_main():
    try:
        from .mcp_server import main as serve
    except ModuleNotFoundError as error:
        if error.name != "mcp":
            raise
        print("Installer l’option mcp de cyber-code-check.", file=sys.stderr)
        return 2
    serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

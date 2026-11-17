"""Générer la configuration locale à partir de l’environnement installé."""

import json
import sys
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path


def main():
    try:
        distribution("cyber-code-check")
        distribution("mcp")
    except PackageNotFoundError:
        raise SystemExit('Installer d’abord `python -m pip install ".[mcp]"`.') from None

    config = {
        "$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
        "mcpServers": {
            "cyber-code-check": {
                "type": "stdio",
                "command": sys.executable,
                "args": ["-I", "-B", "-m", "cyber.mcp_server"],
            },
        },
    }
    path = Path(__file__).parent / "plugins" / "cyber-code-check" / "mcp.json"
    path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    print(path)


if __name__ == "__main__":
    main()

# CYBER dans ChatGPT desktop

Le plugin local analyse les fichiers texte transmis dans une conversation et produit des résultats structurés avec les lignes et recommandations. Il accepte jusqu’à 12 fichiers UTF-8, 32 Kio chacun et 96 Kio au total. Les chemins relatifs activent les règles propres à chaque format. Le serveur attend le contenu fourni et n’ouvre aucun chemin.

Le code d’entrée est traité par ChatGPT avant que le moteur local ne reçoive la demande. Pour chercher de vrais secrets ou examiner du code qui doit rester sur ton poste, utiliser la commande `scan-repo`.

## Installation depuis un clone

Prérequis pour ce parcours testé sous macOS avec Python 3.13. Utiliser une version de ChatGPT desktop qui permet l’installation de plugins locaux et disposer de la commande `codex`.

```sh
python3.13 -m venv .venv
.venv/bin/python -m pip install ".[mcp]"
.venv/bin/python chatgpt-plugin/configure.py
codex plugin marketplace add ./chatgpt-plugin
codex plugin add cyber-code-check@cyber-code-check-local
```

Le script crée un `mcp.json` ignoré par Git, avec le chemin du Python qui a installé l’outil. Si le chemin change, régénérer la configuration et réinstaller le plugin. Rouvrir ChatGPT desktop si le plugin n’apparaît pas, puis sélectionner **CYBER — Vérificateur de code** dans une nouvelle conversation compatible.

Exemple

> Vérifie ce fichier nommé package.json avec CYBER. Son contenu est `{"scripts":{"postinstall":"echo ok"}}`. Résume les règles détectées et les limites.

Le résultat attendu comprend le signal `PKG-001` sur le hook npm. Pour un client MCP qui accepte une commande stdio, utiliser le chemin absolu vers `cyber-code-check-mcp` dans l’environnement installé. Voir la [documentation OpenAI](https://developers.openai.com/plugins/build/plugins) pour le catalogue local.

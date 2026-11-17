# CYBER Code Check

CYBER examine une copie locale d’un dépôt avant utilisation. Il repère certains formats de secrets, les hooks npm, les références de dépendances, les permissions GitHub Actions et des configurations d’éditeur ou d’agent à revoir. Il lit les fichiers comme du texte et restitue des signaux avec règle, niveau de confiance, ligne et recommandation.

## Installer

La CLI fonctionne sous **macOS et Linux** avec **Python 3.10 ou ultérieur** et Git. Sur Windows, utiliser un environnement Linux comme WSL. La CLI n’a aucune dépendance Python à l’exécution.

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install "git+https://github.com/dazyvision/cyber-code-check.git"
cyber-code-check --help
```

Depuis un clone de ce dépôt, `python -m pip install .` installe le même outil.

## Examiner un dépôt

```sh
cyber-code-check scan-repo /chemin/vers/le-depot --output ./rapport-cyber
```

Le dossier des rapports doit être **hors du dépôt examiné**. Ouvrir `rapport-cyber/index.html` dans un navigateur. Le dossier contient aussi `report.md`, `report.json` et `report.sarif`.

Pour essayer sans dépôt tiers, lancer depuis le clone de CYBER

```sh
cyber-code-check scan-repo examples/demo-repo --output reports/demo
```

L’exemple doit signaler le hook npm `PKG-001`. Le code de sortie `0` indique qu’aucun signal n’a atteint le seuil choisi. Le code `1` indique un signal au seuil ou au-dessus. Le code `2` indique une erreur ou une analyse incomplète, même avec `--fail-on none`. Le seuil par défaut est `high`.

Le scan travaille sur les fichiers présents. Il ne lance ni le code ni les commandes du dépôt audité, ne clone pas de dépôt et ne contacte aucun serveur. Il n’inspecte pas l’historique Git, les binaires ni les dépendances distantes. Les heuristiques peuvent produire des faux positifs et manquer des problèmes. Les rapports masquent les valeurs de secrets détectés, mais peuvent contenir des noms de fichiers et des métadonnées privées. Relire avant de partager.

## Vérifier les avis de sécurité npm

```sh
cyber-code-check advisories /chemin/vers/package-lock.json --inventory-only
cyber-code-check advisories /chemin/vers/package-lock.json --online --output ./avis-cyber
```

Le collecteur accepte les lockfiles npm v2 et v3. `--inventory-only` affiche les noms et versions admissibles et les exclusions, sans réseau. `--online` transmet les couples admissibles à OSV. Vérifier l’inventaire avant envoi, car un nom de paquet hébergé sur npm peut être privé. En mode réseau, le code `1` indique une correspondance avec un avis, et `2` une erreur ou une couverture incomplète. Une correspondance invite à vérifier si les conditions de l’avis existent dans l’application.

## Plugin ChatGPT desktop

Le [guide du plugin](chatgpt-plugin/README.md) explique comment installer l’option MCP et ajouter le vérificateur dans les versions de ChatGPT desktop qui prennent en charge les plugins locaux. Pour examiner des secrets ou du code qui doit rester sur ton poste, utilise la CLI.

## Tests et licence

```sh
python -m unittest discover -s tests
```

Le test du serveur MCP nécessite l’option `mcp`. Les tests OSV utilisent des réponses simulées. Les sources des règles sont indiquées dans les rapports. Le code est distribué sous [licence MIT](LICENSE).

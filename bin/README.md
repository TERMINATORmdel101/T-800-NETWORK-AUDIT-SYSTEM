# bin

Ce dossier accueille les exécutables compilés de SIPA. Il est **vide par
défaut** : aucun `.exe` n'est distribué avec le dépôt, et `bin/*.exe` est dans
`.gitignore`.

Pour produire le vôtre :

```bash
pyinstaller --onefile --name sipa sipa.py
```

L'exécutable apparaît dans `dist/` ; déplacez-le ici si vous souhaitez le
conserver à côté du projet.

> N'utilisez pas `--noconsole` : sans console, le mode ligne de commande
> devient muet. Voir [INSTALLATION.md](../INSTALLATION.md).

L'exécutable a les mêmes prérequis que le code source : **Nmap** est
indispensable aux scans, Docker n'est utile qu'à OpenVAS.

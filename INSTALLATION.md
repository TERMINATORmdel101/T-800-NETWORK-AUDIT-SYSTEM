# Guide d'installation — SIPA

> ⚠️ **Usage légal uniquement.** N'auditez que vos propres systèmes ou des
> systèmes pour lesquels vous disposez d'une autorisation écrite.

## Prérequis

| Élément | Nécessité | Où l'obtenir |
|---|---|---|
| **Windows 10/11** (64 bits) | requis | — |
| **Python 3.9+** | requis | https://www.python.org/downloads/ |
| **Nmap** | **requis** pour tout scan réseau | https://nmap.org/download.html |
| Droits administrateur | facultatifs | voir plus bas |
| Docker Desktop | facultatif, pour OpenVAS uniquement | https://www.docker.com/products/docker-desktop |

SIPA **démarre et fonctionne sans droits administrateur et sans Docker**.
Les fonctions qui en ont besoin le signalent elles-mêmes.

### Ce que les droits administrateur apportent

- la détection du système d'exploitation (`nmap -O`) lors du scan complet ;
- la fragmentation IP (`nmap -f`) du mode furtif ;
- le honeypot sur le port 8888 (sinon il bascule sur 18888).

Sans ces droits, tout le reste fonctionne normalement.

---

## Installation depuis le code source

### 1. Cloner le dépôt

```bash
git clone https://github.com/TERMINATORmdel101/T-800-NETWORK-AUDIT-SYSTEM.git
```

```bash
cd T-800-NETWORK-AUDIT-SYSTEM
```

### 2. Créer un environnement virtuel (recommandé)

```bash
python -m venv .venv
```

```bash
.venv\Scripts\activate
```

### 3. Installer les dépendances

```bash
pip install -r requirements.txt
```

### 4. Vérifier que Nmap répond

```bash
nmap --version
```

Si la commande est introuvable, installez Nmap puis rouvrez votre terminal :
son chemin doit figurer dans le `PATH` Windows.

### 5. Lancer l'application

```bash
python sipa.py
```

Au premier lancement, le contrat de licence s'affiche. Une fois accepté, il
n'est plus redemandé.

### Ou en ligne de commande, sans interface

```bash
python sipa.py --cible 192.168.1.0/24 --scan complet --export html
```

Voir [USAGE_GUIDE.md](USAGE_GUIDE.md) pour toutes les options.

---

## Vérifier l'installation

```bash
python tests/run_all.py
```

Toutes les vérifications doivent passer, sans accès réseau.

---

## Compiler un exécutable (facultatif)

```bash
pip install pyinstaller
```

```bash
pyinstaller --onefile --name sipa sipa.py
```

L'exécutable apparaît dans `dist/` ; déplacez-le où vous voulez pour le
conserver.

> ⚠️ **N'utilisez pas `--noconsole`** : sans console, le mode ligne de commande
> devient muet (aucune sortie, aucun message d'erreur) et `sys.stdout` peut
> valoir `None`. Si vous ne voulez qu'une interface graphique, compilez malgré
> tout avec la console : elle reste discrète et sert au diagnostic.

Aucun exécutable précompilé n'est publié pour l'instant : il n'y a pas de page
*Releases* sur le dépôt. Compilez-le vous-même avec la commande ci-dessus.

---

## OpenVAS / Greenbone (facultatif)

Le pont OpenVAS nécessite :

1. un serveur Greenbone joignable (souvent lancé via Docker) ;
2. la bibliothèque `python-gvm`, déjà incluse dans `requirements.txt`.

Sans serveur Greenbone, le bouton OpenVAS signale simplement qu'il ne peut pas
se connecter. Tout le reste de SIPA fonctionne.

---

## Dépannage

### « Nmap introuvable »

```bash
nmap --version
```

Si cette commande échoue : réinstallez Nmap depuis https://nmap.org/download.html
en conservant le chemin d'installation par défaut, puis **rouvrez votre
terminal** pour que le `PATH` soit rechargé.

### L'application affiche « Dépendances absentes »

SIPA n'installe jamais rien à votre insu : il vous donne la commande exacte.

```bash
pip install -r requirements.txt
```

### Le port 5000 est déjà utilisé

Le serveur API REST écoute sur `127.0.0.1:5000`. Si le port est pris, fermez
l'application qui l'occupe avant d'activer l'API.

### Le port 8888 est refusé

Le honeypot tente d'abord `8888` (qui demande des droits administrateur sous
Windows), puis bascule automatiquement sur `18888`. Le journal indique lequel
est utilisé.

### La fenêtre est floue sur un écran 4K

SIPA appelle `SetProcessDpiAwareness` au démarrage. Si le flou persiste, vérifiez
dans les propriétés du raccourci Python : *Compatibilité → Modifier les
paramètres PPP élevés*.

---

## Support

Consultez le [README](README.md), ou ouvrez une **issue** sur le dépôt GitHub.

---

## À propos

SIPA est un projet personnel développé avec l'assistance d'une IA, pour combler
une niche : un outil d'audit réseau en français sur Windows. Voir la section
[« À propos de ce projet »](README.md#-à-propos-de-ce-projet) du README.

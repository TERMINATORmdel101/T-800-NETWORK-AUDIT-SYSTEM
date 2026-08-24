# SIPA — Programme unique intégré pour les audits

**Version 7.1.0** — Outil d'audit réseau et de sécurité pour Windows

> Projet personnel, à usage d'apprentissage et d'audit de vos propres réseaux.
> Ce README dit ce que l'outil fait **réellement** : voir
> [Ce qui n'est pas implémenté](#-ce-qui-nest-pas-implémenté) pour le reste.

---

## ⚠️ Usage légal uniquement

Cet outil est destiné à auditer **vos propres systèmes**, ou des systèmes pour
lesquels vous disposez d'une **autorisation écrite explicite**. Scanner un
réseau sans autorisation est illégal dans la plupart des pays. L'utilisateur
est seul responsable de l'usage qu'il en fait.

---

## 🎯 Le principe du projet : ne jamais simuler un résultat

SIPA a été assaini d'une longue série de fonctionnalités qui **prétendaient
agir sans rien faire** : des modes démo injectaient de fausses menaces dans les
rapports PDF, une intégration collectait une vraie clé API pour pinger
`google.com` et annoncer « connexion établie ».

La règle est donc simple : **si une fonctionnalité n'est pas implémentée, elle
le dit.** Aucune valeur de repli plausible, aucun résultat inventé pour
combler un vide. Une suite de 235 vérifications automatisées veille dessus.

---

## 🚀 Ce que SIPA fait vraiment

### 🔍 Scans réseau
Scan rapide · Scan complet (versions + détection d'OS) · Scan CVE ·
Détection de portes dérobées · Découverte d'hôtes (table ARP + `nmap -sn`) ·
Santé du réseau · Audit d'exposition de services

### 🛡️ Sécurité
Détection de rootkits · Scan SSL/TLS · **Chaîne de certificats réellement
récupérée et vérifiée** (validation contre le magasin système, calcul
d'expiration) · Détection de brute force · Recherche de persistance ·
Exploit-DB (SearchSploit) · Honeypot

### 🔬 Analyse et renseignement
Analyse DNS complète (résolution, DNSBL, DNSSEC, transfert de zone AXFR) ·
Analyse de trafic (sockets bruts, Scapy ou netstat) · Géolocalisation IP ·
OSINT · Graphe réseau (Plotly) · Intégrité ARP · Détection d'anomalies par
Isolation Forest

### 💻 Audit système
Audit système complet · Analyse des processus · Audit Active Directory ·
Analyse forensique · Recherche de secrets dans **vos** fichiers locaux

### 📊 Rapports
Export PDF · Excel · JSON · CSV · HTML · Historique, comparaison
différentielle et rejeu de scans

### 🤖 Automatisation
Configuration persistante · Journal d'audit · Alertes email · Webhooks
Slack/Discord · Planification de scans (APScheduler) · Scan multi-cibles ·
**Mode ligne de commande**

### 🌐 Intégrations externes
SHODAN · VirusTotal · Threat Intelligence · OpenVAS/Greenbone ·
Serveur API REST **local et authentifié** (127.0.0.1, jeton obligatoire)

### 🎨 Interface
**Thème sombre et thème clair**, appliqués immédiatement et mémorisés ·
**Interface traduite en 5 langues** (FR, EN, ES, DE, IT) · Tableau de bord ·
Inventaire des appareils (fabricant OUI, OS, première/dernière détection) ·
Mise à l'échelle 4K · Mode furtif (options Nmap `-T1 --scan-delay
--randomize-hosts`, plus `-f` si administrateur)

---

## 🚫 Ce qui n'est pas implémenté

Les boutons correspondants **l'annoncent explicitement** quand on les actionne :

| Fonctionnalité | État |
|---|---|
| Tenable Nessus, Qualys VMDR, Microsoft Defender, Rapid7 | aucune intégration |
| Mode Agent, Configuration Proxy, Sandbox | non implémentés |
| Heatmap des menaces, Timeline des événements | n'existent pas |

**Nécessitent une clé API** pour produire le moindre résultat : **SHODAN** et
**VirusTotal**. Sans clé, aucun résultat n'est produit — pas de données de
démonstration fictives.

---

## 📦 Prérequis

| Élément | Nécessité |
|---|---|
| **Windows 10/11** | l'interface et plusieurs audits sont spécifiques à Windows |
| **Python 3.9+** | testé sur 3.14 |
| **Nmap** | **indispensable** aux scans réseau — https://nmap.org/download.html |
| Droits administrateur | *facultatifs* : requis seulement pour la détection d'OS (`-O`), la fragmentation IP du mode furtif (`-f`) et le honeypot sur le port 8888 |
| Docker Desktop | *facultatif* : uniquement pour OpenVAS |

SIPA démarre et fonctionne sans droits administrateur et sans Docker ; les
fonctions concernées le signalent d'elles-mêmes.

---

## 🏁 Installation

```bash
git clone https://github.com/TERMINATORmdel101/T-800-NETWORK-AUDIT-SYSTEM.git
cd T-800-NETWORK-AUDIT-SYSTEM
pip install -r requirements.txt
python sipa.py
```

Voir [INSTALLATION.md](INSTALLATION.md) pour le détail et le dépannage.

### Mode ligne de commande

Utile pour une tâche planifiée Windows, une machine sans écran ou un script :

```bash
python sipa.py --cible 192.168.1.0/24 --scan rapide --export html
```

| Option | Rôle |
|---|---|
| `--cible` (ou `--target`) | Adresse IP, nom d'hôte ou plage CIDR (obligatoire) |
| `--scan` | `rapide`, `complet`, `cve` ou `backdoor` (défaut : `rapide`) |
| `--export` | `html`, `json`, `tout` ou `aucun` (défaut : `html`) |
| `--dossier` | Dossier de sortie des rapports (défaut : dossier courant) |
| `--silencieux` | N'afficher que les alertes et les erreurs |
| `--version` | Afficher la version et quitter |

`--export json` produit **aussi** un CSV (les deux sortent du même export).

Codes de sortie : `0` aucun constat · `1` des constats · `2` le scan n'a pas pu
s'exécuter. De quoi enchaîner dans un script.

---

## 📁 Structure du projet

```
T-800-NETWORK-AUDIT-SYSTEM/
├── sipa.py                    # Point d'entrée + classe AuditIA_Ultimate
├── sipa_core/                 # Modules de l'application
│   ├── __init__.py            # Nom et version (APP_NAME / APP_VERSION)
│   ├── theme.py               # Palettes sombre/claire, DPI, contraste WCAG
│   ├── widgets.py             # Widgets Tkinter personnalisés
│   ├── locales.py             # Traductions (interface + licence, 5 langues)
│   ├── services.py            # Config, journal d'audit, email, webhooks, PDF
│   ├── secrets.py             # Chiffrement des secrets (DPAPI Windows)
│   ├── cve.py                 # Base de vulnérabilités locale (NVD)
│   ├── knowledge.py           # Base d'appareils : fabricants OUI, typage
│   ├── cli.py                 # Mode ligne de commande
│   ├── gui_help.py            # Fenêtre d'aide (7 onglets)
│   ├── gui_console.py         # Console de commandes (liste blanche)
│   ├── gui_animations.py      # Effets visuels
│   ├── feature_scans.py       # CVE, DNS, rootkits
│   ├── feature_traffic.py     # Capture et analyse de trafic
│   └── feature_forensics.py   # Exploitation, persistance, forensique
├── tests/                     # Suites de tests
├── bin/                       # Exécutables générés (.exe), vide par défaut
└── requirements.txt           # Dépendances Python
```

Les modules de `sipa_core/` sont assemblés dans `AuditIA_Ultimate` par héritage
multiple (mixins), ce qui permet de découper progressivement sans toucher aux
sites d'appel.

---

## 🧪 Tests

```bash
python tests/run_all.py          # 235 vérifications hors ligne (rapide)
python tests/run_all.py --live   # ajoute les tests d'appels réseau réels
```

| Suite | Rôle |
|---|---|
| `test_structure.py` | Intégrité modulaire : imports, collisions de mixins, câblage et contraste des boutons |
| `test_fixes.py` | Non-régression des correctifs de sécurité, de fiabilité et d'honnêteté |
| `test_live.py` | Appels réseau réels (nécessite Internet) |

Les tests ne lancent jamais l'interface Tkinter : ils instancient la classe
principale sans passer par `__init__`.

---

## ⚠️ Limitations connues

- Sous Windows, le mot de passe SMTP et les webhooks Slack/Discord sont
  **chiffrés via la DPAPI** (déchiffrables uniquement par votre compte
  Windows). Hors Windows, ils restent en clair dans `config.json` : ce fichier
  est dans `.gitignore`, gardez-le hors de tout dépôt.
- Le **honeypot** écoute volontairement sur **toutes les interfaces**
  (`0.0.0.0:8888`, ou `18888` sans droits administrateur) : c'est nécessaire
  pour qu'il puisse piéger, mais ne l'activez pas sur un réseau non maîtrisé.
- Les **messages du journal** restent en français même lorsque l'interface est
  traduite : seuls les libellés (boutons, onglets, catégories) le sont.
- Le projet n'a **pas été validé en environnement de production**. Les scans
  Nmap ont été testés ponctuellement, pas sur un parc étendu.

---

## 📚 Documentation

- [INSTALLATION.md](INSTALLATION.md) — installation, compilation et dépannage
- [USAGE_GUIDE.md](USAGE_GUIDE.md) — manuel d'utilisation
- [CHANGELOG.md](CHANGELOG.md) — historique des versions
- [CLAUDE.md](CLAUDE.md) — repères techniques pour contribuer

---

## 🏆 Crédits

- **Conception fonctionnelle et idées originales** : T-800
- **Développement assisté** principalement par quatre IA collaboratives
- **Contributions et retours utilisateurs** bienvenus pour améliorer le logiciel

---

## 📄 Licence & contribution

Distribué sous **licence MIT** (voir [LICENSE](LICENSE)).

Souhaits de l'auteur, sans valeur contraignante au-delà de la licence MIT :
citer la paternité du travail original, et signaler les bugs ou améliorations
plutôt que de forker en silence. Les contributions sont les bienvenues —
ouvrez une **issue** ou une **pull request**.

**Statut** : 🚧 En cours de fiabilisation · Projet personnel · Contributions bienvenues

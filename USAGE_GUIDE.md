# Guide d'utilisation — SIPA

> ⚠️ **Usage légal uniquement.** N'auditez que vos propres systèmes ou des
> systèmes pour lesquels vous avez une autorisation écrite. Scanner un réseau
> sans permission est illégal dans la plupart des pays.

## Lancer l'application

```bash
python sipa.py
```

Au **premier** lancement, acceptez le contrat de licence. Il n'est plus
redemandé ensuite (la préférence est enregistrée dans `config.json`).

## La cible

En haut de la fenêtre, le champ **Cible** accepte :

- une adresse IP : `192.168.1.10`
- un nom d'hôte : `scanme.nmap.org`
- une plage CIDR : `192.168.1.0/24`

Le champ affiche un texte d'aide grisé tant qu'il est vide ; il s'efface dès
que vous cliquez dedans. Le bouton **📍 DÉTECTER** remplit automatiquement
votre sous-réseau local.

## Les onglets

Chaque onglet propose ses sous-catégories sous forme de **boutons segmentés**
(la catégorie active est marquée par un aplat rouge et un soulignement).

### 🔍 ANALYSES

- **Scans réseau** — scan rapide, complet, CVE, portes dérobées, santé réseau,
  audit d'exposition de services, DNS, SSL/TLS, chaîne SSL.
- **Menaces & forensique** — exploits, rootkits, persistance, brute force,
  analyse forensique, audit système, anomalies (IA), secrets locaux.

Les quatre types de scan principaux :

| Scan | Ce qu'il fait | Options Nmap |
|---|---|---|
| Rapide | Ports courants, très rapide | `-F -T4` |
| Complet | Versions des services + détection d'OS | `-sV -O -T4` |
| CVE | Scan de vulnérabilités via scripts Nmap | `-sV --script vuln -T4` |
| Backdoors | Ports de portes dérobées connues | `-p … --script banner` |

La **détection d'OS** (`-O`) nécessite des droits administrateur ; sans eux,
Nmap l'ignore proprement et le reste du scan aboutit.

### 🌐 RÉSEAU & RENSEIGNEMENT

- **Cartographie & trafic** — analyse de trafic, graphiques temps réel, graphe
  réseau, changements réseau, intégrité ARP, constructeur MAC, Wi-Fi,
  découverte d'hôtes.
- **Renseignement externe** — SHODAN, VirusTotal, réputation IP, SearchSploit,
  OSINT, Active Directory, géolocalisation, technologies web.

> SHODAN et VirusTotal nécessitent une clé API. Sans clé, **aucun résultat
> n'est produit** — pas de fausses données pour faire joli.

### 📑 RAPPORTS & DÉFENSE

- **Rapports & historique** — export PDF/Excel/JSON, rapport HTML, tableau de
  bord, appareils détectés, historique, comparaison de deux scans, rejeu,
  journal, capture d'écran.
- **Défense & surveillance** — monitoring continu, règles de pare-feu,
  honeypot, mode furtif, processus, sandbox *(non implémentée : le bouton le
  signale)*.

### 💻 COMMANDES

Console de diagnostic restreinte à une liste blanche de commandes sûres :
`ping`, `ipconfig`, `netstat`, `nslookup`, `tracert`, `arp`, `whoami`,
`hostname`, `tasklist`.

### ⚙️ PARAMÈTRES

- **Intégrations** — OpenVAS, serveur API REST (local, authentifié par jeton),
  scan multi-cibles, planification de scans, Slack, webhooks. *Tenable, Qualys,
  Defender et le mode agent ne sont pas implémentés : les boutons l'annoncent.*
- **Préférences & alertes** — aide, configuration email, notifications, sons,
  mode performance, thème et langue.

## Thème clair et thème sombre

**Paramètres → Préférences & alertes → 🌙 THÈME SOMBRE / ☀️ THÈME CLAIR.**

Le changement est appliqué **immédiatement** : l'interface est reconstruite
avec la nouvelle palette et le contenu du journal est conservé. La préférence
est enregistrée dans `config.json` et restituée au lancement suivant. Le bouton
**🎨 PALETTE ACTIVE** rappelle laquelle est en cours.

Les deux palettes respectent un contraste WCAG d'au moins 4.5:1 sur chaque
bouton — vérifié par les tests.

## Changer la langue

L'interface existe en **français, anglais, espagnol, allemand et italien**.
Le changement retraduit les boutons, les onglets et les catégories, puis
enregistre la préférence.

> Les **messages du journal** restent en français : seuls les libellés de
> l'interface sont traduits.

## Le mode furtif

**Paramètres → 🥷 MODE FURTIF** modifie réellement les options passées à Nmap :

| Option ajoutée | Effet |
|---|---|
| `-T1` | rythme le plus lent (remplace `-T4`) |
| `--scan-delay 500ms` | attente imposée entre deux sondes |
| `--max-retries 1` | moins de paquets réémis |
| `--randomize-hosts` | ordre des cibles brouillé |
| `-f` | fragmentation IP — **seulement si SIPA tourne en administrateur** |

Le journal affiche la ligne d'options exacte au moment de l'activation, et
indique explicitement quand `-f` n'est pas appliqué. **Les scans deviennent
nettement plus lents** : c'est le principe.

## Comprendre les résultats

Chaque constat indique l'**hôte**, le **port**, le **service**, un **détail**,
une **action recommandée** et une **sévérité** sur cinq niveaux :

🔴 CRITIQUE · 🟠 ÉLEVÉ · 🟡 MOYEN · 🔵 FAIBLE · ⚪ INFO

La sévérité des CVE provient directement du score CVSS officiel.

## La chaîne SSL

**Analyses → ⛓️ CHAÎNE SSL** ouvre une vraie connexion TLS sur le port 443 de
la cible et :

- valide (ou non) la chaîne contre le magasin de confiance du système, en
  affichant le motif exact d'un refus ;
- décrit chaque certificat de la chaîne : sujet, émetteur, dates de validité ;
- calcule les jours restants et crée un constat si un certificat est expiré ou
  expire dans moins de 30 jours.

Si la cible n'écoute pas en TLS, SIPA le dit — il n'annonce jamais une chaîne
valide par défaut.

## Détection de dérive et alertes

Chaque scan est comparé au précédent (référence conservée par cible). Si un
hôte ou un port apparaît, un constat est créé. Pour recevoir une alerte
email/Slack/Discord, activez-la dans **Paramètres → Intégrations** et cochez
« Alerter quand un hôte ou un port apparaît ».

## Planifier des scans

**Paramètres → Intégrations → ⏰ PLANIFIER DES SCANS** : choisissez l'heure,
les jours et le type de scan. Les scans planifiés s'exécutent tant que
l'application est ouverte. Pour des scans totalement automatiques (machine sans
session ouverte), utilisez le **mode ligne de commande** avec le Planificateur
de tâches Windows.

## Mode ligne de commande

Sans ouvrir l'interface — idéal pour une tâche planifiée ou un script :

```bash
python sipa.py --cible 192.168.1.0/24 --scan complet --export html
```

| Option | Rôle |
|---|---|
| `--cible` (ou `--target`) | IP, nom d'hôte ou plage CIDR (obligatoire) |
| `--scan` | `rapide`, `complet`, `cve`, `backdoor` (défaut : `rapide`) |
| `--export` | `html`, `json`, `tout`, `aucun` (défaut : `html`) |
| `--dossier` | dossier de sortie des rapports |
| `--silencieux` | n'afficher que les alertes et les erreurs |
| `--version` | afficher la version et quitter |

`--export json` produit **aussi** un fichier CSV : les deux sortent du même
export.

Codes de sortie : `0` aucun constat · `1` des constats · `2` le scan n'a pas pu
s'exécuter.

## Arrêter un scan

Le bouton **⏹ ARRÊTER LE SCAN** (barre du bas) interrompt l'analyse. Le scan
Nmap en cours va à son terme, mais aucun hôte, port ou cible supplémentaire
n'est traité ensuite. En ligne de commande, `Ctrl+C` a le même effet.

Pendant un scan, les boutons de la grille sont grisés pour éviter de lancer
deux analyses concurrentes.

## Exporter l'aide

La fenêtre **❓ AIDE** comporte 7 onglets. Le bouton **💾 EXPORTER AIDE** écrit
leur contenu intégral dans un fichier texte (environ 50 Ko).

# Historique des versions

## Version 7.1.0 — passe de vérité avant publication

Audit complet du dépôt avant sa mise en ligne. Le fil conducteur : **plus
aucune fonctionnalité ne doit annoncer un résultat qu'elle n'a pas obtenu**, et
`python sipa.py` doit fonctionner pour quiconque clone le dépôt.

### 🚨 Corrections bloquantes

- **L'application refusait de démarrer sans droits administrateur.** Le
  bootstrap appelait `input()` puis `sys.exit(1)` ; `SystemExit` n'étant pas
  rattrapé par le `except Exception` englobant, la commande documentée
  `python sipa.py` quittait immédiatement. Les outils externes sont désormais
  vérifiés et signalés, jamais imposés.
- **Un `pip install` non sollicité se déclenchait à chaque lancement.** Les
  dépendances étaient cherchées par leur nom PyPI (`python-nmap`, `pillow`)
  au lieu de leur nom d'import (`nmap`, `PIL`) : elles paraissaient toujours
  absentes. La correspondance est corrigée, et SIPA se contente désormais
  d'indiquer la commande à lancer.

### 🐛 Bugs corrigés

- **Trois modules appelaient des noms globaux inexistants**, hérités de
  l'extraction en mixins : `requests` dans `feature_scans`, `scapy` et
  `SCAPY_AVAILABLE` dans `feature_traffic`, `random` dans `services`. Chaque
  appel levait un `NameError` avalé par un `except` large. Conséquence
  concrète : **l'analyse DNS s'arrêtait silencieusement avant les étapes
  DNSBL, DNSSEC et transfert de zone AXFR**, et le mode d'analyse profonde
  Scapy échouait systématiquement, même avec Scapy installé.
- **Le texte d'aide du champ cible ne s'effaçait jamais** et se dupliquait à
  chaque perte de focus, au point d'être envoyé comme cible de scan.
- **`disable_buttons()` ne désactivait rien** : la méthode parcourait
  49 attributs qui n'existent plus depuis que les boutons sont générés
  dynamiquement.
- **OpenVAS était inaccessible en toutes circonstances** : la détection
  importait `Gvmd` depuis `gvm.protocols`, symbole qui n'existe pas dans
  python-gvm. Le bouton réclamait donc d'installer une bibliothèque déjà
  présente.
- **Le contrat de licence réapparaissait à chaque démarrage** alors que la
  documentation annonçait « au premier lancement ». L'acceptation est
  maintenant mémorisée.

### 🎯 Fonctionnalités qui faisaient semblant, désormais réelles

- **Chaîne SSL** — affichait « Leaf / Intermediate / Root : Valid » puis
  « Chain Status: COMPLETE » sans ouvrir le moindre socket, quelle que soit la
  cible. Ouvre désormais une vraie connexion TLS, valide la chaîne contre le
  magasin de confiance du système, décrit chaque certificat et calcule
  réellement les jours restants avant expiration.
- **Scan broadcast** — annonçait « Sending ARP requests… » puis listait
  toujours `192.168.1.1/51/101/151/201` comme actifs, sans émettre un paquet
  et sans tenir compte de la cible. Croise désormais la table ARP du système
  et un balayage `nmap -sn`.
- **Mode furtif** — le journal promettait délais aléatoires et fragmentation
  IP, mais aucun scan ne lisait le drapeau : les options Nmap étaient
  identiques. `run_nmap` applique maintenant `-T1 --scan-delay 500ms
  --max-retries 1 --randomize-hosts`, plus `-f` si les droits le permettent —
  et le dit explicitement quand ce n'est pas le cas.
- **Thème clair** — les deux boutons affichaient « Theme will be applied on
  next restart » sans rien enregistrer, et aucune palette claire n'existait.
  Deux palettes complètes sont désormais définies, appliquées immédiatement
  par reconstruction de l'interface, et mémorisées.
- **Changement de langue** — affichait « Buttons will update when available »
  et ne reconfigurait aucun widget. Les 89 libellés de l'interface (boutons,
  onglets, catégories) sont traduits en anglais, espagnol, allemand et
  italien, appliqués immédiatement et mémorisés.
- **Export de l'aide** — écrivait un en-tête et la phrase « Documentation aide
  système - complet », puis annonçait « Aide exportée avec succès ». Exporte
  maintenant le contenu intégral des 7 onglets (~50 Ko).

### 🧹 Nettoyage

- Suppression de 87 lignes de code mort qui **fabriquait des résultats** :
  analyse malware annonçant toujours « CLEAN », statistiques de menaces
  inventées (3 critiques, 7 élevées…), graphiques et règles de notification
  factices, liste de menaces codée en dur.
- Suppression de la **fausse offre commerciale** dans la fenêtre d'aide :
  comparatif « GRATUIT vs PRO vs ENTERPRISE » avec un tarif de 99 €/mois pour
  une offre qui n'existe pas.
- Statistiques de l'aide corrigées (lignes de code, onglets, langues) et
  affirmations invérifiables retirées (« OAuth 2.0 », « Dashboard 3D »,
  « 113+ fonctionnalités »).
- `LICENSE` restauré au texte MIT canonique : un bloc inséré empêchait GitHub
  de reconnaître la licence et ajoutait des contraintes au-delà de la MIT.
  Les souhaits de l'auteur sont désormais exprimés dans le README.
- `scikit-learn` ajouté à `requirements.txt` (bouton « Anomalies (IA) ») ;
  `pandas`, jamais utilisé, retiré des dépendances vérifiées.
- `.gitignore` élargi ; l'aide exportée `T-800_AIDE_COMPLETE.txt`, qui était
  versionnée par erreur, est retirée du suivi.

### 📚 Documentation

README, INSTALLATION, USAGE_GUIDE et CLAUDE relus ligne à ligne et confrontés
au code. Les fonctionnalités inexistantes (heatmap, timeline) ne sont plus
annoncées, les prérequis distinguent l'indispensable du facultatif, et les
limitations réelles sont énoncées — dont le honeypot qui écoute sur toutes les
interfaces.

### 🧪 Tests

De 186 à **235 vérifications**, dont une quarantaine dédiées aux régressions
ci-dessus : contraste des deux palettes, couverture des traductions, absence
de résultats codés en dur, bootstrap qui ne bloque plus.

---

## Version 7.0.0

### ✨ Nouvelles fonctionnalités
- **Base de vulnérabilités CVE** : corrélation des services détectés avec les
  CVE connues (base NVD mise en cache localement).
- **Détection de dérive réseau** : chaque scan est comparé au précédent, avec
  alertes email/Slack/Discord quand un hôte ou un port apparaît.
- **Mode ligne de commande** : scans sans interface, pour tâches planifiées et
  scripts (`python sipa.py --cible ...`).
- **Planification de scans** réellement fonctionnelle (APScheduler).
- **Annulation de scan** (bouton dédié et `Ctrl+C` en ligne de commande).
- **Chiffrement des secrets** via la DPAPI Windows (mot de passe SMTP, webhooks).
- **Base de connaissances des appareils** : registre des fabricants (OUI),
  détection d'OS, première et dernière détection, constats acceptés.

### 🔧 Fiabilité et sécurité
- Serveur API REST limité à localhost et authentifié par jeton.
- Console de commandes restreinte à une liste blanche.
- Assainissement des noms de fichiers, fermeture des sockets, verrou SQLite.
- Suppression des résultats fictifs qui polluaient les rapports.
- Fonctionnalités non implémentées désormais annoncées comme telles.

### 🎨 Interface
- Correction de la mise à l'échelle DPI et de la transparence.
- Refonte du système de couleurs : contraste vérifié sur chaque bouton.
- Catégories en boutons segmentés, libellés clarifiés.
- Inventaire des appareils dans sa propre fenêtre.

### 🏗️ Architecture
- Découpage du fichier unique en un paquet `sipa_core/` de modules (mixins).
- Suite de tests automatisés (`python tests/run_all.py`).

---

## Versions antérieures (1.x – 6.x)

Développement initial : interface Tkinter, scans réseau et DNS, audit système,
exports, sur un fichier unique. Voir l'historique git pour le détail.

---

Pour plus de détails : [README.md](README.md) · [INSTALLATION.md](INSTALLATION.md)

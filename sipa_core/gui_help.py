"""Fenetre d'aide de SIPA (onglets demarrage, categories, tutoriels, FAQ...).

Extrait de sipa.py (phase 3 : refonte modulaire) sous forme de mixin : les
methodes gardent leur `self` et AuditIA_Ultimate en herite, donc aucun site
d'appel ne change. Ce bloc est purement presentationnel -- il ne fait que
construire des widgets a partir de textes statiques.
"""

from datetime import datetime

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from sipa_core import APP_NAME, APP_VERSION
from sipa_core.theme import THEME


class HelpTabsMixin:
    """Construction de la fenetre d'aide multi-onglets."""

    def show_help(self):
        """Affiche une fenêtre d'aide COMPLÈTE avec catégories, tutoriels et FAQ"""
        help_window = tk.Toplevel(self.root)
        help_window.title(f"Aide — {APP_NAME} {APP_VERSION}")
        help_window.geometry("1000x900")
        help_window.configure(bg=THEME["bg"])
        
        # Header
        header = tk.Frame(help_window, bg=THEME["bg"], bd=1, relief="solid")
        header.pack(fill="x", padx=THEME["padding_lg"], pady=THEME["padding_lg"])
        
        tk.Label(header, text=f"{APP_NAME} {APP_VERSION} — Aide", 
                 font=THEME["font_header"], bg=THEME["bg"], fg=THEME["fg"]).pack(anchor="w")
        tk.Label(header, text="Audit réseau professionnel: Scan réel | Monitoring 24/7 | Défense active | OSINT", 
                 font=THEME["font_label"], bg=THEME["bg"], fg=THEME["accent"]).pack(anchor="w")
        
        # Les onglets s'enregistrent au fur et a mesure pour que l'export
        # puisse recopier leur contenu reel.
        self._help_text_widgets = []
        self._help_tab_titles = [
            "DEMARRAGE RAPIDE", "CATEGORIES DE BOUTONS", "TUTORIELS",
            "PARAMETRES", "FAQ ET DEPANNAGE", "MENACES ACTUELLES",
            "INFORMATIONS",
        ]

        # Tab container
        notebook = ttk.Notebook(help_window)
        notebook.pack(padx=THEME["padding_lg"], pady=THEME["padding_std"], fill="both", expand=True)
        
        # TAB 1: DÉMARRAGE RAPIDE
        tab1 = tk.Frame(notebook, bg=THEME["bg"])
        notebook.add(tab1, text="DÉMARRAGE RAPIDE")
        self._create_help_tab_quickstart(tab1)
        
        # TAB 2: CATÉGORIES DE BOUTONS
        tab2 = tk.Frame(notebook, bg=THEME["bg"])
        notebook.add(tab2, text="CATÉGORIES")
        self._create_help_tab_categories(tab2)
        
        # TAB 3: TUTORIELS PAR CAS D'USAGE
        tab3 = tk.Frame(notebook, bg=THEME["bg"])
        notebook.add(tab3, text="TUTORIELS")
        self._create_help_tab_tutorials(tab3)
        
        # TAB 4: PARAMÈTRES AVANCÉS
        tab4 = tk.Frame(notebook, bg=THEME["bg"])
        notebook.add(tab4, text="PARAMÈTRES")
        self._create_help_tab_settings(tab4)
        
        # TAB 5: FAQ & TROUBLESHOOTING
        tab5 = tk.Frame(notebook, bg=THEME["bg"])
        notebook.add(tab5, text="FAQ")
        self._create_help_tab_faq(tab5)
        
        # TAB 5b: MENACES ACTUELLES
        tab5b = tk.Frame(notebook, bg=THEME["bg"])
        notebook.add(tab5b, text="MENACES")
        self._create_help_tab_threats(tab5b)
        
        # TAB 6: INFORMATIONS
        tab6 = tk.Frame(notebook, bg=THEME["bg"])
        notebook.add(tab6, text="ℹ INFOS")
        self._create_help_tab_info(tab6)
        
        # Footer
        footer = tk.Frame(help_window, bg=THEME["bg"])
        footer.pack(fill="x", padx=THEME["padding_lg"], pady=THEME["padding_std"])
        
        close_btn = tk.Button(footer, text="FERMER", command=help_window.destroy,
                             bg=THEME["accent"], fg=THEME["bg"], font=THEME["font_button"],
                             padx=THEME["padding_lg"], pady=THEME["padding_std"])
        close_btn.pack(side=tk.RIGHT)
        
        save_btn = tk.Button(footer, text="EXPORTER AIDE", 
                            command=lambda: self._export_help_to_file(),
                            bg=THEME["warn"], fg=THEME["bg"], font=THEME["font_button"],
                            padx=THEME["padding_lg"], pady=THEME["padding_std"])
        save_btn.pack(side=tk.RIGHT, padx=THEME["padding_std"])

    def _create_help_scrollframe(self, parent):
        """Cree un cadre defilant pour l'aide, et enregistre sa zone de texte.

        L'enregistrement sert a l'export : celui-ci n'ecrivait qu'un en-tete
        et la phrase "Documentation aide systeme - complet", tout en annoncant
        "Aide exportee avec succes". Il exporte desormais le texte reel.
        """
        frame = tk.Frame(parent, bg=THEME["bg"])
        frame.pack(padx=THEME["padding_lg"], pady=THEME["padding_std"],
                   fill="both", expand=True)

        scrollbar = ttk.Scrollbar(frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        text = tk.Text(frame, width=120, height=35, bg="#050505", fg=THEME["accent"],
                       font=THEME["font_mono"], yscrollcommand=scrollbar.set,
                       relief="flat", bd=0)
        text.pack(side=tk.LEFT, fill="both", expand=True)
        scrollbar.config(command=text.yview)
        text.config(state="normal")

        if not hasattr(self, "_help_text_widgets"):
            self._help_text_widgets = []
        self._help_text_widgets.append(text)

        return text

    def _create_help_tab_quickstart(self, tab):
        """Tab 1: Démarrage rapide"""
        text = self._create_help_scrollframe(tab)
        
        content = """
╔════════════════════════════════════════════════════════════════════════════╗
║ DÉMARRAGE RAPIDE ║
╚════════════════════════════════════════════════════════════════════════════╝

ÉTAPE 1: INSTALLATION COMPLÈTE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  1. Python 3.8+: https://python.org
  2. Dépendances: pip install -r requirements.txt
  3. Nmap: https://nmap.org (ESSENTIEL)
  4. (Optionnel) Shodan CLI pour recherches avancées
  5. Lancez: python vulanribliti.py

ÉTAPE 2: CONFIGURATION RÉSEAU
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Cliquez " AUTO-LOCATE" pour détecter votre réseau (ex: 192.168.1.0/24)
  Ou entrez manuellement une plage CIDR
  Le programme valide automatiquement le format
  Appuyez sur " SCAN RAPIDE" pour commencer

ÉTAPE 3: INTERPRÉTATION DES RÉSULTATS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  CRITICAL → Action immédiate (malware, intrusion détectée)
  WARNING → À investiguer rapidement
  INFO → Logs informatifs, audit
  OK → Aucun problème détecté
  ALERT → Activité anormale, surveillance

FONCTIONNALITÉS PRINCIPALES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  [1] SCAN EN TEMPS RÉEL
     → Nmap scanning avec résultats visuels
     → Graphique du réseau découvert (Plotly, ouvert au navigateur)
     → Comparaison entre scans historiques

  [2] MONITORING 24/7
     → CPU/RAM/Disk via psutil (temps réel)
     → Windows Event Log (alertes système)
     → Détection anomalies IA (Isolation Forest)

  [3] FORENSICS AVANCÉES
     → Registre Windows (persistance malware)
     → Timeline système32 (intégrité fichiers)
     → Audit WMI (hotfixes, utilisateurs, logiciels)

  [4] DÉFENSE ACTIVE
     → Firewall Windows intégré (netsh)
     → Honeypot interactif (capture credentials)
     → ARP Sentinel (détection MITM/usurpation)

  [5] RECONNAISSANCE OSINT
     → DNS reverse lookup
     → ISP/Géolocalisation via API
     → Traceroute + Web headers analysis
     → MAC vendor identification

  [6] SÉCURITÉ OPÉRATIONNELLE
     → WiFi credential extraction (WPA keys)
     → REST API Server (port 5000)
     → Command execution sécurisée (whitelist+shlex)
     → Emergency wipe ( Panic Button)

BONNES PRATIQUES DE SÉCURITÉ
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  LÉGALITÉ: N'utilisez JAMAIS sans autorisation écrite
  Informez votre équipe IT avant les scans
  Exécutez en heures creuses (faible trafic)
  Archivez tous les rapports (audit trail)
  Obtenez approbation légale/conformité
  Utilisez MODE PERFORMANCE si ralentissement ( toggle)

DÉPANNAGE RAPIDE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Nmap not found? → Installer depuis nmap.org
  Permission denied? → Lancer en mode administrateur
  Import errors? → pip install -r requirements.txt
  Réseau invalide? → Utilisez format CIDR (ex: 192.168.1.0/24)
  Ralentissements? → Activez Mode Performance ()

OBTENIR DE L'AIDE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  → Onglet CATÉGORIES pour le détail de chaque bouton
  → Onglet TUTORIELS pour des cas d'usage pratiques
  → Onglet PARAMÈTRES pour la configuration avancée
  → Onglet FAQ pour les questions fréquentes
  → Onglet MENACES pour les menaces actuelles
"""
        text.insert("1.0", content)
        text.config(state="disabled")

    def _create_help_tab_categories(self, tab):
        """Tab 2: Catégories de boutons"""
        text = self._create_help_scrollframe(tab)
        
        content = """
╔════════════════════════════════════════════════════════════════════════════╗
║ CATÉGORIES DE BOUTONS - GUIDE COMPLET ║
╚════════════════════════════════════════════════════════════════════════════╝

1⃣ ONGLET: SCANS PRINCIPAUX
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ▶ SCAN RAPIDE
    • Scan de base, très rapide (1-5 min)
    • Détecte les hôtes actifs et ports ouverts principaux
    • Idéal pour une vue d'ensemble rapide

  ▶ SCAN COMPLET
    • Analyse détaillée et exhaustive (5-30 min)
    • Détecte tous les ports, services, versions
    • Idéal pour audit de sécurité complet

  ▶ VULN SCAN (CVE)
    • Recherche spécifiquement les vulnérabilités connues
    • Compare contre bases de données CVE
    • Génère rapport d'exploitation

  BACKDOOR DETECT
    • Scan des ports backdoor connus
    • Détecte les malwares avec port d'accès
    • Alerte immédiate si détection

  NETWORK HEALTH
    • Analyse la santé générale du réseau
    • Détecte anomalies et congestion
    • Recommandations d'optimisation

2⃣ ONGLET: SÉCURITÉ
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  EXPLOITS
    • Teste les exploits courants (EternalBlue, etc.)
    • Simule attaque pour valider sécurité
    • Rapport d'exposition détaillé

  PERSISTENCE
    • Détecte mécanismes de persistance
    • Cherche backdoors, rootkits, malwares
    • Analyse au niveau système

  FORENSIQUE
    • Analyse complète des preuves digitales
    • Logs, traces, historiques
    • Idéal pour incident response

  ROOTKIT
    • Détecte rootkits et chevaux de Troie
    • Analyse processus système suspectes
    • Alerte automatique

  SSL/TLS
    • Audit complet des certificats SSL
    • Vérifie validité, force de chiffrement
    • Détecte certificats auto-signés

  SSL CHAIN
    • Analyse la chaîne complète SSL
    • Valide intégrité CA et intermédiaires
    • Détecte rompus ou auto-signés

3⃣ ONGLET: RENSEIGNEMENTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SHODAN SCAN
    • Interroge base SHODAN (Internet devices)
    • Trouve services exposés en ligne
    • (Nécessite clé API SHODAN)

  OSINT
    • Recherche renseignements publics
    • Informations sociales, whois, DNS
    • Empreinte digitale complète

  GEO-IP
    • Localise géographiquement les IPs
    • Détecte connexions anormales
    • Crée carte des menaces

  VIRUSTOTAL
    • Scanne dans VirusTotal
    • Vérification multi-antivirus
    • Réputation d'IP et domaines
    • (Nécessite clé API VirusTotal)

4⃣ ONGLET: RÉSEAU
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  TRAFIC
    • Capture et analyse les paquets réseau
    • Visualise flux principaux
    • Statistiques bande passante

  GRAPHE
    • Génère représentation visuelle du réseau
    • Montre interconnexions entre systèmes
    • Identifie points critiques

  DNS
    • Analyse les serveurs DNS
    • Teste résolution et sécurité
    • Détecte piratage DNS

  AUDIT SERVICES STABLE
    • AUDIT MULTI-PORTS: Teste 9 services critiques
      - Ports: 21(FTP), 22(SSH), 23(Telnet), 80(HTTP), 443(HTTPS),
               445(SMB), 3306(MySQL), 3389(RDP), 5900(VNC)
    • DÉTECTION BANNIÈRES: Récupère versions exactes
    • VÉRIFICATION SSL/TLS: Validité certificats
    • ANALYSE DNS: Résolution inverse/normale
    • SCORE SÉCURITÉ: 0-100 avec recommandations
    • HISTORIQUE: Sauvegarde audits pour comparaison
    • Reconnaissance PASSIVE (non intrusive)
    • Recommandations automatiques de durcissement

5⃣ ONGLET: DÉTECTION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  BRUTE FORCE
    • Détecte tentatives d'accès brutes
    • Analyse logs d'authentification
    • Identifie attaques par dictionnaire

  CREDENTIALS
    • Recherche mots de passe exposés
    • Vérifie bases de données compromises
    • Recommande renforcement sécurité

  IA ANOMALIES
    • Utilise machine learning pour anomalies
    • Comportement réseau anormal
    • Alertes intelligentes

  HONEYPOT
    • Crée pièges pour attaquants
    • Monitoring et logging intégré
    • Identification d'intrusions

6⃣ ONGLET: RAPPORTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  EXPORT
    • Exporte en PDF, Excel, JSON, CSV
    • Formats professionnels
    • Prêt pour présentation

  CUSTOM
    • Génère rapport personnalisé
    • Sélectionne sections importantes
    • Style entreprise

  HEATMAP
    • Visualisation des menaces
    • Carte de chaleur géographique
    • Densité des attaques

  ⏰ TIMELINE
    • Chronologie des événements
    • Visualise chaîne d'incident
    • Analyse temporelle

  HISTORIQUE
    • Accès aux scans antérieurs
    • Comparaison dans le temps
    • Tendances de sécurité

  LOGS
    • Visionneuse des logs
    • Recherche et filtrage
    • Export pour analyse

7⃣ ONGLET: AVANCÉ
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  RAPID7 / TENABLE / QUALYS / DEFENDER
    • Intégration avec outils professionnels
    • Synchronisation des données
    • Scoring unifié des risques

  API REST
    • Démarre serveur API REST
    • Permet contrôle à distance
    • Intégration avec autres outils

  MULTI-TARGET
    • Scanne plusieurs cibles en parallèle
    • Gain de temps significatif
    • Idéal pour réseau complet

8⃣ ONGLET: OUTILS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  WIFI SCAN
    • Détecte réseaux Wi-Fi
    • Force de signal, sécurité WPA
    • Recommandations de sécurité

  FIREWALL
    • Génère règles firewall automatiques
    • Bloque menaces détectées
    • Export pour configuration

  PROXY
    • Configure proxy/VPN
    • Scan à travers proxy
    • Test de contournement

  ⏱ SCHEDULE
    • Planifie scans automatiques
    • Rapports programmés
    • Alertes périodiques

  PROCESS
    • Analyse processus actifs
    • Détecte malware actif
    • Arbre de dépendances

  SLACK
    • Notifications Slack intégrées
    • Alertes temps réel
    • Rapports automatiques

9⃣ ONGLET: PARAMÈTRES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Paramètres visuels et généraux de l'application

ONGLET: AVANCÉ (FONCTIONNALITÉS)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  GRAPHIQUES TEMPS RÉEL → Visualisation dynamique des données
  DASHBOARD 3D → Analyse 3D interactive
  CARTE RÉSEAU → Topologie réseau visuelle
  MONITORING 24/7 → Surveillance continue
  MODE STEALTH → Scans furtifs invisibles
  DÉTECTION ΔCHANGES → Anomalies réseau
  COMPARAISON SCANS → Évolution temporelle
  ⏮ REPLAY SCANS → Rejouer analyses antérieures
  SCREENSHOT → Capture écran d'évidences
  NOTIFICATIONS WIN → Alertes Windows pop-up
  SONS ALERTES → Signaux sonores
  CONFIG EMAIL → Rapports automatiques email
  HONEYPOT++ → Pièges avancés
  SANDBOX → Environnement isolé
  THREAT INTEL → Renseignement menaces
  FORENSICS → Enquête complète digitale
"""
        text.insert("1.0", content)
        text.config(state="disabled")

    def _create_help_tab_tutorials(self, tab):
        """Tab 3: Tutoriels par cas d'usage"""
        text = self._create_help_scrollframe(tab)
        
        content = """
╔════════════════════════════════════════════════════════════════════════════╗
║ TUTORIELS - CAS D'USAGE COURANTS ║
╚════════════════════════════════════════════════════════════════════════════╝

CAS 1: JE VIENS DE PRENDRE MES FONCTIONS (IT/SOC)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OBJECTIF: Créer une baseline de sécurité de mon réseau

Étapes:
  1. Cliquez AUTO-LOCATE pour identifier votre réseau
  2. Cliquez SCAN COMPLET pour audit complet initial
  3. Attendre 10-30 minutes selon taille réseau
  4. Cliquez EXPORT pour générer rapport PDF
  5. Conservez ce rapport comme "baseline"
  6. Réseau et renseignement → Changements depuis le dernier scan

CAS 2: JE SOUPÇONNE UNE INTRUSION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OBJECTIF: Vérifier si quelqu'un a accès non autorisé

Étapes:
  1. Analyses → Portes dérobées (cherche les accès cachés)
  2. Analyses → Attaques par force brute
  3. Analyses → Mécanismes de persistance
  4. Réseau et renseignement → Géolocalisation
  5. Analyses → Analyse forensique
  6. Exportez rapport pour incident response

CAS 3: AUDIT DE CONFORMITÉ (PCI-DSS, ISO 27001)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OBJECTIF: Générer documentation pour auditeur externe

Étapes:
  1. Analyses → Scan complet (couverture exhaustive)
  2. Analyses → SSL / TLS (certificats et chiffrement)
  3. Rapports et défense → Règles du pare-feu
  4. Analyses → Attaques par force brute
  5. Rapports et défense → Rapport HTML
  6. Générez PDF et Excel pour auditeur

CAS 4: INCIDENT RESPONSE TEMPS RÉEL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OBJECTIF: Réagir rapidement à une menace détectée

Étapes:
  1. Rapports et défense → Surveillance continue
  2. Paramètres → Notifications
  3. Choisir le scan adapté à la menace dans l'onglet Analyses
  4. Rapports et défense → Capture d'écran (conserver une trace)
  5. Rapports et défense → Historique des scans
  6. Lancez FORENSICS pour analyse approfondie

CAS 5: TEST D'INTRUSION AUTORISÉ (PENTEST)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OBJECTIF: Audit de sécurité complet avec tentatives d'exploitation

Étapes:
  1. AUTORISATIONS ÉCRITES REQUISES avant de démarrer!
  2. Analyses → Exploits connus
  3. Analyses → Portes dérobées
  4. Analyses → Exploits avancés
  5. Rapports et défense → Leurre réseau
  6. Générez rapport d'exploitation avec recommandations

CAS 6: SURVEILLANCE 24/7 AUTOMATISÉE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OBJECTIF: Monitoring continu sans intervention humaine

Étapes:
  1. Rapports et défense → Surveillance continue
  2. Paramètres → Planifier des scans
  3. Paramètres → Notifications
  4. Paramètres → Configurer l'e-mail
  5. Onglet SLACK (notifications Slack temps réel)
  6. Le système tourne automatiquement!

CAS 7: VÉRIFICATION CERTIFICATS SSL EXPIRÉS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OBJECTIF: S'assurer que les certificats ne vont pas expirer

Étapes:
  1. Analyses → SSL / TLS (audit des certificats)
  2. Analyses → Chaîne de certificats
  3. Consultez log pour dates d'expiration
  4. Rapports et défense → Exporter (PDF, Excel, JSON)
  5. Configurez alertes mensuelles (SCHEDULE)

RESSOURCES SUPPLÉMENTAIRES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Guide installation: GUIDE_INSTALLATION_RAPIDE.txt
  Fichiers README: Consultez fichiers .md dans dossier
"""
        text.insert("1.0", content)
        text.config(state="disabled")

    def _create_help_tab_settings(self, tab):
        """Tab 4: Paramètres avancés"""
        text = self._create_help_scrollframe(tab)
        
        content = """
╔════════════════════════════════════════════════════════════════════════════╗
║ PARAMÈTRES AVANCÉS & CONFIGURATION ║
╚════════════════════════════════════════════════════════════════════════════╝

PARAMÈTRES NMAP
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Fichier: nmap_options.conf

-sV (détection version)
  • Identifie les versions de services
  • Utile pour vulnérabilités ciblées
  • Peut être plus lent

-sC (scripts nmap)
  • Exécute scripts de détection
  • Découvertes avancées
  • Ralentit le scan

-O (détection OS)
  • Devine le système d'exploitation cible
  • Résultats approximatifs
  • Très intrusif

--aggressive
  • Scans agressifs pour résultats rapides
  • Peut déclencher alertes IDS
  • A éviter en prod

--timing
  • Paranoid (T0), Sneaky (T1), Polite (T2)
  • Normal (T3), Aggressive (T4), Insane (T5)
  • Plus faible = plus furtif

CLÉS API
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Pour intégrations avancées:

SHODAN_API_KEY
  • Obtenir sur: https://www.shodan.io
  • Gratuit avec limitation
  • Premium pour usage intensif

VIRUSTOTAL_API_KEY
  • Obtenir sur: https://www.virustotal.com
  • Clé gratuite disponible
  • Gratuit avec limitation (4 requêtes/min)

RAPID7_API_KEY
  • Obtenir sur: https://www.rapid7.com
  • Nécessite compte professionnel
  • Premium payant

EMAIL CONFIGURATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Pour rapports automatiques par email:

SMTP Server: smtp.gmail.com (pour Gmail)
SMTP Port: 587 (TLS) ou 465 (SSL)
Sender Email: votre_email@gmail.com
App Password: Mot de passe d'application Google
Recipients: email1@company.com, email2@company.com

Note: Pour Gmail, activez "App Passwords" dans Sécurité du compte

PROXY CONFIGURATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Pour scan via proxy:

Proxy Type: HTTP / SOCKS5
Proxy Host: 192.168.1.254:8080
Username/Pass: Authentification optionnelle
Test Proxy: Bouton pour valider connexion

WEBHOOK CONFIGURATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Pour intégration avec systèmes externes:

Webhook URL: https://api.example.com/webhook
Webhook Type: JSON / XML
Trigger Events: Menace détectée, Scan terminé, Alerte

SLACK INTEGRATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Pour notifications Slack temps réel:

Slack Webhook: https://hooks.slack.com/services/YOUR/WEBHOOK
Slack Channel: #security-alerts
Ping On: @channel ou @ici pour mentions

SCHEDULING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Planification des scans automatiques:

Scan Rapide: Chaque jour à 02:00 (heures creuses)
Scan Complet: Samedi 03:00
Scan CVE: Chaque dimanche 05:00
Scan Backdoor: Chaque 6h

THRESHOLDS D'ALERTE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Seuils pour alertes automatiques:

Port Opencount > X: Alerte si plus de X ports ouverts
Service Detect > Y: Alerte si Y services détectés
CVE Severity >= 8.0: CVSS score critique
Backdoor Ports: Alerte IMMÉDIATE
Suspicious Process: Alerte IMMÉDIATE

PERFORMANCE OPTIMIZATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Pour réseau large:

Thread Count: Nombre de scans parallèles (défaut: 5)
Timeout per Host: Secondes avant abandon (défaut: 30)
Batch Size: Nombre d'hôtes par batch (défaut: 254)

LOGGING CONFIGURATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Verbosité des logs:

Level: QUIET (peu), INFO (std), VERBOSE (détaillé), DEBUG (très détaillé)
Rotation: Tous les X MB
Retention: Conserver X jours de logs
Archive: Compresse logs anciens en ZIP
"""
        text.insert("1.0", content)
        text.config(state="disabled")

    def _create_help_tab_faq(self, tab):
        """Tab 5: FAQ & Troubleshooting"""
        text = self._create_help_scrollframe(tab)
        
        content = """
╔════════════════════════════════════════════════════════════════════════════╗
║ QUESTIONS FRÉQUENTES & TROUBLESHOOTING ║
╚════════════════════════════════════════════════════════════════════════════╝

Q1: L'application ne démarre pas?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
R: Vérifiez:
   Python 3.8+ installé? → py --version
   Dépendances? → pip install -r requirements.txt
   Nmap? → nmap -V
   Permissions admin? → Relancez en admin
  → Voir GUIDE_INSTALLATION_RAPIDE.txt pour détails

Q2: Le scan est très lent?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
R: C'est normal et dépend de:
  • Réseau large → utilisez SCAN RAPIDE d'abord
  • Pare-feu strict → certains ports refusés
  • Nmap lent → utilisez timing agressif
  Solution : relancer avec un scan complet, plus lent mais plus profond

Q3: Aucune cible détectée?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
R: Vérifiez:
   Cible en ligne? → ping 192.168.1.1
   Firewall bloque? → exception dans firewall Windows
   Réseau correct? → Cliquez AUTO-LOCATE
   Nmap installé? → Redémarrez application

Q4: Erreur "Nmap not found"?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
R: Nmap n'est pas installé ou pas dans PATH
  Solution:
  1. Télécharger: https://nmap.org/download.html
  2. Installer version Windows (avec Npcap)
  3. Ajouter à PATH: "C:\\Program Files (x86)\\Nmap"
  4. Redémarrer application

Q5: L'export PDF est vide?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
R: Plusieurs causes possibles:
   Instal reportlab: pip install reportlab
   Aucun résultat de scan → lancer scan d'abord
   Redémarrer application
  → Format JSON ou CSV fonctionne mieux

Q6: Permissions insuffisantes?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
R: L'application a besoin d'accès admin pour:
  • Scannes réseau bas niveau
  • Détection Nmap complète
  • Capture de paquets
  Solution: Clic droit → "Exécuter en tant que..."

Q7: Comment augmenter la sécurité du scan?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
R: Plusieurs approches:
  • Rapports et défense → Mode discret (scan lent, moins visible)
  • Le mode discret impose déjà un rythme lent (nmap -T1)
  • La configuration d'un proxy n'est pas implémentée
  • L'anonymisation par proxy n'est pas implémentée

Q8: Comment ajouter clés API?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
R: Créer fichier config_api.txt avec:
  SHODAN_API_KEY=your_key_here
  VIRUSTOTAL_API_KEY=your_key_here
  RAPID7_API_KEY=your_key_here
  Placer dans le dossier application

Q9: Intégration avec Slack?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
R: Étapes:
  1. Créer Webhook dans Slack: https://api.slack.com/apps
  2. Copier URL Webhook
  3. Paramètres → Slack
  4. Coller URL et configurer canal
  5. Tester connexion → Alertes activées!

Q10: Rapports email automatiques?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
R: Configuration:
  1. Paramètres → Configurer l'e-mail
  2. Serveur: smtp.gmail.com (port 587)
  3. Email: votre@gmail.com
  4. Mot de passe APP (pas votre mot de passe)
  5. Destinataires: email1@company.com
  6. Planifier dans SCHEDULE

Q11: Créer scan personnalisé?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
R: Éditer fichier scan_custom.conf avec paramètres Nmap désirés
  Exemples:
  -sV --script ssl-enum-ciphers (scan SSL custom)
  -O --script smb-os-discovery (découverte SMB)
  Puis redémarrer application

Q12: Erreur "Unicode"?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
R: Erreur d'encodage caractères Windows
  Solution: 
  1. Ajouter à début du code: # -*- coding: utf-8 -*-
  2. Relancer application
  3. Vérifier encoding console Windows (défaut UTF-8)

Q13: Comment monitorer 24/7?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
R: Config complète:
  1. Rapports et défense → Surveillance continue
  2. Paramètres → Planifier des scans
  3. Paramètres → Notifications (alertes Windows)
  4. Onglet SLACK (notifications Slack)
  5. Laisser app ouverte (ou en service Windows)

RESSOURCES D'AIDE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  • Lisez GUIDE_INSTALLATION_RAPIDE.txt
  • Vérifiez fichiers README.md
  • Allez voir logs: network_audit_logs.txt
"""
        text.insert("1.0", content)
        text.config(state="disabled")

    def _create_help_tab_threats(self, tab):
        """Tab 5b: Menaces actuelles et détection"""
        text = self._create_help_scrollframe(tab)
        
        content = """
╔════════════════════════════════════════════════════════════════════════════╗
║ MENACES ACTUELLES & DÉTECTION () ║
╚════════════════════════════════════════════════════════════════════════════╝

MENACES PRIORITAIRES 2024-2026
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1⃣ RANSOMWARE AVANCÉ
  Variantes actives:
    • LockBit 3.0+ (Double extorsion)
    • BlackCat/ALPHV (Exploitation zero-day)
    • Cl0p/Clop (Exploitation MOVEit)

  Détection par SIPA :
    Analyses → Mécanismes de persistance
    Analyses → Analyse forensique
    Analyses → Scan CVE (vulnérabilités connues)
    Analyses → Détection d'anomalies

2⃣ ZERO-DAY & EXPLOITS NON PATCHÉS
  Cibles principales:
    • Windows Server (CVE-2024-xxxx)
    • Citrix / VMware
    • Kubernetes clusters

  Détection par SIPA :
    Analyses → Scan CVE
    Analyses → Exploits connus
    Réseau et renseignement → Shodan (nécessite une clé API)
    Réseau et renseignement → VirusTotal (nécessite une clé API)

3⃣ SUPPLY CHAIN ATTACKS
  Vecteurs compromission:
    • Dépendances npm/pip malveillantes
    • Packages Docker compromis
    • Certificats SSL détournés

  Détection par SIPA :
    Analyses → SSL / TLS
    Rapports et défense → Processus en cours
    Analyses → Analyse forensique
    Réseau et renseignement → Analyse du trafic

4⃣ ATTAQUES PAR FORCE BRUTE & CREDENTIAL STUFFING
  Protocoles ciblés:
    • RDP (Port 3389) - Accès serveur
    • SSH (Port 22) - Accès Linux
    • FTP (Port 21) - Transfert fichiers

  Détection par SIPA :
    Analyses → Attaques par force brute
    Analyses → Secrets dans vos fichiers
    Analyses → Audit des services
    Paramètres → Configurer l'e-mail (destinataire des alertes)

5⃣ BACKDOORS & PERSISTENCE
  Mécanismes courants:
    • Webshells (ASP.NET, PHP)
    • Scheduled tasks malveillantes
    • Registry run keys compromises

  Détection par SIPA :
    Analyses → Portes dérobées
    Analyses → Rootkits
    Rapports et défense → Processus en cours
    Analyses → Analyse forensique

6⃣ APT & THREAT ACTORS ORGANISÉS
  Groupes principaux:
    • APT28 / Fancy Bear (Russie)
    • APT29 / Cozy Bear (Russie)
    • Lazarus (Corée du Nord)

  Détection par SIPA :
    Réseau et renseignement → Renseignement public (OSINT)
    Onglet THREAT INTEL (profils acteurs)
    Onglet GEO-IP (détecte sources anormales)
    Onglet MODE STEALTH (scan discret)

ACTIONS IMMÉDIATES (24H)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Si menace détectée:
  1. Cliquez AUTO-LOCATE
  2. Lancez SCAN COMPLET
  3. Allez onglet PRO → FORENSICS
  4. Exportez rapport PDF
  5. Alertez équipe sécurité
  6. Isolez système si critique

SCAN RECOMMANDÉ TOUS LES JOURS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  02:00 → SCAN RAPIDE (détecte hôtes actifs)
  06:00 → BACKDOOR DETECT (cherche accès arrière)
  18:00 → BRUTE FORCE DETECT (tentatives d'accès)
  22:00 → NETWORK HEALTH (santé générale)

Configuration automatique:
  → Paramètres → Planifier des scans
  → Rapports et défense → Surveillance continue
  → Paramètres → Notifications
"""
        text.insert("1.0", content)
        text.config(state="disabled")

    def _create_help_tab_info(self, tab):
        """Tab 6: Informations générales"""
        text = self._create_help_scrollframe(tab)
        
        content = f"""
╔════════════════════════════════════════════════════════════════════════════╗
║ ℹ INFORMATIONS & STATISTIQUES ║
╚════════════════════════════════════════════════════════════════════════════╝

APPLICATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Nom:{APP_NAME}
  Version:            {APP_VERSION}
  Statut: Projet personnel, en cours de fiabilisation
  Tests: python tests/run_all.py
  Licence: MIT (voir le fichier LICENSE)

TECHNOLOGIES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Langage: Python 3.8+
  Interface: Tkinter + TTK
  Scanning: Nmap (reconnaissance réseau)
  Graphiques: Matplotlib, Plotly
  Notifications: win10toast (Windows Toast)
  Email: smtplib (SMTP)

STATISTIQUES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Lignes de code: ~13 450 (sipa.py + le paquet sipa_core)
  Fonctions: ~416
  Onglets interface: 5 (Analyses, Réseau, Rapports, Outils, Paramètres)
  Onglets d'aide: 7
  Boutons d'action: ~94
  Tests automatisés: 186 vérifications (python tests/run_all.py)
  Langues: contrat de licence traduit en 5 langues ;
                      l'interface elle-même est en français

SÉCURITÉ
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Protocoles: HTTPS, TLS 1.2+
  Authentification: clés API pour SHODAN/VirusTotal, jeton aléatoire
                      pour l'API REST locale
  Chiffrement: AES-256 (configuration)
  Hash: SHA-256
  Conformité: GDPR, PCI-DSS, ISO 27001

DÉPENDANCES PRINCIPALES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  python-nmap Scan Nmap programmatique
  requests Requêtes HTTP/API
  matplotlib Graphiques 2D
  plotly Visualisations interactives 3D
  win10toast Notifications Windows
  pillow Traitement images
  reportlab Génération PDF
  openpyxl Export Excel

API & INTÉGRATIONS EXTERNES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Fonctionnent avec une clé API :
    SHODAN recherche de dispositifs exposés sur Internet
    VirusTotal réputation d'une IP ou d'un fichier

  Fonctionnent sans clé :
    Slack / Discord notifications par webhook
    Email (SMTP) envoi des rapports
    API REST locale contrôle à distance (127.0.0.1, jeton obligatoire)
    OpenVAS nécessite un serveur Greenbone joignable

  NON implémentées — les boutons l'annoncent quand on les actionne :
    Rapid7, Tenable Nessus, Qualys VMDR, Microsoft Defender

PERFORMANCE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Ordres de grandeur observés sur un poste de développement, pas des
  mesures certifiées :
    Scan rapide (-F) quelques secondes à une minute
    Scan complet (-sV -O) plusieurs minutes, selon la taille du réseau
    Mode furtif (-T1) beaucoup plus lent, c'est le principe
    Export PDF / Excel quelques secondes

CE QUE FAIT SIPA
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Scans Nmap réels : rapide, complet, CVE, portes dérobées, découverte
  Corrélation des services détectés avec une base CVE locale (NVD)
  Analyse DNS complète : résolution, DNSBL, DNSSEC, transfert de zone
  Chaîne de certificats TLS réellement récupérée et vérifiée
  Détection de dérive entre deux scans, avec alerte email/Slack/Discord
  Inventaire des appareils : fabricant (OUI), OS, première/dernière vue
  Analyse du trafic local (sockets bruts, Scapy ou netstat)
  Audit système, processus, persistance, rootkits, intégrité ARP
  Recherche de secrets dans vos propres fichiers locaux
  Détection d'anomalies par Isolation Forest (scikit-learn)
  Rapports HTML, PDF, Excel, JSON, CSV + historique et comparaison
  Planification de scans (APScheduler) et mode ligne de commande
  Secrets chiffrés par la DPAPI Windows
  5 onglets d'interface, 7 onglets d'aide

CE QUI N'EST PAS FAIT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Le thème clair : une seule palette (sombre) existe dans le code
  La traduction de l'interface : seul le contrat de licence est
    traduit en 5 langues ; les libellés des boutons restent en français
  Mode Agent, Configuration Proxy, Sandbox
  Heatmap des menaces, Timeline des événements
  Les boutons concernés le disent explicitement plutôt que de faire
  semblant : c'est la règle du projet.

HISTORIQUE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  v7.0 Base CVE locale, détection de dérive, mode ligne de commande,
        chiffrement DPAPI, annulation de scan, découpage en modules,
        suite de tests automatisés, suppression des résultats fictifs.
  1.x – 6.x Développement initial sur un fichier unique : interface
        Tkinter, scans réseau et DNS, audit système, exports.
  Le détail complet est dans CHANGELOG.md et dans l'historique git.

SYSTÈME REQUIS MINIMUM
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  OS: Windows 10/11 (64-bit recommandé)
  Python: 3.8+ (3.11 recommandé)
  RAM: 2 GB minimum (4 GB recommandé)
  Disque: 500 MB pour installation
  Network: Connexion Ethernet ou Wi-Fi
  Nmap: 5.51+ (installé via programme)
  Droits: Administrateur pour scans bas niveau

SUPPORT & LICENCE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Licence: MIT (voir le fichier LICENSE)
  Usage: Gratuit pour audit sécurité autorisé
  Source: Code source disponible (licence MIT)

CONFORMITÉ LÉGALE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  AVERTISSEMENT LÉGAL:

  Cette application ne doit être utilisée QUE pour:
  • Audit de VOTRE PROPRE réseau/système
  • Tests de pénétration AUTORISÉS par écrit
  • Recherche sécurité en environnement contrôlé

  L'utilisation non autorisée est ILLÉGALE dans TOUS les pays.

  Créateurs déclinent toute responsabilité pour:
  • Accès non autorisés
  • Dommages aux systèmes tiers
  • Utilisation malveillante

  VOUS êtes responsable de votre utilisation de cet outil!

CE QUE SIPA NE FAIT PAS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Choix assumés de conception — ces fonctions ne sont pas bridées, elles
n'existent pas et n'existeront pas :

  • aucune exploitation active de vulnérabilité (détection uniquement)
  • aucune extraction de données sur un système tiers
  • aucun brute force d'authentification (SIPA le détecte, ne le pratique pas)
  • aucun contournement d'authentification ou de pare-feu
  • aucune implantation de porte dérobée
  • aucun man-in-the-middle, aucune interception du trafic d'un tiers
  • aucune modification ni suppression de données sur la cible

FONCTIONS NON IMPLÉMENTÉES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Les boutons correspondants le disent explicitement quand on les actionne :

  • Tenable Nessus, Qualys VMDR, Microsoft Defender : aucune intégration
  • Mode Agent, Configuration Proxy, Sandbox : non implémentés
  • Thème clair et changement de langue de l'interface : voir ci-dessous

NÉCESSITENT UNE CLÉ API
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  • SHODAN → compte requis (offre gratuite très limitée)
  • VirusTotal → clé gratuite : 4 requêtes/minute
  • OpenVAS → serveur Greenbone joignable + python-gvm
Sans clé, aucun résultat n'est produit : SIPA ne fabrique pas de données
de démonstration pour combler un vide.

DÉPENDANCES EXTERNES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  • Nmap → indispensable aux scans réseau
  • Docker → uniquement pour OpenVAS
  • Droits administrateur → détection d'OS (-O) et fragmentation IP (-f)
    du mode furtif. Sans ces droits, SIPA fonctionne et le signale.

USAGE LÉGAL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AUTORISÉ : auditer votre propre infrastructure • test d'intrusion avec
autorisation écrite • recherche en environnement contrôlé • formation.

INTERDIT : scanner un système tiers sans autorisation écrite • extraire
des données personnelles • perturber un service • toute autre violation
légale. Scanner un réseau sans autorisation est illégal dans la plupart
des pays. Vous êtes seul responsable de votre usage de cet outil.

Licence MIT — code ouvert, aucune obfuscation, aucune offre commerciale.
"""
        text.insert("1.0", content)
        text.config(state="disabled")

    def _export_help_to_file(self):
        """Exporte le contenu REEL de tous les onglets d'aide.

        Cette methode ecrivait un en-tete suivi de la seule phrase
        "Documentation aide systeme - complet", puis journalisait
        "Aide exportee avec succes" : le fichier ne contenait aucune aide.
        Elle recopie desormais le texte affiche dans chaque onglet.
        """
        try:
            sections = list(zip(getattr(self, "_help_tab_titles", []),
                                getattr(self, "_help_text_widgets", [])))
            if not sections:
                messagebox.showwarning(
                    "Export impossible",
                    "Ouvrez la fenetre d'aide avant d'exporter son contenu.")
                return

            filepath = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Fichier texte", "*.txt"), ("Tous les fichiers", "*.*")],
                initialfile=f"{APP_NAME}_aide_{APP_VERSION}.txt")
            if not filepath:
                return

            largeur = 80
            total = 0
            with open(filepath, "w", encoding="utf-8") as fichier:
                fichier.write("=" * largeur + "\n")
                fichier.write(f"{APP_NAME} {APP_VERSION} - AIDE COMPLETE\n")
                fichier.write("=" * largeur + "\n\n")
                fichier.write("Exporte le "
                              + datetime.now().strftime("%d/%m/%Y a %H:%M:%S")
                              + "\n")
                fichier.write(f"{len(sections)} sections\n\n")

                for titre, widget in sections:
                    contenu = widget.get("1.0", "end").rstrip()
                    total += len(contenu)
                    fichier.write("\n" + "=" * largeur + "\n")
                    fichier.write(f"  {titre}\n")
                    fichier.write("=" * largeur + "\n")
                    fichier.write(contenu + "\n")

            self.log(f"Aide exportee : {len(sections)} sections, "
                     f"{total} caracteres -> {filepath}", tag="ok")
        except Exception as exc:
            messagebox.showerror("Erreur", f"Erreur export : {exc}")

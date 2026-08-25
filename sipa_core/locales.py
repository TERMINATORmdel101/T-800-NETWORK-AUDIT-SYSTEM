"""Donnees de localisation de SIPA : traductions d'interface, langues,
texte de licence et descriptions des boutons.

Extrait de sipa.py sans modification de contenu (phase 3 : refonte modulaire).
Ce module ne contient que des donnees -- aucune logique, aucune dependance.
"""

TRANSLATIONS = {
    'FR': {
        'title': 'AUDIT RÉSEAU',
        'target': 'CIBLE',
        'auto_locate': 'AUTO-LOCALISER',
        'scan_fast': 'SCAN RAPIDE',
        'scan_full': 'SCAN COMPLET',
        'scan_vuln': 'SCAN VULN (CVE)',
        'detect_backdoor': 'DÉTECTER BACKDOOR',
        'network_health': 'SANTÉ RÉSEAU',
        'detect_exploit': 'DÉTECTER EXPLOIT',
        'persistence': 'SCAN PERSISTENCE',
        'forensic': 'FORENSIC DEEP',
        'advanced_exploits': 'EXPLOITS AVANCÉS',
        'network_graph': 'GRAPHIQUE RÉSEAU',
        'shodan': 'SCAN SHODAN',
        'traffic': 'ANALYSE TRAFIC',
        'export': 'EXPORT RAPPORTS',
        'brute_force': 'BRUTE FORCE DET.',
        'geolocation': 'GÉOLOCALISATION',
        'ssl': 'SCAN SSL/TLS',
        'honeypot': 'HONEYPOT PIÈGE',
        'firewall': 'RÈGLES FIREWALL',
        'virustotal': 'VIRUSTOTAL CHECK',
        'credentials': 'SECRETS LOCAUX',
        'dashboard': 'TABLEAU BORD',
        'help': 'AIDE',
        'dark_mode': 'MODE SOMBRE',
        'light_mode': 'MODE CLAIR',
        'cve_advanced': 'CVE AVANCÉ',
        'dns_analysis': 'ANALYSE DNS',
        'rootkit_detect': 'DÉTECT. ROOTKIT',
        'wifi_scan': 'SCAN WIFI',
        'heatmap': 'HEATMAP MENACES',
        'timeline': 'TIMELINE ÉVÉNEMENTS',
        'custom_report': 'RAPPORT PERSO',
        'rapid7': 'RAPID7 SYNC',
        'tenable': 'TENABLE NESSUS',
        'qualys': 'QUALYS VMDR',
        'defender': 'DEFENDER SYNC',
        'schedule_scan': 'PLANNING SCANS',
        'multi_target': 'MULTI-CIBLE PAR.',
        'api_rest': 'API REST SERVER',
        'agent_mode': 'MODE AGENT',
        'broadcast': 'SCAN BROADCAST',
        'osint': 'OSINT RESEARCH',
        'proxy_config': 'CONFIG PROXY',
        'logs_viewer': 'VISIONNEUSE LOGS',
        'anomaly_ai': 'ANOMALIES IA',
        'ssl_chain': 'CHAÎNE SSL COMPLÈTE',
        'process_analyze': 'ANALYSE PROCESSUS',
        'slack_notify': 'NOTIF SLACK',
        'webhook': 'WEBHOOK INTÉGR.',
    },
    'EN': {
        'title': 'NETWORK AUDIT',
        'target': 'TARGET',
        'auto_locate': 'AUTO-LOCATE',
        'scan_fast': 'FAST SCAN',
        'scan_full': 'FULL SCAN',
        'scan_vuln': 'VULN SCAN (CVE)',
        'detect_backdoor': 'DETECT BACKDOOR',
        'network_health': 'NETWORK HEALTH',
        'detect_exploit': 'DETECT EXPLOIT',
        'persistence': 'PERSISTENCE SCAN',
        'forensic': 'FORENSIC DEEP',
        'advanced_exploits': 'ADVANCED EXPLOITS',
        'network_graph': 'NETWORK GRAPH',
        'shodan': 'SHODAN SCAN',
        'traffic': 'TRAFFIC ANALYSIS',
        'export': 'EXPORT REPORTS',
        'brute_force': 'BRUTE FORCE DET.',
        'geolocation': 'IP GEOLOCATION',
        'ssl': 'SSL/TLS SCAN',
        'honeypot': 'HONEYPOT TRAP',
        'firewall': 'FIREWALL RULES',
        'virustotal': 'VIRUSTOTAL CHECK',
        'credentials': 'LOCAL SECRETS',
        'dashboard': 'LIVE DASHBOARD',
        'help': 'HELP',
        'dark_mode': 'DARK MODE',
        'light_mode': 'LIGHT MODE',
        'cve_advanced': 'ADVANCED CVE',
        'dns_analysis': 'DNS ANALYSIS',
        'rootkit_detect': 'ROOTKIT DETECT',
        'wifi_scan': 'WIFI SCAN',
        'heatmap': 'THREAT HEATMAP',
        'timeline': 'EVENT TIMELINE',
        'custom_report': 'CUSTOM REPORT',
        'rapid7': 'RAPID7 SYNC',
        'tenable': 'TENABLE NESSUS',
        'qualys': 'QUALYS VMDR',
        'defender': 'DEFENDER SYNC',
        'schedule_scan': 'SCHEDULE SCANS',
        'multi_target': 'MULTI-TARGET PAR.',
        'api_rest': 'API REST SERVER',
        'agent_mode': 'AGENT MODE',
        'broadcast': 'BROADCAST SCAN',
        'osint': 'OSINT RESEARCH',
        'proxy_config': 'PROXY CONFIG',
        'logs_viewer': 'LOGS VIEWER',
        'anomaly_ai': 'AI ANOMALIES',
        'ssl_chain': 'SSL CHAIN FULL',
        'process_analyze': 'PROCESS ANALYSIS',
        'slack_notify': 'SLACK NOTIFY',
        'webhook': 'WEBHOOK INTEG.',
    },
    'ES': {
        'title': 'AUDITORÍA RED',
        'target': 'OBJETIVO',
        'auto_locate': 'AUTO-LOCALIZAR',
        'scan_fast': 'ESCANEO RÁPIDO',
        'scan_full': 'ESCANEO COMPLETO',
        'scan_vuln': 'ESCANEO VULN (CVE)',
        'detect_backdoor': 'DETECTAR BACKDOOR',
        'network_health': 'SALUD RED',
        'detect_exploit': 'DETECTAR EXPLOIT',
        'persistence': 'ESCANEO PERSISTENCIA',
        'forensic': 'FORENSE PROFUNDO',
        'advanced_exploits': 'EXPLOITS AVANZADOS',
        'network_graph': 'GRÁFICO RED',
        'shodan': 'ESCANEO SHODAN',
        'traffic': 'ANÁLISIS TRÁFICO',
        'export': 'EXPORTAR REPORTES',
        'brute_force': 'DET. FUERZA BRUTA',
        'geolocation': 'GEOLOCALIZACIÓN IP',
        'ssl': 'ESCANEO SSL/TLS',
        'honeypot': 'TRAMPA HONEYPOT',
        'firewall': 'REGLAS FIREWALL',
        'virustotal': 'VERIFICAR VIRUSTOTAL',
        'credentials': 'SECRETOS LOCALES',
        'dashboard': 'PANEL EN VIVO',
        'help': 'AYUDA',
        'dark_mode': 'MODO OSCURO',
        'light_mode': 'MODO CLARO',
        'cve_advanced': 'CVE AVANZADO',
        'dns_analysis': 'ANÁLISIS DNS',
        'rootkit_detect': 'DET. ROOTKIT',
        'wifi_scan': 'ESCANEO WIFI',
        'heatmap': 'MAPA DE CALOR',
        'timeline': 'LÍNEA DE TIEMPO',
        'custom_report': 'REPORTE CUSTOM',
        'rapid7': 'SINCRONIZACIÓN R7',
        'tenable': 'NESSUS TENABLE',
        'qualys': 'QUALYS VMDR',
        'defender': 'DEFENDER SINCR.',
        'schedule_scan': 'PROGRAMAR ESCANEOS',
        'multi_target': 'MÚLTIPLES OBJETIVOS',
        'api_rest': 'SERVIDOR API REST',
        'agent_mode': 'MODO AGENTE',
        'broadcast': 'ESCANEO BROADCAST',
        'osint': 'INVESTIGACIÓN OSINT',
        'proxy_config': 'CONFIG PROXY',
        'logs_viewer': 'VISOR DE REGISTROS',
        'anomaly_ai': 'ANOMALÍAS IA',
        'ssl_chain': 'CADENA SSL COMPLETA',
        'process_analyze': 'ANÁLISIS PROCESOS',
        'slack_notify': 'NOTIF SLACK',
        'webhook': 'INTEGRACIÓN WEBHOOK',
    },
    'DE': {
        'title': 'NETZWERKPRÜFUNG',
        'target': 'ZIEL',
        'auto_locate': 'AUTO-LOKALISIEREN',
        'scan_fast': 'SCHNELLSCAN',
        'scan_full': 'VOLLSTÄNDIGER SCAN',
        'scan_vuln': 'SICHERHEITSLÜCKEN-SCAN',
        'detect_backdoor': 'BACKDOOR ERKENNEN',
        'network_health': 'NETZWERKZUSTAND',
        'detect_exploit': 'EXPLOIT ERKENNEN',
        'persistence': 'PERSISTENZ-SCAN',
        'forensic': 'FORENSISCHE ANALYSE',
        'advanced_exploits': 'FORTGESCHRITTENE EXPLOITS',
        'network_graph': 'NETZWERKGRAF',
        'shodan': 'SHODAN-SCAN',
        'traffic': 'VERKEHRSANALYSE',
        'export': 'BERICHTE EXPORTIEREN',
        'brute_force': 'BRUTE-FORCE-ERKENNUNG',
        'geolocation': 'IP-GEOLOKALISIERUNG',
        'ssl': 'SSL/TLS-SCAN',
        'honeypot': 'HONEYPOT-FALLE',
        'firewall': 'FIREWALL-REGELN',
        'virustotal': 'VIRUSTOTAL-ÜBERPRÜFUNG',
        'credentials': 'LOKALE GEHEIMNISSE',
        'dashboard': 'LIVE-DASHBOARD',
        'help': 'HILFE',
        'dark_mode': 'DUNKELMODUS',
        'light_mode': 'HELLMODUS',
        'cve_advanced': 'FORTGESCHRITTENE CVE',
        'dns_analysis': 'DNS-ANALYSE',
        'rootkit_detect': 'ROOTKIT-ERKENNUNG',
        'wifi_scan': 'WLAN-SCAN',
        'heatmap': 'BEDROHUNGSHEATMAP',
        'timeline': 'EREIGNIS-ZEITLEISTE',
        'custom_report': 'BENUTZERDEFINIERTER BERICHT',
        'rapid7': 'RAPID7-SYNCHRONISIERUNG',
        'tenable': 'TENABLE NESSUS',
        'qualys': 'QUALYS VMDR',
        'defender': 'DEFENDER-SYNCHRONISIERUNG',
        'schedule_scan': 'SCANS PLANEN',
        'multi_target': 'MULTI-ZIEL PARALLEL',
        'api_rest': 'API REST-SERVER',
        'agent_mode': 'AGENTENMODUS',
        'broadcast': 'BROADCAST-SCAN',
        'osint': 'OSINT-FORSCHUNG',
        'proxy_config': 'PROXY-KONFIGURATION',
        'logs_viewer': 'PROTOKOLL-VIEWER',
        'anomaly_ai': 'KI-ANOMALIEN',
        'ssl_chain': 'VOLLSTÄNDIGE SSL-KETTE',
        'process_analyze': 'PROZESSANALYSE',
        'slack_notify': 'SLACK-BENACHRICHTIGUNG',
        'webhook': 'WEBHOOK-INTEGRATION',
        'license_accept': 'Ich akzeptiere die Lizenzvereinbarung',
        'license_decline': 'Ablehnen',
        'license_accept_btn': 'AKZEPTIEREN',
    },
    'IT': {
        'title': 'AUDIT RETE',
        'target': 'OBIETTIVO',
        'auto_locate': 'AUTO-LOCALIZZA',
        'scan_fast': 'SCANSIONE RAPIDA',
        'scan_full': 'SCANSIONE COMPLETA',
        'scan_vuln': 'SCANSIONE VULNERABILITÀ',
        'detect_backdoor': 'RILEVA BACKDOOR',
        'network_health': 'SALUTE RETE',
        'detect_exploit': 'RILEVA EXPLOIT',
        'persistence': 'SCANSIONE PERSISTENZA',
        'forensic': 'ANALISI FORENSE',
        'advanced_exploits': 'EXPLOIT AVANZATI',
        'network_graph': 'GRAFICO RETE',
        'shodan': 'SCANSIONE SHODAN',
        'traffic': 'ANALISI TRAFFICO',
        'export': 'ESPORTA REPORT',
        'brute_force': 'RILEVAMENTO BRUTE FORCE',
        'geolocation': 'GEOLOCALIZZAZIONE IP',
        'ssl': 'SCANSIONE SSL/TLS',
        'honeypot': 'TRAPPOLA HONEYPOT',
        'firewall': 'REGOLE FIREWALL',
        'virustotal': 'CONTROLLO VIRUSTOTAL',
        'credentials': 'SEGRETI LOCALI',
        'dashboard': 'DASHBOARD LIVE',
        'help': 'AIUTO',
        'dark_mode': 'MODALITÀ SCURA',
        'light_mode': 'MODALITÀ CHIARA',
        'cve_advanced': 'CVE AVANZATE',
        'dns_analysis': 'ANALISI DNS',
        'rootkit_detect': 'RILEVA ROOTKIT',
        'wifi_scan': 'SCANSIONE WIFI',
        'heatmap': 'MAPPA DI CALORE MINACCE',
        'timeline': 'CRONOLOGIA EVENTI',
        'custom_report': 'REPORT PERSONALIZZATO',
        'rapid7': 'SINCRONIZZAZIONE RAPID7',
        'tenable': 'TENABLE NESSUS',
        'qualys': 'QUALYS VMDR',
        'defender': 'DEFENDER SINCR.',
        'schedule_scan': 'PIANIFICA SCANSIONI',
        'multi_target': 'MULTI-TARGET PARALLELO',
        'api_rest': 'SERVER API REST',
        'agent_mode': 'MODALITÀ AGENTE',
        'broadcast': 'SCANSIONE BROADCAST',
        'osint': 'RICERCA OSINT',
        'proxy_config': 'CONFIG PROXY',
        'logs_viewer': 'VISUALIZZATORE REGISTRI',
        'anomaly_ai': 'ANOMALIE IA',
        'ssl_chain': 'CATENA SSL COMPLETA',
        'process_analyze': 'ANALISI PROCESSI',
        'slack_notify': 'NOTIFICA SLACK',
        'webhook': 'INTEGRAZIONE WEBHOOK',
        'license_accept': 'Accetto il contratto di licenza',
        'license_decline': 'Rifiuta',
        'license_accept_btn': 'ACCETTA',
    }
}

# Ajout des clés manquantes en FR et EN
for lang in ['FR', 'EN']:
    if 'license_accept' not in TRANSLATIONS[lang]:
        if lang == 'FR':
            TRANSLATIONS[lang]['license_accept'] = 'J\'accepte le contrat de licence'
            TRANSLATIONS[lang]['license_decline'] = 'Refuser'
            TRANSLATIONS[lang]['license_accept_btn'] = 'ACCEPTER'
        else:
            TRANSLATIONS[lang]['license_accept'] = 'I accept the license agreement'
            TRANSLATIONS[lang]['license_decline'] = 'Decline'
            TRANSLATIONS[lang]['license_accept_btn'] = 'ACCEPT'

# Mapping language codes <-> display names
LANGUAGES = {
    'FR': 'Français',
    'EN': 'English',
    'ES': 'Español',
    'DE': 'Deutsch',
    'IT': 'Italiano'
}

LICENSE_TEXT = {
    'FR': """
═══════════════════════════════════════════════════════════════════════════════
                   CONTRAT DE LICENCE ET CONDITIONS D'UTILISATION
                            SIPA — Audit réseau et sécurité
═══════════════════════════════════════════════════════════════════════════════

ACCEPTATION DE LA LICENCE

En utilisant ce logiciel, vous acceptez les conditions suivantes:

1. OBJET DU LOGICIEL
   • Ce logiciel est conçu EXCLUSIVEMENT pour tester les vulnérabilités réseau
   • Son utilisation doit respecter le cadre légal du pays actif
   • Ce logiciel n'est PAS conçu à des fins illégales ou malveillantes

2. RESPONSABILITÉ DE L'UTILISATEUR
   L'utilisateur qui utilise ce programme est ENTIÈREMENT RESPONSABLE:
   • De l'utilisation du logiciel
   • De la conformité légale de ses actions
   • De tout dommage causé par son utilisation
   • Du respect des lois nationales et internationales

3. RESPONSABILITÉ DU CRÉATEUR
   Le créateur du logiciel N'EST PAS RESPONSABLE:
   • De l'utilisation abusive du logiciel
   • De tout dommage causé par ce logiciel
   • De toute violation légale commise par l'utilisateur
   • De tout impact négatif sur des systèmes tiers

4. CONDITIONS D'UTILISATION LÉGALE
   UTILISATION AUTORISÉE:
   • Tests de sécurité sur VOS propres systèmes
   • Tests sur des systèmes avec permission écrite explicite du propriétaire
   • À titre éducatif et de recherche en cybersécurité
   • Pour améliorer votre sécurité réseau

   UTILISATION INTERDITE:
   • Accès non autorisé à des systèmes tiers
   • Tests de sécurité sans consentement explicite
   • Utilisation à des fins malveillantes ou criminelles
   • Violation des lois nationales sur la cybersécurité

5. RÉGLEMENTATION LÉGALE
   Le logiciel doit être utilisé en conformité avec:
   • Les lois nationales du pays d'utilisation
   • Les lois internationales applicables
   • Les politiques de sécurité de votre organisation
   • Les contrats d'engagement de niveau de service (SLA)

6. GARANTIES
   Ce logiciel est fourni "TEL QUEL" sans garantie d'aucune sorte:
   • Pas de garantie quant à sa pertinence
   • Pas de garantie quant à sa performance
   • Pas de garantie quant à l'absence de bugs
   • Pas de responsabilité en cas de perte de données

7. LIMITATION DE RESPONSABILITÉ
   En aucun cas le créateur ne sera responsable de:
   • Pertes de données
   • Interruption de service
   • Dommages indirects ou consécutifs
   • Toute autre cause de préjudice

8. CONSENTEMENT INFORMÉ
   En acceptant cette licence, vous confirmez que vous:
   • Avez lu et compris l'intégralité de ce contrat
   • Acceptez pleinement la responsabilité de votre utilisation
   • Reconnaissez que le créateur n'est pas responsable des conséquences
   • Utiliserez le logiciel de manière légale et éthique

═══════════════════════════════════════════════════════════════════════════════
9. LICENCE DE DISTRIBUTION
   Ce logiciel est distribué sous licence MIT (voir le fichier LICENSE).
   Vous pouvez l'utiliser, le modifier et le redistribuer librement, à
   condition de conserver la mention de copyright et cet avertissement.

═══════════════════════════════════════════════════════════════════════════════
Licence MIT · Contrat révisé le 23 août 2026
═══════════════════════════════════════════════════════════════════════════════
""",
    'EN': """
═══════════════════════════════════════════════════════════════════════════════
                   LICENSE AGREEMENT AND TERMS OF USE
                            SIPA — Audit réseau et sécurité
═══════════════════════════════════════════════════════════════════════════════

LICENSE ACCEPTANCE

By using this software, you accept the following conditions:

1. SOFTWARE PURPOSE
   • This software is designed EXCLUSIVELY for testing network vulnerabilities
   • Its use must comply with the legal framework of the active country
   • This software is NOT designed for illegal or malicious purposes

2. USER RESPONSIBILITY
   The user who uses this program is FULLY RESPONSIBLE for:
   • The use of the software
   • Legal compliance of their actions
   • Any damage caused by its use
   • Compliance with national and international laws

3. CREATOR RESPONSIBILITY
   The software creator IS NOT RESPONSIBLE for:
   • Misuse of the software
   • Any damage caused by this software
   • Any legal violation committed by the user
   • Any negative impact on third-party systems

4. LEGAL USE CONDITIONS
   AUTHORIZED USE:
   • Security testing on YOUR own systems
   • Testing on systems with explicit written permission from the owner
   • For educational and cybersecurity research purposes
   • To improve your network security

   PROHIBITED USE:
   • Unauthorized access to third-party systems
   • Security testing without explicit consent
   • Use for malicious or criminal purposes
   • Violation of national cybersecurity laws

5. LEGAL COMPLIANCE
   The software must be used in compliance with:
   • National laws of the country of use
   • Applicable international laws
   • Your organization's security policies
   • Service level agreement (SLA) policies

6. WARRANTIES
   This software is provided "AS IS" without any warranty:
   • No warranty as to its fitness
   • No warranty as to its performance
   • No warranty as to absence of bugs
   • No liability in case of data loss

7. LIMITATION OF LIABILITY
   In no event shall the creator be liable for:
   • Data loss
   • Service interruption
   • Indirect or consequential damages
   • Any other cause of harm

8. INFORMED CONSENT
   By accepting this license, you confirm that you:
   • Have read and understood this entire agreement
   • Fully accept responsibility for your use
   • Acknowledge that the creator is not responsible for consequences
   • Will use the software legally and ethically

═══════════════════════════════════════════════════════════════════════════════
9. DISTRIBUTION LICENCE
   This software is distributed under the MIT licence (see LICENSE).
   You may use, modify and redistribute it freely, provided the copyright
   notice and this disclaimer are retained.

═══════════════════════════════════════════════════════════════════════════════
MIT licence · Agreement revised on 23 August 2026
═══════════════════════════════════════════════════════════════════════════════
""",
    'ES': """
═══════════════════════════════════════════════════════════════════════════════
               ACUERDO DE LICENCIA Y TÉRMINOS DE USO
                            SIPA — Audit réseau et sécurité
═══════════════════════════════════════════════════════════════════════════════

ACEPTACIÓN DE LA LICENCIA

Al utilizar este software, acepta las siguientes condiciones:

1. PROPÓSITO DEL SOFTWARE
   • Este software está diseñado EXCLUSIVAMENTE para probar vulnerabilidades de red
   • Su uso debe cumplir con el marco legal del país activo
   • Este software NO está diseñado para fines ilegales o maliciosos

2. RESPONSABILIDAD DEL USUARIO
   El usuario que utiliza este programa es TOTALMENTE RESPONSABLE de:
   • El uso del software
   • Cumplimiento legal de sus acciones
   • Cualquier daño causado por su uso
   • Cumplimiento de leyes nacionales e internacionales

3. RESPONSABILIDAD DEL CREADOR
   El creador del software NO ES RESPONSABLE de:
   • El mal uso del software
   • Cualquier daño causado por este software
   • Cualquier violación legal cometida por el usuario
   • Cualquier impacto negativo en sistemas de terceros

4. CONDICIONES DE USO LEGAL
   USO AUTORIZADO:
   • Pruebas de seguridad en SUS propios sistemas
   • Pruebas en sistemas con permiso escrito explícito del propietario
   • Con fines educativos y de investigación en ciberseguridad
   • Para mejorar su seguridad de red

   USO PROHIBIDO:
   • Acceso no autorizado a sistemas de terceros
   • Pruebas de seguridad sin consentimiento explícito
   • Uso para fines maliciosos o criminales
   • Violación de leyes nacionales de ciberseguridad

5. CUMPLIMIENTO LEGAL
   El software debe usarse de conformidad con:
   • Leyes nacionales del país de uso
   • Leyes internacionales aplicables
   • Políticas de seguridad de su organización
   • Políticas de acuerdo de nivel de servicio (SLA)

6. GARANTÍAS
   Este software se proporciona "TAL CUAL" sin garantía alguna:
   • Sin garantía en cuanto a su idoneidad
   • Sin garantía en cuanto a su rendimiento
   • Sin garantía en cuanto a la ausencia de errores
   • Sin responsabilidad en caso de pérdida de datos

7. LIMITACIÓN DE RESPONSABILIDAD
   En ningún caso el creador será responsable de:
   • Pérdida de datos
   • Interrupción del servicio
   • Daños indirectos o consecuentes
   • Cualquier otra causa de daño

8. CONSENTIMIENTO INFORMADO
   Al aceptar esta licencia, usted confirma que:
   • Ha leído y entendido completamente este acuerdo
   • Acepta plenamente la responsabilidad de su uso
   • Reconoce que el creador no es responsable de las consecuencias
   • Utilizará el software de manera legal y ética

═══════════════════════════════════════════════════════════════════════════════
9. LICENCIA DE DISTRIBUCIÓN
   Este software se distribuye bajo licencia MIT (véase el archivo LICENSE).
   Puede usarlo, modificarlo y redistribuirlo libremente, siempre que
   conserve el aviso de copyright y esta exención de responsabilidad.

═══════════════════════════════════════════════════════════════════════════════
Licencia MIT · Contrato revisado el 23 de agosto de 2026
═══════════════════════════════════════════════════════════════════════════════
""",
    'DE': """
═══════════════════════════════════════════════════════════════════════════════
                   LIZENZVEREINBARUNG UND NUTZUNGSBEDINGUNGEN
                            SIPA — Audit réseau et sécurité
═══════════════════════════════════════════════════════════════════════════════

LIZENZAKZEPTANZ

Durch die Nutzung dieser Software akzeptieren Sie die folgenden Bedingungen:

1. ZWECK DER SOFTWARE
   • Diese Software ist AUSSCHLIESSLICH zum Testen von Netzwerksicherheitslücken gedacht
   • Ihre Nutzung muss dem rechtlichen Rahmen des aktiven Landes entsprechen
   • Diese Software ist NICHT für illegale oder böswillige Zwecke gedacht

2. VERANTWORTUNG DES BENUTZERS
   Der Benutzer, der dieses Programm nutzt, ist VOLLSTÄNDIG verantwortlich für:
   • Die Nutzung der Software
   • Rechtliche Konformität seiner Handlungen
   • Alle durch die Nutzung verursachten Schäden
   • Einhaltung nationaler und internationaler Gesetze

3. HAFTUNG DES SCHÖPFERS
   Der Softwareentwickler IST NICHT HAFTBAR für:
   • Missbrauch der Software
   • Alle durch diese Software verursachten Schäden
   • Alle illegalen Handlungen des Benutzers
   • Negative Auswirkungen auf Systeme Dritter

4. BEDINGUNGEN FÜR LEGALE NUTZUNG
   AUTORISIERTE NUTZUNG:
   • Sicherheitstests auf IHREN eigenen Systemen
   • Tests auf Systemen mit ausdrücklicher schriftlicher Genehmigung des Eigentümers
   • Zu Bildungs- und Cybersecurity-Forschungszwecken
   • Zur Verbesserung Ihrer Netzwerksicherheit

   VERBOTENE NUTZUNG:
   • Unbefugter Zugriff auf Systeme Dritter
   • Sicherheitstests ohne ausdrückliche Zustimmung
   • Nutzung für illegale oder kriminelle Zwecke
   • Verstoß gegen nationale Cybersicherheitsgesetze

5. RECHTLICHE KONFORMITÄT
   Die Software muss in Übereinstimmung mit folgendem verwendet werden:
   • Nationale Gesetze des Nutzungslandes
   • Anwendbare internationale Gesetze
   • Sicherheitsrichtlinien Ihrer Organisation
   • SLA-Richtlinien (Service Level Agreement)

6. GEWÄHRLEISTUNGEN
   Diese Software wird "WIE BESEHEN" ohne jegliche Garantie bereitgestellt:
   • Keine Garantie bezüglich ihrer Eignung
   • Keine Garantie bezüglich ihrer Leistung
   • Keine Garantie bezüglich Fehlerfreiheit
   • Keine Haftung im Falle von Datenverlust

7. HAFTUNGSBESCHRÄNKUNG
   Der Schöpfer haftet in keinem Fall für:
   • Datenverlust
   • Dienstunterbrechung
   • Indirekte oder Folgeschäden
   • Jede andere Schadensursache

8. INFORMIERTE ZUSTIMMUNG
   Durch die Annahme dieser Lizenz bestätigen Sie, dass Sie:
   • Diese gesamte Vereinbarung gelesen und verstanden haben
   • Vollständig die Verantwortung für Ihre Nutzung übernehmen
   • Anerkennen, dass der Schöpfer nicht für die Folgen verantwortlich ist
   • Die Software legal und ethisch nutzen werden

═══════════════════════════════════════════════════════════════════════════════
9. VERTRIEBSLIZENZ
   Diese Software wird unter der MIT-Lizenz vertrieben (siehe LICENSE).
   Sie dürfen sie frei verwenden, ändern und weitergeben, sofern der
   Copyright-Hinweis und dieser Haftungsausschluss erhalten bleiben.

═══════════════════════════════════════════════════════════════════════════════
MIT-Lizenz · Vertrag überarbeitet am 23. August 2026
═══════════════════════════════════════════════════════════════════════════════
""",
    'IT': """
═══════════════════════════════════════════════════════════════════════════════
                   CONTRATTO DI LICENZA E TERMINI DI UTILIZZO
                            SIPA — Audit réseau et sécurité
═══════════════════════════════════════════════════════════════════════════════

ACCETTAZIONE DELLA LICENZA

Utilizzando questo software, accettate le seguenti condizioni:

1. SCOPO DEL SOFTWARE
   • Questo software è progettato ESCLUSIVAMENTE per testare vulnerabilità di rete
   • Il suo utilizzo deve rispettare il quadro legale del paese attivo
   • Questo software NON è progettato per scopi illegali o dannosi

2. RESPONSABILITÀ DELL'UTENTE
   L'utente che utilizza questo programma è INTERAMENTE RESPONSABILE di:
   • L'utilizzo del software
   • Conformità legale delle sue azioni
   • Qualsiasi danno causato dal suo utilizzo
   • Conformità alle leggi nazionali e internazionali

3. RESPONSABILITÀ DEL CREATORE
   Il creatore del software NON È RESPONSABILE di:
   • Abuso del software
   • Qualsiasi danno causato da questo software
   • Qualsiasi violazione legale commessa dall'utente
   • Qualsiasi impatto negativo su sistemi di terzi

4. CONDIZIONI DI UTILIZZO LEGALE
   UTILIZZO AUTORIZZATO:
   • Test di sicurezza sui VOSTRI sistemi
   • Test su sistemi con permesso scritto esplicito del proprietario
   • A fini educativi e di ricerca in cybersecurity
   • Per migliorare la vostra sicurezza di rete

   UTILIZZO VIETATO:
   • Accesso non autorizzato a sistemi di terzi
   • Test di sicurezza senza consenso esplicito
   • Utilizzo per scopi illegali o criminali
   • Violazione delle leggi nazionali sulla cybersecurity

5. CONFORMITÀ LEGALE
   Il software deve essere utilizzato in conformità con:
   • Leggi nazionali del paese di utilizzo
   • Leggi internazionali applicabili
   • Politiche di sicurezza della vostra organizzazione
   • Politiche dell'accordo di livello di servizio (SLA)

6. GARANZIE
   Questo software è fornito "COSÌ COM'È" senza alcuna garanzia:
   • Nessuna garanzia quanto alla sua idoneità
   • Nessuna garanzia quanto alle sue prestazioni
   • Nessuna garanzia quanto all'assenza di errori
   • Nessuna responsabilità in caso di perdita di dati

7. LIMITAZIONE DI RESPONSABILITÀ
   In nessun caso il creatore sarà responsabile di:
   • Perdita di dati
   • Interruzione del servizio
   • Danni indiretti o consequenziali
   • Qualsiasi altra causa di danno

8. CONSENSO INFORMATO
   Accettando questa licenza, confermate che:
   • Avete letto e compreso completamente questo contratto
   • Accettate pienamente la responsabilità del vostro utilizzo
   • Riconoscete che il creatore non è responsabile delle conseguenze
   • Utilizzerete il software legalmente ed eticamente

═══════════════════════════════════════════════════════════════════════════════
9. LICENZA DI DISTRIBUZIONE
   Questo software è distribuito con licenza MIT (vedere il file LICENSE).
   Puoi usarlo, modificarlo e ridistribuirlo liberamente, a condizione di
   conservare l'avviso di copyright e questa esclusione di responsabilità.

═══════════════════════════════════════════════════════════════════════════════
Licenza MIT · Contratto rivisto il 23 agosto 2026
═══════════════════════════════════════════════════════════════════════════════
"""
}

BUTTON_DESCRIPTIONS = {
    'FR': {
        'scan_fast': 'Scan rapide des ports ouverts avec Nmap',
        'scan_full': 'Scan complet avec détection des versions de services',
        'scan_vuln': 'Détecte les CVE (Common Vulnerabilities and Exposures)',
        'detect_backdoor': 'Cherche les ports et services malveillants connus',
        'network_health': 'Vérifie la santé du réseau (DNS, DHCP, SMB)',
        'detect_exploit': 'Teste les vulnérabilités d\'exploitation courants',
        'persistence': 'Détecte les mécanismes de persistence malveillants',
        'forensic': 'Analyse forensique profonde du système',
        'advanced_exploits': 'Détecte EternalBlue, Mimikatz, ZeroLogon, etc.',
        'network_graph': 'Visualise la topologie réseau en ASCII art',
        'shodan': 'Vérifie si vos ports sont exposés sur Internet',
        'traffic': 'Capture et analyse les paquets réseau en temps réel',
        'export': 'Exporte les rapports en PDF, Excel, JSON, CSV',
        'brute_force': 'Détecte les attaques par force brute SSH/RDP',
        'geolocation': 'Localise les IPs externes et identifie les menaces',
        'ssl': 'Analyse les certificats SSL/TLS (expiration, faiblesse)',
        'honeypot': 'Crée des pièges pour détecter les attaquants',
        'firewall': 'Génère automatiquement des règles de blocage',
        'virustotal': 'Vérifie la réputation des IPs sur VirusTotal',
        'credentials': 'Cherche des mots de passe en clair dans VOS fichiers locaux (Documents)',
        'dashboard': 'Affiche un tableau de bord de sécurité temps réel',
    },
    'EN': {
        'scan_fast': 'Quick port scan with Nmap',
        'scan_full': 'Full scan with service version detection',
        'scan_vuln': 'Detects CVE (Common Vulnerabilities and Exposures)',
        'detect_backdoor': 'Searches for known malicious ports and services',
        'network_health': 'Checks network health (DNS, DHCP, SMB)',
        'detect_exploit': 'Tests common exploitation vulnerabilities',
        'persistence': 'Detects malicious persistence mechanisms',
        'forensic': 'Deep forensic system analysis',
        'advanced_exploits': 'Detects EternalBlue, Mimikatz, ZeroLogon, etc.',
        'network_graph': 'Visualizes network topology in ASCII art',
        'shodan': 'Checks if your ports are exposed on the Internet',
        'traffic': 'Captures and analyzes network packets in real-time',
        'export': 'Exports reports in PDF, Excel, JSON, CSV',
        'brute_force': 'Detects SSH/RDP brute force attack attempts',
        'geolocation': 'Locates external IPs and identifies threats',
        'ssl': 'Analyzes SSL/TLS certificates (expiration, weakness)',
        'honeypot': 'Creates traps to detect attackers',
        'firewall': 'Automatically generates blocking rules',
        'virustotal': 'Checks IP reputation on VirusTotal',
        'credentials': 'Searches YOUR local files (Documents) for plaintext passwords',
        'dashboard': 'Displays real-time security dashboard',
    }
}


#: Libelles de l'interface, indexes par le texte francais exact.
#: `AuditIA_Ultimate.tr()` les applique au moment du rendu, ce qui permet
#: de retraduire l'interface entiere sans toucher aux sites d'appel.
#: Une chaine absente de ce tableau reste affichee en francais.
UI_LABELS = {
    'Analyses': {
        'EN': 'Analysis',
        'ES': 'Análisis',
        'DE': 'Analysen',
        'IT': 'Analisi',
    },
    'Réseau et renseignement': {
        'EN': 'Network & intelligence',
        'ES': 'Red e inteligencia',
        'DE': 'Netzwerk & Aufklärung',
        'IT': 'Rete e intelligence',
    },
    'Rapports et défense': {
        'EN': 'Reports & defence',
        'ES': 'Informes y defensa',
        'DE': 'Berichte & Abwehr',
        'IT': 'Rapporti e difesa',
    },
    'Commandes': {
        'EN': 'Commands',
        'ES': 'Comandos',
        'DE': 'Befehle',
        'IT': 'Comandi',
    },
    'Paramètres': {
        'EN': 'Settings',
        'ES': 'Ajustes',
        'DE': 'Einstellungen',
        'IT': 'Impostazioni',
    },
    'Réseau': {
        'EN': 'Network',
        'ES': 'Red',
        'DE': 'Netzwerk',
        'IT': 'Rete',
    },
    'Rapports': {
        'EN': 'Reports',
        'ES': 'Informes',
        'DE': 'Berichte',
        'IT': 'Rapporti',
    },
    'Scans réseau': {
        'EN': 'Network scans',
        'ES': 'Escaneos de red',
        'DE': 'Netzwerk-Scans',
        'IT': 'Scansioni di rete',
    },
    'Menaces et forensique': {
        'EN': 'Threats & forensics',
        'ES': 'Amenazas y forense',
        'DE': 'Bedrohungen & Forensik',
        'IT': 'Minacce e forense',
    },
    'Cartographie et trafic': {
        'EN': 'Mapping & traffic',
        'ES': 'Mapeo y tráfico',
        'DE': 'Kartierung & Datenverkehr',
        'IT': 'Mappatura e traffico',
    },
    'Renseignement externe': {
        'EN': 'External intelligence',
        'ES': 'Inteligencia externa',
        'DE': 'Externe Aufklärung',
        'IT': 'Intelligence esterna',
    },
    'Rapports et historique': {
        'EN': 'Reports & history',
        'ES': 'Informes e historial',
        'DE': 'Berichte & Verlauf',
        'IT': 'Rapporti e cronologia',
    },
    'Défense et surveillance': {
        'EN': 'Defence & monitoring',
        'ES': 'Defensa y vigilancia',
        'DE': 'Abwehr & Überwachung',
        'IT': 'Difesa e monitoraggio',
    },
    'Intégrations': {
        'EN': 'Integrations',
        'ES': 'Integraciones',
        'DE': 'Integrationen',
        'IT': 'Integrazioni',
    },
    'Préférences et alertes': {
        'EN': 'Preferences & alerts',
        'ES': 'Preferencias y alertas',
        'DE': 'Einstellungen & Warnungen',
        'IT': 'Preferenze e avvisi',
    },
    'Scan rapide': {
        'EN': 'Quick scan',
        'ES': 'Escaneo rápido',
        'DE': 'Schnell-Scan',
        'IT': 'Scansione rapida',
    },
    'Scan complet': {
        'EN': 'Full scan',
        'ES': 'Escaneo completo',
        'DE': 'Vollständiger Scan',
        'IT': 'Scansione completa',
    },
    'Scan CVE': {
        'EN': 'CVE scan',
        'ES': 'Escaneo CVE',
        'DE': 'CVE-Scan',
        'IT': 'Scansione CVE',
    },
    'Portes dérobées': {
        'EN': 'Backdoors',
        'ES': 'Puertas traseras',
        'DE': 'Hintertüren',
        'IT': 'Backdoor',
    },
    'Audit des services': {
        'EN': 'Service audit',
        'ES': 'Auditoría de servicios',
        'DE': 'Dienste-Audit',
        'IT': 'Audit dei servizi',
    },
    'Santé du réseau': {
        'EN': 'Network health',
        'ES': 'Salud de la red',
        'DE': 'Netzwerkzustand',
        'IT': 'Salute della rete',
    },
    'Analyse DNS': {
        'EN': 'DNS analysis',
        'ES': 'Análisis DNS',
        'DE': 'DNS-Analyse',
        'IT': 'Analisi DNS',
    },
    'SSL / TLS': {
        'EN': 'SSL / TLS',
        'ES': 'SSL / TLS',
        'DE': 'SSL / TLS',
        'IT': 'SSL / TLS',
    },
    'Chaîne de certificats': {
        'EN': 'Certificate chain',
        'ES': 'Cadena de certificados',
        'DE': 'Zertifikatskette',
        'IT': 'Catena di certificati',
    },
    'Exploits connus': {
        'EN': 'Known exploits',
        'ES': 'Exploits conocidos',
        'DE': 'Bekannte Exploits',
        'IT': 'Exploit noti',
    },
    'Exploits avancés': {
        'EN': 'Advanced exploits',
        'ES': 'Exploits avanzados',
        'DE': 'Erweiterte Exploits',
        'IT': 'Exploit avanzati',
    },
    'Rootkits': {
        'EN': 'Rootkits',
        'ES': 'Rootkits',
        'DE': 'Rootkits',
        'IT': 'Rootkit',
    },
    'Mécanismes de persistance': {
        'EN': 'Persistence mechanisms',
        'ES': 'Mecanismos de persistencia',
        'DE': 'Persistenzmechanismen',
        'IT': 'Meccanismi di persistenza',
    },
    'Attaques par force brute': {
        'EN': 'Brute-force attacks',
        'ES': 'Ataques de fuerza bruta',
        'DE': 'Brute-Force-Angriffe',
        'IT': 'Attacchi a forza bruta',
    },
    'Analyse forensique': {
        'EN': 'Forensic analysis',
        'ES': 'Análisis forense',
        'DE': 'Forensische Analyse',
        'IT': 'Analisi forense',
    },
    'Audit du système': {
        'EN': 'System audit',
        'ES': 'Auditoría del sistema',
        'DE': 'System-Audit',
        'IT': 'Audit di sistema',
    },
    "Détection d'anomalies": {
        'EN': 'Anomaly detection',
        'ES': 'Detección de anomalías',
        'DE': 'Anomalieerkennung',
        'IT': 'Rilevamento anomalie',
    },
    'Secrets dans vos fichiers': {
        'EN': 'Secrets in your files',
        'ES': 'Secretos en sus archivos',
        'DE': 'Geheimnisse in Ihren Dateien',
        'IT': 'Segreti nei vostri file',
    },
    'Analyse du trafic': {
        'EN': 'Traffic analysis',
        'ES': 'Análisis de tráfico',
        'DE': 'Verkehrsanalyse',
        'IT': 'Analisi del traffico',
    },
    'Graphiques en temps réel': {
        'EN': 'Live charts',
        'ES': 'Gráficos en tiempo real',
        'DE': 'Echtzeit-Diagramme',
        'IT': 'Grafici in tempo reale',
    },
    'Graphe du réseau': {
        'EN': 'Network graph',
        'ES': 'Grafo de red',
        'DE': 'Netzwerkgraph',
        'IT': 'Grafo di rete',
    },
    'Carte du réseau': {
        'EN': 'Network map',
        'ES': 'Mapa de red',
        'DE': 'Netzwerkkarte',
        'IT': 'Mappa di rete',
    },
    'Changements depuis le dernier scan': {
        'EN': 'Changes since last scan',
        'ES': 'Cambios desde el último escaneo',
        'DE': 'Änderungen seit dem letzten Scan',
        'IT': "Modifiche dall'ultima scansione",
    },
    'Intégrité ARP': {
        'EN': 'ARP integrity',
        'ES': 'Integridad ARP',
        'DE': 'ARP-Integrität',
        'IT': 'Integrità ARP',
    },
    'Fabricant (adresse MAC)': {
        'EN': 'Vendor (MAC address)',
        'ES': 'Fabricante (dirección MAC)',
        'DE': 'Hersteller (MAC-Adresse)',
        'IT': 'Produttore (indirizzo MAC)',
    },
    'Réseaux Wi-Fi': {
        'EN': 'Wi-Fi networks',
        'ES': 'Redes Wi-Fi',
        'DE': 'WLAN-Netze',
        'IT': 'Reti Wi-Fi',
    },
    'Découverte par diffusion': {
        'EN': 'Broadcast discovery',
        'ES': 'Descubrimiento por difusión',
        'DE': 'Broadcast-Erkennung',
        'IT': 'Rilevamento broadcast',
    },
    'Shodan': {
        'EN': 'Shodan',
        'ES': 'Shodan',
        'DE': 'Shodan',
        'IT': 'Shodan',
    },
    'VirusTotal': {
        'EN': 'VirusTotal',
        'ES': 'VirusTotal',
        'DE': 'VirusTotal',
        'IT': 'VirusTotal',
    },
    "Réputation d'une IP": {
        'EN': 'IP reputation',
        'ES': 'Reputación de una IP',
        'DE': 'IP-Reputation',
        'IT': 'Reputazione di un IP',
    },
    'SearchSploit': {
        'EN': 'SearchSploit',
        'ES': 'SearchSploit',
        'DE': 'SearchSploit',
        'IT': 'SearchSploit',
    },
    'Renseignement public (OSINT)': {
        'EN': 'Open-source intelligence',
        'ES': 'Inteligencia de fuentes abiertas',
        'DE': 'Open-Source-Aufklärung',
        'IT': 'Intelligence di fonti aperte',
    },
    'Active Directory': {
        'EN': 'Active Directory',
        'ES': 'Active Directory',
        'DE': 'Active Directory',
        'IT': 'Active Directory',
    },
    'Géolocalisation': {
        'EN': 'Geolocation',
        'ES': 'Geolocalización',
        'DE': 'Geolokalisierung',
        'IT': 'Geolocalizzazione',
    },
    'Technologies web': {
        'EN': 'Web technologies',
        'ES': 'Tecnologías web',
        'DE': 'Web-Technologien',
        'IT': 'Tecnologie web',
    },
    'Exporter (PDF, Excel, JSON)': {
        'EN': 'Export (PDF, Excel, JSON)',
        'ES': 'Exportar (PDF, Excel, JSON)',
        'DE': 'Exportieren (PDF, Excel, JSON)',
        'IT': 'Esporta (PDF, Excel, JSON)',
    },
    'Rapport HTML': {
        'EN': 'HTML report',
        'ES': 'Informe HTML',
        'DE': 'HTML-Bericht',
        'IT': 'Rapporto HTML',
    },
    'Tableau de bord': {
        'EN': 'Dashboard',
        'ES': 'Panel de control',
        'DE': 'Dashboard',
        'IT': 'Cruscotto',
    },
    'Tableau de bord 3D': {
        'EN': '3D dashboard',
        'ES': 'Panel 3D',
        'DE': '3D-Dashboard',
        'IT': 'Cruscotto 3D',
    },
    'Appareils détectés': {
        'EN': 'Detected devices',
        'ES': 'Dispositivos detectados',
        'DE': 'Erkannte Geräte',
        'IT': 'Dispositivi rilevati',
    },
    'Historique des scans': {
        'EN': 'Scan history',
        'ES': 'Historial de escaneos',
        'DE': 'Scan-Verlauf',
        'IT': 'Cronologia scansioni',
    },
    'Comparer deux scans': {
        'EN': 'Compare two scans',
        'ES': 'Comparar dos escaneos',
        'DE': 'Zwei Scans vergleichen',
        'IT': 'Confronta due scansioni',
    },
    'Rejouer un scan': {
        'EN': 'Replay a scan',
        'ES': 'Repetir un escaneo',
        'DE': 'Scan wiederholen',
        'IT': 'Ripeti una scansione',
    },
    "Journal d'audit": {
        'EN': 'Audit log',
        'ES': 'Registro de auditoría',
        'DE': 'Audit-Protokoll',
        'IT': 'Registro di audit',
    },
    "Capture d'écran": {
        'EN': 'Screenshot',
        'ES': 'Captura de pantalla',
        'DE': 'Bildschirmfoto',
        'IT': 'Schermata',
    },
    'Audit de posture': {
        'EN': 'Hardening audit',
        'ES': 'Auditoría de configuración',
        'DE': 'Härtungs-Audit',
        'IT': 'Audit di configurazione',
    },
    'Surveillance continue': {
        'EN': 'Continuous monitoring',
        'ES': 'Monitorización continua',
        'DE': 'Dauerüberwachung',
        'IT': 'Monitoraggio continuo',
    },
    'Règles du pare-feu': {
        'EN': 'Firewall rules',
        'ES': 'Reglas del cortafuegos',
        'DE': 'Firewall-Regeln',
        'IT': 'Regole del firewall',
    },
    'Leurre réseau': {
        'EN': 'Network decoy',
        'ES': 'Señuelo de red',
        'DE': 'Netzwerk-Köder',
        'IT': 'Esca di rete',
    },
    'Mode discret': {
        'EN': 'Low-profile mode',
        'ES': 'Modo discreto',
        'DE': 'Zurückhaltender Modus',
        'IT': 'Modalità discreta',
    },
    'Processus en cours': {
        'EN': 'Running processes',
        'ES': 'Procesos en ejecución',
        'DE': 'Laufende Prozesse',
        'IT': 'Processi in esecuzione',
    },
    'Bac à sable': {
        'EN': 'Sandbox',
        'ES': 'Entorno aislado',
        'DE': 'Sandbox',
        'IT': 'Sandbox',
    },
    'OpenVAS (Windows)': {
        'EN': 'OpenVAS (Windows)',
        'ES': 'OpenVAS (Windows)',
        'DE': 'OpenVAS (Windows)',
        'IT': 'OpenVAS (Windows)',
    },
    'OpenVAS (Docker)': {
        'EN': 'OpenVAS (Docker)',
        'ES': 'OpenVAS (Docker)',
        'DE': 'OpenVAS (Docker)',
        'IT': 'OpenVAS (Docker)',
    },
    'Serveur API REST': {
        'EN': 'REST API server',
        'ES': 'Servidor API REST',
        'DE': 'REST-API-Server',
        'IT': 'Server API REST',
    },
    'Scan multi-cibles': {
        'EN': 'Multi-target scan',
        'ES': 'Escaneo multiobjetivo',
        'DE': 'Mehrziel-Scan',
        'IT': 'Scansione multi-obiettivo',
    },
    'Planifier des scans': {
        'EN': 'Schedule scans',
        'ES': 'Programar escaneos',
        'DE': 'Scans planen',
        'IT': 'Pianifica scansioni',
    },
    'Slack': {
        'EN': 'Slack',
        'ES': 'Slack',
        'DE': 'Slack',
        'IT': 'Slack',
    },
    'Webhook': {
        'EN': 'Webhook',
        'ES': 'Webhook',
        'DE': 'Webhook',
        'IT': 'Webhook',
    },
    'Tenable': {
        'EN': 'Tenable',
        'ES': 'Tenable',
        'DE': 'Tenable',
        'IT': 'Tenable',
    },
    'Qualys': {
        'EN': 'Qualys',
        'ES': 'Qualys',
        'DE': 'Qualys',
        'IT': 'Qualys',
    },
    'Microsoft Defender': {
        'EN': 'Microsoft Defender',
        'ES': 'Microsoft Defender',
        'DE': 'Microsoft Defender',
        'IT': 'Microsoft Defender',
    },
    'Mode agent': {
        'EN': 'Agent mode',
        'ES': 'Modo agente',
        'DE': 'Agentenmodus',
        'IT': 'Modalità agente',
    },
    'Aide': {
        'EN': 'Help',
        'ES': 'Ayuda',
        'DE': 'Hilfe',
        'IT': 'Aiuto',
    },
    "Configurer l'e-mail": {
        'EN': 'Configure email',
        'ES': 'Configurar correo',
        'DE': 'E-Mail einrichten',
        'IT': 'Configura e-mail',
    },
    'Notifications': {
        'EN': 'Notifications',
        'ES': 'Notificaciones',
        'DE': 'Benachrichtigungen',
        'IT': 'Notifiche',
    },
    "Sons d'alerte": {
        'EN': 'Alert sounds',
        'ES': 'Sonidos de alerta',
        'DE': 'Warntöne',
        'IT': 'Suoni di avviso',
    },
    'Mode performance': {
        'EN': 'Performance mode',
        'ES': 'Modo rendimiento',
        'DE': 'Leistungsmodus',
        'IT': 'Modalità prestazioni',
    },
    'Thème sombre': {
        'EN': 'Dark theme',
        'ES': 'Tema oscuro',
        'DE': 'Dunkles Design',
        'IT': 'Tema scuro',
    },
    'Thème clair': {
        'EN': 'Light theme',
        'ES': 'Tema claro',
        'DE': 'Helles Design',
        'IT': 'Tema chiaro',
    },
    'Palette active': {
        'EN': 'Active palette',
        'ES': 'Paleta activa',
        'DE': 'Aktive Palette',
        'IT': 'Tavolozza attiva',
    },
    'Détecter': {
        'EN': 'Detect',
        'ES': 'Detectar',
        'DE': 'Erkennen',
        'IT': 'Rileva',
    },
    ' Cible ': {
        'EN': ' Target ',
        'ES': ' Objetivo ',
        'DE': ' Ziel ',
        'IT': ' Obiettivo ',
    },
}

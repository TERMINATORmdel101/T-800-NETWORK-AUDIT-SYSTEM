"""Services autonomes de SIPA : configuration, journalisation, notifications,
rapports PDF, planification, file de scans et installation des prerequis.

Extrait de sipa.py (phase 3 : refonte modulaire) sans modification de
comportement. Ces classes ne dependent pas de l'interface Tkinter.
"""

import ctypes
import json
import os
import random
import shlex
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import datetime

# Envoi d'emails (stdlib)
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

# Dependances optionnelles : chaque service se degrade proprement si absente.
from sipa_core import secrets as _secrets

try:
    import requests
except ImportError:
    requests = None

PDF_AVAILABLE = False
try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter, A4
    PDF_AVAILABLE = True
except ImportError:
    canvas = None

APSCHEDULER_AVAILABLE = False
try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger
    APSCHEDULER_AVAILABLE = True
except ImportError:
    BackgroundScheduler = None
    CronTrigger = None


def resource_path(relative_path):
    """Trouve le chemin absolu des ressources, que ce soit en dev ou dans le .exe"""
    try:
        # PyInstaller crée un dossier temporaire et stocke le chemin dans _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    
    return os.path.join(base_path, relative_path)

# ========== CONFIG MANAGER CLASS ==========
class ConfigManager:
    """Gestionnaire de configuration - RÉEL, pas simulé. Charge/sauvegarde config.json"""
    
    DEFAULT_CONFIG_PATH = "config.json"
    
    def __init__(self, config_path=None):
        self.config_path = config_path or self.DEFAULT_CONFIG_PATH
        self.config = {}
        self.load_config()
    
    def load_config(self):
        """Charge la configuration depuis config.json"""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    self.config = json.load(f)
                    print(f"[CONFIG] Fichier de configuration chargé:{self.config_path}")
            else:
                print(f"[CONFIG] Fichier config non trouvé:{self.config_path}")
                self.config = self.get_default_config()
        except Exception as e:
            print(f"[CONFIG] Erreur de chargement:{e}")
            self.config = self.get_default_config()
    
    def save_config(self):
        """Sauvegarde la configuration dans config.json"""
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"[CONFIG] Erreur de sauvegarde:{e}")
            return False
    
    def get(self, key_path, default=None):
        """Récupère une valeur config avec notation pointée (ex: 'email.enabled')"""
        keys = key_path.split('.')
        value = self.config
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key_path, value):
        """Définit une valeur config avec notation pointée"""
        keys = key_path.split('.')
        config = self.config
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        config[keys[-1]] = value
        # Persistance immediate : les dialogues de configuration appelaient
        # set() sans jamais save_config(), donc AUCUN reglage ne survivait au
        # redemarrage. On sauvegarde ici pour que chaque modification tienne.
        self.save_config()
    
    def get_scan_settings(self):
        """Retourne les paramètres de scan"""
        return self.get('scan_settings', {})
    
    def get_email_config(self):
        """Retourne la configuration email"""
        return self.get('email', {})
    
    def get_slack_config(self):
        """Retourne la configuration Slack"""
        return self.get('slack', {})
    
    def get_discord_config(self):
        """Retourne la configuration Discord"""
        return self.get('discord', {})
    
    def get_pdf_config(self):
        """Retourne la configuration des rapports PDF"""
        return self.get('pdf_reports', {})
    
    def get_audit_config(self):
        """Retourne la configuration du audit log"""
        return self.get('audit_log', {})
    
    def get_schedule_config(self):
        """Retourne la configuration du scheduling"""
        return self.get('scheduling', {})
    
    def get_multi_scan_config(self):
        """Retourne la configuration multi-scans"""
        return self.get('multi_scan', {})
    
    @staticmethod
    def get_default_config():
        """Retourne une configuration par défaut complète"""
        return {
            "scan_settings": {
                "targets": ["192.168.1.0/24"],
                "scan_type": "comprehensive",
                "nmap_timeout": 300,
                "max_parallel_scans": 3
            },
            "scheduling": {
                "enabled": False,
                "frequency": "daily",
                "time": "02:00",
                "days": ["monday", "tuesday", "wednesday", "thursday", "friday"]
            },
            "email": {
                "enabled": False,
                "smtp_server": "smtp.gmail.com",
                "smtp_port": 587,
                "sender_email": "your-email@gmail.com",
                "sender_password": "your-app-password",
                "recipients": [],
                "include_pdf_report": True,
                "send_on_threats": True,
                "threat_severity": "medium"
            },
            "cve": {
                # Correlation des services detectes avec les CVE connues (NVD).
                "enabled": True
            },
            "nvd": {
                # Cle API NVD facultative : accelere la correlation en relevant
                # la limite de debit. https://nvd.nist.gov/developers/request-an-api-key
                "api_key": ""
            },
            "alerts": {
                # Prevenir quand le reseau change entre deux scans : nouvel
                # hote, nouveau port ouvert. C'est ce qui distingue une
                # surveillance d'un scan ponctuel.
                "on_drift": False
            },
            "slack": {
                "enabled": False,
                "webhook_url": "",
                "send_on_threats": True
            },
            "discord": {
                "enabled": False,
                "webhook_url": "",
                "send_on_threats": True
            },
            "pdf_reports": {
                "enabled": True,
                "include_graphs": True,
                "include_trends": True,
                "output_directory": "./reports"
            },
            "audit_log": {
                "enabled": True,
                "database": "t800_neural_net.db",
                "table": "audit_log",
                "retention_days": 365
            },
            "multi_scan": {
                "enabled": True,
                "max_concurrent": 3,
                "queue_enabled": True
            }
        }

# ========== AUDIT LOG CLASS (GDPR Compliant) ==========
class AuditLogger:
    """Enregistre toutes les actions de l'utilisateur - RÉEL, pas simulé. GDPR/ISO27001 compliant"""
    
    def __init__(self, config_manager):
        self.config = config_manager
        self.db_path = self.config.get('audit_log.database', 't800_neural_net.db')
        self.table_name = self.config.get('audit_log.table', 'audit_log')
        self.init_database()
    
    def init_database(self):
        """Crée la table audit_log si elle n'existe pas"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(f"""
                CREATE TABLE IF NOT EXISTS {self.table_name} (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    user_action TEXT NOT NULL,
                    details TEXT,
                    result TEXT,
                    severity TEXT DEFAULT 'INFO',
                    target_ip TEXT,
                    scan_type TEXT
                )
            """)
            conn.commit()
            conn.close()
            print(f"[AUDIT] Table de log créée/vérifiée")
        except Exception as e:
            print(f"[AUDIT] Erreur db:{e}")
    
    def log_action(self, user_action, details="", result="SUCCESS", severity="INFO", target_ip="", scan_type=""):
        """Enregistre une action utilisateur - RÉEL"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            timestamp = datetime.now().isoformat()
            cursor.execute(f"""
                INSERT INTO {self.table_name} 
                (timestamp, user_action, details, result, severity, target_ip, scan_type)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (timestamp, user_action, details, result, severity, target_ip, scan_type))
            conn.commit()
            conn.close()
            print(f"[AUDIT] Action enregistrée:{user_action}")
            return True
        except Exception as e:
            print(f"[AUDIT] Erreur log:{e}")
            return False
    
    def get_logs(self, limit=100, severity=None):
        """Récupère les logs (optionnel: filtre par sévérité)"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            if severity:
                cursor.execute(f"SELECT * FROM {self.table_name} WHERE severity=? ORDER BY timestamp DESC LIMIT ?", 
                             (severity, limit))
            else:
                cursor.execute(f"SELECT * FROM {self.table_name} ORDER BY timestamp DESC LIMIT ?", (limit,))
            logs = cursor.fetchall()
            conn.close()
            return logs
        except Exception as e:
            print(f"[AUDIT] Erreur fetch:{e}")
            return []

# ========== EMAIL ALERTS CLASS ==========
class EmailNotifier:
    """Envoie des alertes email - RÉEL (smtplib vrai)"""
    
    def __init__(self, config_manager):
        self.config = config_manager
        self.email_cfg = self.config.get_email_config()
    
    def send_email(self, subject, body, html=False, attachments=None):
        """Envoie un email RÉEL via SMTP"""
        if not self.email_cfg.get('enabled'):
            print("[EMAIL] Emails désactivés dans config")
            return False
        
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.email_cfg.get('sender_email')
            msg['To'] = ', '.join(self.email_cfg.get('recipients', []))
            
            if html:
                msg.attach(MIMEText(body, 'html'))
            else:
                msg.attach(MIMEText(body, 'plain'))
            
            # Ajoute les pièces jointes (rapports PDF, etc)
            if attachments:
                for attach_path in attachments:
                    if os.path.exists(attach_path):
                        try:
                            with open(attach_path, 'rb') as attachment:
                                part = MIMEBase('application', 'octet-stream')
                                part.set_payload(attachment.read())
                                encoders.encode_base64(part)
                                part.add_header('Content-Disposition', f'attachment; filename= {os.path.basename(attach_path)}')
                                msg.attach(part)
                        except:
                            pass
            
            # Envoie via SMTP (RÉEL)
            with smtplib.SMTP(self.email_cfg.get('smtp_server'), self.email_cfg.get('smtp_port')) as server:
                server.starttls()
                server.login(self.email_cfg.get('sender_email'),
                             _secrets.unprotect(self.email_cfg.get('sender_password') or ''))
                server.send_message(msg)
            
            print(f"[EMAIL] Email envoyé à{len(self.email_cfg.get('recipients', []))} destinataires")
            return True
        except Exception as e:
            print(f"[EMAIL] Erreur:{e}")
            return False

# ========== SLACK/DISCORD WEBHOOKS CLASS ==========
class WebhookNotifier:
    """Envoie des alertes Slack/Discord - RÉEL (webhook HTTP)"""
    
    def __init__(self, config_manager):
        self.config = config_manager
        self.slack_cfg = self.config.get_slack_config()
        self.discord_cfg = self.config.get_discord_config()
    
    def send_slack(self, title, message, severity="INFO"):
        """Envoie une alerte Slack RÉELLE via webhook"""
        if not self.slack_cfg.get('enabled'):
            return False
        
        url = _secrets.unprotect(self.slack_cfg.get('webhook_url') or '')
        if not url:
            print("[SLACK] URL webhook vide")
            return False
        
        colors = {
            'CRITICAL': '#FF0000',
            'HIGH': '#FF0000',
            'MEDIUM': '#FF0000',
            'LOW': '#CCCCCC',
            'INFO': '#FFFFFF'
        }
        
        payload = {
            "text": title,
            "attachments": [{
                "color": colors.get(severity, colors['INFO']),
                "text": message,
                "ts": int(time.time())
            }]
        }
        
        try:
            response = requests.post(url, json=payload, timeout=5)
            if response.status_code == 200:
                print(f"[SLACK] Message posté")
                return True
            else:
                print(f"[SLACK] Status{response.status_code}")
                return False
        except Exception as e:
            print(f"[SLACK] Erreur:{e}")
            return False
    
    def send_discord(self, title, message, severity="INFO"):
        """Envoie une alerte Discord RÉELLE via webhook"""
        if not self.discord_cfg.get('enabled'):
            return False
        
        url = _secrets.unprotect(self.discord_cfg.get('webhook_url') or '')
        if not url:
            print("[DISCORD] URL webhook vide")
            return False
        
        colors = {
            'CRITICAL': 16711680,  # Red
            'HIGH': 16744960,      # Orange
            'MEDIUM': 16776960,    # Yellow
            'LOW': 65280,          # Green
            'INFO': 65535          # Cyan
        }
        
        payload = {
            "embeds": [{
                "title": title,
                "description": message,
                "color": colors.get(severity, colors['INFO']),
                "timestamp": datetime.now().isoformat()
            }]
        }
        
        try:
            response = requests.post(url, json=payload, timeout=5)
            if response.status_code in [200, 204]:
                print(f"[DISCORD] Message posté")
                return True
            else:
                print(f"[DISCORD] Status{response.status_code}")
                return False
        except Exception as e:
            print(f"[DISCORD] Erreur:{e}")
            return False

# ========== PDF REPORTS CLASS ==========
class PDFReportGenerator:
    """Génère des rapports PDF professionnels - RÉEL (reportlab)"""
    
    def __init__(self, config_manager):
        self.config = config_manager
        self.pdf_cfg = self.config.get_pdf_config()
    
    def generate_report(self, scan_results, report_title="Rapport d'Audit Réseau", output_file=None):
        """Génère un rapport PDF RÉEL"""
        if not self.pdf_cfg.get('enabled') or not PDF_AVAILABLE:
            print("[PDF] PDF désactivé ou reportlab non disponible")
            return None
        
        try:
            output_dir = self.pdf_cfg.get('output_directory', './reports')
            os.makedirs(output_dir, exist_ok=True)
            
            if not output_file:
                output_file = os.path.join(output_dir, f"rapport_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
            
            from reportlab.pdfgen import canvas
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.units import inch
            
            c = canvas.Canvas(output_file, pagesize=letter)
            width, height = letter
            y = height - 0.75*inch
            
            # En-tête
            c.setFont("Helvetica-Bold", 16)
            c.drawString(0.75*inch, y, report_title)
            y -= 0.3*inch
            
            # Date
            c.setFont("Helvetica", 10)
            c.drawString(0.75*inch, y, f"Généré: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
            y -= 0.2*inch
            
            # Contenu
            c.setFont("Helvetica", 10)
            if isinstance(scan_results, dict):
                for key, value in scan_results.items():
                    c.drawString(0.75*inch, y, f"{key}: {value}")
                    y -= 0.2*inch
            else:
                c.drawString(0.75*inch, y, str(scan_results))
                y -= 0.2*inch
            
            c.save()
            print(f"[PDF] Rapport généré:{output_file}")
            
            if self.pdf_cfg.get('auto_open'):
                import webbrowser
                webbrowser.open(output_file)
            
            return output_file
        except Exception as e:
            print(f"[PDF] Erreur:{e}")
            return None

# ========== SCHEDULER CLASS ==========
class ScanScheduler:
    """Planifie les scans automatiques - RÉEL (APScheduler)"""
    
    #: Jours acceptes par la configuration, dans l'ordre attendu par cron.
    DAYS = ("monday", "tuesday", "wednesday", "thursday",
            "friday", "saturday", "sunday")

    def __init__(self, config_manager, audit_logger=None, email_notifier=None,
                 scan_callback=None):
        self.config = config_manager
        self.audit_logger = audit_logger
        self.email_notifier = email_notifier
        # Fonction reellement appelee a l'heure dite. Sans elle, le scheduler
        # se declenchait mais ne lancait aucun scan (ancien "TODO").
        self.scan_callback = scan_callback
        self.scheduler = None
        self.is_running = False

        if APSCHEDULER_AVAILABLE:
            self.scheduler = BackgroundScheduler()
    
    def start_scheduler(self):
        """Démarre le scheduler APScheduler"""
        if not APSCHEDULER_AVAILABLE:
            print("[SCHEDULER] APScheduler non disponible")
            return False
        
        schedule_cfg = self.config.get_schedule_config()
        if not schedule_cfg.get('enabled'):
            print("[SCHEDULER] Scheduling désactivé dans config")
            return False
        
        try:
            if self.scheduler and not self.is_running:
                # Récupère l'heure et les jours
                time_str = schedule_cfg.get('time', '02:00')  # HH:MM
                days_list = schedule_cfg.get('days', [])
                
                hour, minute = map(int, time_str.split(':'))
                day_of_week = ','.join([self._day_to_number(d) for d in days_list])
                
                # Configure le trigger Cron
                trigger = CronTrigger(
                    day_of_week=day_of_week or '*',
                    hour=hour,
                    minute=minute
                )
                
                self.scheduler.add_job(
                    self._scheduled_scan,
                    trigger,
                    id='auto_scan_job'
                )
                
                self.scheduler.start()
                self.is_running = True
                print(f"[SCHEDULER] Scheduling ACTIF - Scan à{time_str}")
                
                if self.audit_logger:
                    self.audit_logger.log_action('SCHEDULER_START', f"Scan automatique à {time_str}")
                
                return True
        except Exception as e:
            print(f"[SCHEDULER] Erreur:{e}")
        
        return False
    
    def stop_scheduler(self):
        """Arrête le scheduler"""
        try:
            if self.scheduler and self.is_running:
                self.scheduler.shutdown(wait=False)
                self.is_running = False
                # APScheduler n'autorise pas le redemarrage d'une instance
                # arretee : on la remplace pour permettre apply_config().
                self.scheduler = BackgroundScheduler() if APSCHEDULER_AVAILABLE else None
                print("[SCHEDULER] Scheduler arrete")
        except Exception as exc:
            print(f"[SCHEDULER] Arret impossible : {exc}")
    
    def _scheduled_scan(self):
        """Declenche le scan reel a l'heure programmee."""
        if self.audit_logger:
            self.audit_logger.log_action('SCAN_AUTO', 'Scan automatique via scheduler')

        if not self.scan_callback:
            print("[SCHEDULER] Aucun scan associe : rien a lancer.")
            return

        try:
            self.scan_callback()
        except Exception as exc:
            print(f"[SCHEDULER] Echec du scan programme : {exc}")
            if self.audit_logger:
                self.audit_logger.log_action('SCAN_AUTO_ERROR', str(exc))

    def describe(self):
        """Resume lisible de la planification active (ou de son absence)."""
        cfg = self.config.get_schedule_config()
        if not APSCHEDULER_AVAILABLE:
            return "APScheduler n'est pas installe : planification indisponible."
        if not self.is_running:
            return "Aucune planification active."
        days = cfg.get('days') or []
        label = "tous les jours" if len(days) == 7 else ", ".join(days)
        return f"Scan programme a {cfg.get('time', '02:00')} ({label})."

    def apply_config(self):
        """Relit la configuration et (re)installe la tache planifiee."""
        self.stop_scheduler()
        if APSCHEDULER_AVAILABLE and self.scheduler is None:
            self.scheduler = BackgroundScheduler()
        return self.start_scheduler()
    
    @staticmethod
    def _day_to_number(day_name):
        """Convertit le nom du jour au numéro (lun=0, dim=6)"""
        days = {name: index for index, name in enumerate(ScanScheduler.DAYS)}
        key = day_name.lower()
        if key not in days:
            # Auparavant un nom invalide devenait lundi sans prevenir.
            raise ValueError(f"Jour de semaine inconnu : {day_name!r}")
        return str(days[key])

# ========== MULTI-SCAN QUEUE CLASS ==========
class ScanQueue:
    """Gère une file d'attente de scans parallèles - RÉEL (ThreadPoolExecutor)"""
    
    def __init__(self, config_manager):
        self.config = config_manager
        self.queue_cfg = self.config.get_multi_scan_config()
        self.pending_scans = []
        self.running_scans = {}
        self.completed_scans = []
        self.max_concurrent = self.queue_cfg.get('max_concurrent', 3)
        self.lock = threading.Lock()
    
    def add_scan(self, target, scan_type, scan_id=None):
        """Ajoute un scan à la file d'attente"""
        if not scan_id:
            scan_id = f"scan_{int(time.time())}_{random.randint(1000, 9999)}"
        
        scan_item = {
            'id': scan_id,
            'target': target,
            'type': scan_type,
            'status': 'PENDING',
            'added_at': datetime.now(),
            'started_at': None,
            'completed_at': None
        }
        
        with self.lock:
            self.pending_scans.append(scan_item)
            print(f"[QUEUE] Scan ajouté:{scan_id} ({target})")
        
        return scan_id
    
    def get_status(self):
        """Retourne le statut actuel de la queue"""
        with self.lock:
            return {
                'pending': len(self.pending_scans),
                'running': len(self.running_scans),
                'completed': len(self.completed_scans),
                'pending_scans': self.pending_scans,
                'running_scans': list(self.running_scans.values()),
                'completed_scans': self.completed_scans[-10:]  # Derniers 10
            }
    
    def get_queue_for_dashboard(self):
        """Format pour affichage dans le dashboard"""
        status = self.get_status()
        return {
            'total_pending': status['pending'],
            'total_running': status['running'],
            'total_completed': status['completed'],
            'progress': f"{status['completed']}/{status['pending']+status['running']+status['completed']}",
            'list': status['running_scans']
        }

class AutoInstaller:
    """Installateur automatique - mode OFFLINE (fichiers embarqués dans l'exe)."""
    
    def __init__(self):
        # On pointe vers les fichiers INCLUS (via resource_path)
        self.nmap_exe = resource_path("nmap-7.98-setup.exe")
        self.docker_exe = resource_path("Docker Desktop Installer.exe")

    def is_admin(self):
        """Vérifie les droits administrateur (Requis pour les installations)."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    def check_tool_installed(self, check_cmd):
        """Vérifie si un outil est présent dans le PATH."""
        try:
            # SÉCURITÉ: Ne JAMAIS utiliser shell=True avec check_cmd
            cmd_list = shlex.split(check_cmd) if isinstance(check_cmd, str) else check_cmd
            subprocess.run(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                         timeout=5, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired, ValueError):
            return False

    def diagnose_nmap(self):
        """Diagnostic complet de NMAP - Vérifie installation et fonctionnalité"""
        self.log("\n" + "="*70, tag="title")
        self.log("[NMAP DIAGNOSTIC] Vérification complète du système...", tag="info")
        self.log("="*70, tag="title")
        
        # 1. VÉRIFIER DISPONIBILITÉ NMAP
        nmap_available = False
        nmap_version = "UNKNOWN"
        
        try:
            result = subprocess.run(["nmap", "--version"], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE, 
                                   timeout=5, text=True)
            if result.returncode == 0:
                nmap_available = True
                nmap_version = result.stdout.split('\n')[0]
                self.log(f"NMAP détecté:{nmap_version}", tag="ok")
            else:
                self.log(f"NMAP retourné une erreur:{result.stderr}", tag="warn")
        except FileNotFoundError:
            self.log("NMAP introuvable dans le PATH", tag="warn")
        except subprocess.TimeoutExpired:
            self.log("NMAP timeout (ne répond pas après 5s)", tag="warn")
        except Exception as e:
            self.log(f"Erreur lors de la vérification:{e}", tag="warn")
        
        # 2. VÉRIFIER CHEMINS CONNUS
        self.log("\n Vérification des chemins d'installation courants...", tag="info")
        paths_to_check = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            r"C:\nmap\nmap.exe",
        ]
        
        found_paths = []
        for path in paths_to_check:
            if os.path.exists(path):
                found_paths.append(path)
                self.log(f"   Trouvé:{path}", tag="ok")
            else:
                self.log(f"   Pas trouvé:{path}", tag="warn")
        
        # 3. VÉRIFIER PYTHON-NMAP
        self.log("\n Vérification du module python-nmap...", tag="info")
        try:
            import nmap as nmap_module
            self.log(f"Module python-nmap disponible", tag="ok")
        except ImportError:
            self.log("Module python-nmap NON INSTALLÉ (pip install python-nmap)", tag="warn")
        
        # 4. VÉRIFIER L'INITIALISEUR DE NMAP
        self.log("\n Vérification de l'initialiseur interne...", tag="info")
        if self.nm is not None:
            self.log("NMAP initialisé et prêt", tag="ok")
            self.nmap_status = "ONLINE"
        else:
            self.log("NMAP non initialisé - Tentative de ré-initialisation...", tag="warn")
            self.init_nmap()
            if self.nm is not None:
                self.log("NMAP initialisé après retry", tag="ok")
                self.nmap_status = "ONLINE"
            else:
                self.log("IMPOSSIBLE D'INITIALISER NMAP", tag="warn")
                self.nmap_status = "OFFLINE"
        
        # 5. RÉSUMÉ ET RECOMMANDATIONS
        self.log("\n" + "="*70, tag="title")
        self.log("[DIAGNOSTIC SUMMARY]", tag="title")
        self.log("="*70, tag="title")
        
        if nmap_available and self.nm is not None:
            self.log("SYSTÈME OPÉRATIONNEL - Tous les tests passés", tag="ok")
            self.log(f"   Version NMAP: {nmap_version}", tag="ok")
            self.log(f"   Chemins trouvés: {len(found_paths)}", tag="ok")
            self.log(f"   Module Python-Nmap: OK", tag="ok")
        else:
            self.log("PROBLÈMES DÉTECTÉS - Actions recommandées:", tag="warn")
            
            if not nmap_available:
                self.log("\n 1⃣ NMAP non trouvé:", tag="warn")
                self.log("     → Télécharger: https://nmap.org/download.html", tag="info")
                self.log("     → Windows: Exécuter l'installateur .exe", tag="info")
                self.log("     → Installer avec chemin par défaut (C:\\Program Files)", tag="info")
                self.log("     → Redémarrer Windows après installation", tag="info")
            
            if self.nm is None:
                self.log("\n 2⃣ Module Python-Nmap non importable:", tag="warn")
                self.log("     → Exécuter: pip install python-nmap", tag="info")
                self.log("     → Ou depuis le terminal PowerShell (admin)", tag="info")
        
        self.log("\n" + "="*70 + "\n", tag="title")


    def install_nmap(self):
        """Installe Nmap depuis le fichier embarqué."""
        print("\n[!] NMAP MANQUANT. Lancement de l'installation EMBARQUÉE...")
        
        if os.path.exists(self.nmap_exe):
            print(f"   [INSTALL] Fichier trouvé : {self.nmap_exe}")
            try:
                # /S = Silent install
                subprocess.run([self.nmap_exe, "/S"], check=True)
                print("   [SUCCESS] Nmap installé.")
                os.environ["PATH"] += r";C:\Program Files (x86)\Nmap"
            except Exception as e:
                print(f"   [ERREUR] Installation échouée : {e}")
        else:
            print(f"   [ERREUR] L'installateur {self.nmap_exe} est introuvable dans le paquet !")

    def install_docker(self):
        """Installe Docker Desktop depuis le fichier embarqué."""
        print("\n[!] DOCKER MANQUANT. Lancement de l'installation EMBARQUÉE...")
        
        if os.path.exists(self.docker_exe):
            print(f"   [INSTALL] Fichier trouvé : {self.docker_exe}")
            try:
                subprocess.run([self.docker_exe, "install", "--quiet"], check=True)
                print("   [SUCCESS] Docker installé (Reboot requis).")
            except Exception as e:
                print(f"   [ERREUR] Installation échouée : {e}")
        else:
            print(f"   [ERREUR] L'installateur {self.docker_exe} est introuvable dans le paquet !")

    def run_check_sequence(self):
        """Verifie les outils externes et rapporte ce qui manque.

        Cette sequence ne doit JAMAIS empecher l application de demarrer :
        elle exigeait auparavant les droits administrateur puis appelait
        sys.exit(1), ce qui rendait `python sipa.py` inutilisable pour
        quiconque lancait la commande documentee dans un terminal normal.
        Nmap absent n est pas fatal (l interface s ouvre et signale le
        probleme), et Docker ne sert qu a OpenVAS. On informe, on n impose
        rien, et on n installe rien sans que l utilisateur le demande.
        """
        print("\n" + "="*70)
        print("[BOOTSTRAP] Verification des outils externes")
        print("="*70)

        nmap_ok = self.check_tool_installed(["nmap", "--version"])
        docker_ok = self.check_tool_installed(["docker", "--version"])

        print("  Nmap   : %s" % ("present" if nmap_ok else "ABSENT"))
        print("  Docker : %s" % ("present" if docker_ok
                                 else "absent (utile a OpenVAS uniquement)"))

        if not nmap_ok:
            print("\n  [!] Nmap est necessaire aux scans reseau.")
            print("      Installation : https://nmap.org/download.html")
            print("      Verifiez ensuite que 'nmap' repond dans un terminal.")
            if not self.is_admin():
                print("      (installer Nmap demande des droits administrateur)")

        print("="*70 + "\n")
        return nmap_ok
        time.sleep(2)

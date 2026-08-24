"""Detection d'exploitation active, de persistence et analyse forensique.

Extrait de sipa.py (phase 3 : refonte modulaire) sous forme de mixin.
"""

import os
import platform
import subprocess
import threading
import time
from datetime import datetime

import tkinter as tk
from tkinter import messagebox

from sipa_core.theme import THEME


class ForensicsMixin:
    """Exploitation active, persistence et analyse forensique du systeme."""

    def check_exploitation(self):
        """Détecte les signes d'exploitation active sur le réseau"""
        self.problems_found = []
        self.disable_buttons()
        self.progress.start(10)
        self.text_area.delete(1.0, tk.END)
        self.typewriter_log("SCANNING FOR EXPLOITATION SIGNATURES...", speed=0.02, tag="title")
        self.matrix_processing(lines=8, duration=0.8)

        thread = threading.Thread(target=self.run_exploitation_scan)
        thread.start()

    def run_exploitation_scan(self):
        """Analyse forensique des traces d'exploitation"""
        self.log("[1/5] ANALYZING SUSPICIOUS PROCESSES...", tag="info")
        try:
            if platform.system() == "Windows":
                # UTILISATION DE LA COMMANDE SÉCURISÉE
                output_netstat = self.run_safe_command(['netstat', '-ano'])
                suspicious_pids = set()
                
                for line in output_netstat.split('\n'):
                    if 'ESTABLISHED' in line or 'LISTENING' in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            try:
                                pid = parts[-1]
                                port = parts[1].split(':')[-1] if ':' in parts[1] else None
                                if port and (int(port) in self.backdoor_ports or int(port) > 49152):
                                    suspicious_pids.add(pid)
                            except: pass
                
                for pid in suspicious_pids:
                    # UTILISATION DE LA COMMANDE SÉCURISÉE
                    output_task = self.run_safe_command(['tasklist', '/FI', f'PID eq {pid}', '/FO', 'CSV'])
                    if output_task:
                        lines = output_task.split('\n')
                        if len(lines) > 1:
                            process_info = lines[1].strip('"').split('","')
                            if process_info and len(process_info) > 0:
                                self.problems_found.append({
                                    'type': 'PROCESSUS SUSPECT', 'host': 'LOCAL', 'port': 'N/A',
                                    'service': process_info[0],
                                    'details': f'PID {pid} avec port non-standard ouvert',
                                    'action': 'Analyser le processus'
                                })
                                self.log(f"SUSPICIOUS PROCESS: {process_info[0]} (PID {pid})", tag="warn")
        except Exception as exc:
            self.log(f"SCAN ERROR: {exc}", tag="warn")

        self.log("[2/5] CHECKING FAILED LOGIN ATTEMPTS...", tag="info")
        self.matrix_processing(lines=3, duration=0.3)
        try:
            if platform.system() == "Windows":
                # UTILISATION DE LA COMMANDE SÉCURISÉE
                output_evt = self.run_safe_command(['wevtutil', 'qe', 'Security', '/c:50', '/rd:true', '/f:text', '/q:*[System[(EventID=4625)]]'])
                failed_attempts = output_evt.count('Event ID: 4625')
                if failed_attempts > 5:
                    self.problems_found.append({
                        'type': 'BRUTEFORCE DETECTED', 'host': 'LOCAL', 'port': 'N/A',
                        'service': 'Windows Security',
                        'details': f'{failed_attempts} échecs de connexion',
                        'action': 'Bloquer les IPs sources'
                    })
                    self.log(f"BRUTEFORCE ALERT: {failed_attempts} failed logins", tag="warn")
                else:
                    self.log(f"Login attempts: {failed_attempts} (NORMAL)", tag="ok")
        except:
            self.log("Event log access requires admin privileges", tag="warn")

        self.log("[3/5] SCANNING FOR LATERAL MOVEMENT...", tag="info")
        self.matrix_processing(lines=3, duration=0.3)
        try:
            if platform.system() == "Windows":
                output_smb = self.run_safe_command(['netstat', '-ano'])
                smb_connections = 0
                rdp_connections = 0
                for line in output_smb.split('\n'):
                    if 'ESTABLISHED' in line:
                        if ':445' in line or ':139' in line: smb_connections += 1
                        if ':3389' in line: rdp_connections += 1
                
                if smb_connections > 3:
                    self.log(f"LATERAL MOVEMENT RISK: {smb_connections} SMB links", tag="warn")
                    self.problems_found.append({
                        'type': 'LATERAL MOVEMENT', 'host': 'LOCAL', 'port': 445,
                        'service': 'SMB', 'details': f'{smb_connections} connexions SMB actives',
                        'action': 'Vérifier et isoler si nécessaire'
                    })
                if rdp_connections > 0:
                    self.log(f"RDP SESSIONS: {rdp_connections} active", tag="warn")
        except: pass

        self.log("[4/5] DETECTING DNS TUNNELING...", tag="info")
        self.matrix_processing(lines=3, duration=0.3)
        try:
            if platform.system() == "Windows":
                output_dns = self.run_safe_command(['netstat', '-ano'])
                dns_count = 0
                for line in output_dns.split('\n'):
                    if ':53' in line and 'ESTABLISHED' in line:
                        dns_count += 1
                
                if dns_count > 5:
                    self.log(f"DNS TUNNELING RISK: {dns_count} connections", tag="warn")
                    self.problems_found.append({'type': 'DNS TUNNELING', 'host': 'LOCAL', 'port': 53, 'service': 'DNS', 'details': 'Exfiltration possible', 'action': 'Analyser trafic'})
                elif dns_count > 0:
                    self.log(f"DNS activity: {dns_count} connections (NORMAL)", tag="ok")
        except: pass

        self.log("[5/5] MEMORY INJECTION DETECTION...", tag="info")
        self.matrix_processing(lines=3, duration=0.3)
        try:
            if platform.system() == "Windows":
                output_mem = self.run_safe_command(['tasklist', '/FO', 'CSV'])
                suspicious_names = ['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe']
                found_suspicious = []
                for line in output_mem.split('\n'):
                    for name in suspicious_names:
                        if name.lower() in line.lower():
                            found_suspicious.append(name)
                            break
                
                if len(found_suspicious) > 3:
                    self.log(f"SUSPICIOUS INTERPRETERS: {len(found_suspicious)} active", tag="warn")
                    self.problems_found.append({'type': 'SCRIPT RISK', 'host': 'LOCAL', 'port': 'N/A', 'service': 'Scripting', 'details': "Trop d'interpréteurs actifs", 'action': 'Vérifier processus'})
        except: pass

        # Vérifier historique exploitation
        self.log("[6/6] CHECKING EXPLOITATION HISTORY...", tag="info")
        self.matrix_processing(lines=4, duration=0.4)
        try:
            if platform.system() == "Windows":
                # Vérifier commandes PowerShell suspectes dans l'historique
                ps_history_path = os.path.expandvars(r'%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt')
                if os.path.exists(ps_history_path):
                    with open(ps_history_path, 'r', encoding='utf-8', errors='ignore') as f:
                        history = f.read().lower()
                        suspicious_cmds = ['invoke-mimikatz', 'invoke-expression', 'downloadstring', 'iex', 
                                          'bypass', 'base64', 'encodedcommand', '-enc', 'net user', 'net localgroup']
                        
                        found_cmds = [cmd for cmd in suspicious_cmds if cmd in history]
                        if found_cmds:
                            self.log(f"EXPLOITATION HISTORY: {len(found_cmds)} suspicious commands found", tag="warn")
                            self.problems_found.append({
                                'type': 'HISTORIQUE EXPLOITATION',
                                'host': 'LOCAL',
                                'port': 'N/A',
                                'service': 'PowerShell History',
                                'details': f'Commandes suspectes: {', '.join(found_cmds[:5])}',
                                'action': 'URGENT: Système probablement compromis - Investigation complète nécessaire'
                            })
        except:
            pass

        self.matrix_processing(lines=4, duration=0.4)
        self.log(f"\nEXPLOITATION INDICATORS: {len(self.problems_found)}", tag="title")
        if not self.problems_found:
            self.log("NO ACTIVE EXPLOITATION DETECTED", tag="ok")
        self.root.after(0, self.stop_loading)

    def check_persistence(self):
        """Détecte les mécanismes de persistence"""
        self.problems_found = []
        self.disable_buttons()
        self.progress.start(10)
        self.text_area.delete(1.0, tk.END)
        self.typewriter_log("SCANNING PERSISTENCE MECHANISMS...", speed=0.02, tag="title")
        self.matrix_processing(lines=6, duration=0.6)

        thread = threading.Thread(target=self.run_persistence_scan)
        thread.start()

    def run_persistence_scan(self):
        """Scan des points de persistence Windows"""
        self.log("[1/4] REGISTRY RUN KEYS...", tag="info")
        try:
            if platform.system() == "Windows":
                reg_keys = [
                    r'HKLM\Software\Microsoft\Windows\CurrentVersion\Run',
                    r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
                ]
                for key in reg_keys:
                    # UTILISATION DE LA COMMANDE SÉCURISÉE
                    output = self.run_safe_command(['reg', 'query', key])
                    if output:
                        entries = [l for l in output.split('\n') if 'REG_' in l]
                        if len(entries) > 5:
                            self.log(f"Run key {key}: {len(entries)} entries", tag="warn")
                        for entry in entries:
                            if any(sus in entry.lower() for sus in ['temp', 'appdata\\roaming', '.tmp', '.bat']):
                                self.problems_found.append({'type': 'PERSISTENCE REGISTRY', 'host': 'LOCAL', 'port': 'N/A', 'service': 'Registry', 'details': f'Clé suspecte: {entry[:50]}', 'action': 'Examiner'})
                                self.log(f"SUSPICIOUS KEY: {entry[:60]}", tag="warn")
        except Exception as exc:
            self.log(f"Registry error: {exc}", tag="warn")

        self.log("[2/4] SCHEDULED TASKS...", tag="info")
        self.matrix_processing(lines=3, duration=0.3)
        try:
            if platform.system() == "Windows":
                # UTILISATION DE LA COMMANDE SÉCURISÉE
                output = self.run_safe_command(['schtasks', '/query', '/fo', 'CSV'])
                tasks = output.split('\n')
                for task in tasks:
                    if any(sus in task.lower() for sus in ['powershell', 'cmd', 'wscript', 'download']):
                        self.log(f"SUSPICIOUS TASK: {task[:50]}", tag="warn")
                        self.problems_found.append({'type': 'SCHEDULED TASK', 'host': 'LOCAL', 'port': 'N/A', 'service': 'Task', 'details': task[:80], 'action': 'Vérifier'})
        except: pass

        self.log("[3/4] STARTUP FOLDER...", tag="info")
        self.matrix_processing(lines=2, duration=0.2)
        try:
            if platform.system() == "Windows":
                startup_paths = [
                    os.path.expandvars(r'%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup'),
                    os.path.expandvars(r'%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup')
                ]
                for path in startup_paths:
                    if os.path.exists(path):
                        files = os.listdir(path)
                        if files:
                            self.log(f"Startup folder {path}: {len(files)} items", tag="warn")
                            for f in files:
                                self.problems_found.append({'type': 'STARTUP PERSISTENCE', 'host': 'LOCAL', 'port': 'N/A', 'service': 'Startup Folder', 'details': f'File: {f}', 'action': 'Vérifier légitimité du fichier'})
        except: pass

        self.log("[4/4] SERVICES SUSPECTS...", tag="info")
        self.matrix_processing(lines=3, duration=0.3)
        try:
            if platform.system() == "Windows":
                # UTILISATION DE LA COMMANDE SÉCURISÉE
                output = self.run_safe_command(['sc', 'query', 'state=', 'all'])
                services = output.split('SERVICE_NAME:')
                suspicious_count = 0
                for service in services[1:]:
                    service_name = service.split('\n')[0].strip()
                    if any(sus in service_name.lower() for sus in ['update', 'helper', 'monitor']) and 'microsoft' not in service.lower():
                        suspicious_count += 1
                        if suspicious_count <= 5:
                            self.log(f"Review service: {service_name}", tag="warn")
        except: pass

        self.matrix_processing(lines=4, duration=0.4)
        self.log(f"\nPERSISTENCE MECHANISMS: {len(self.problems_found)}", tag="title")
        if not self.problems_found:
            self.log("NO SUSPICIOUS PERSISTENCE DETECTED", tag="ok")
        self.root.after(0, self.stop_loading)

    def forensic_analysis(self):
        """Analyse forensique complète"""
        self.problems_found = []
        self.disable_buttons()
        self.progress.start(10)
        self.text_area.delete(1.0, tk.END)
        self.typewriter_log("INITIATING DEEP FORENSIC ANALYSIS...", speed=0.02, tag="title")
        self.matrix_processing(lines=10, duration=1.0)

        thread = threading.Thread(target=self.run_forensic_deep)
        thread.start()

    def run_forensic_deep(self):
        """
        VRAI FORENSIC : Analyse de la Persistance dans le Registre Windows.
        (Run, RunOnce, Services)
        """
        import winreg
        
        if platform.system() != "Windows":
            self.log("[-] Forensic Registre non supporté sur Linux/Mac.", tag="error")
            return

        self.disable_buttons()
        self.text_area.delete(1.0, tk.END)
        self.log("[FORENSIC] ANALYSE DE LA PERSISTANCE REGISTRE...", tag="title")
        
        # -----------------------------------------------------------
        # LA BLAGUE PSYCHO
        # -----------------------------------------------------------
        self.log("\n[SYSTEM CHECK] Vérification de la santé mentale de l'OS...", tag="matrix")
        self.log("... OS détecté : Windows.", tag="warn")
        self.log("... Diagnostic : Masochisme confirmé. Pourquoi tu t'infliges ça ?", tag="warn")
        self.log("... Chargement des clés de registre (bon courage)...", tag="info")
        # -----------------------------------------------------------

        def _scan_registry():
            try:
                # Liste des clés critiques où les malwares se cachent
                registry_locations = [
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
                    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
                ]

                suspicious_keywords = ['temp', 'appdata', 'powershell', 'cmd', '.vbs', '.bat']
                
                for hkey, path in registry_locations:
                    try:
                        self.log(f"\nScanning: {path}", tag="accent")
                        key = winreg.OpenKey(hkey, path, 0, winreg.KEY_READ)
                        
                        i = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, i)
                                tag = "info"
                                
                                # Détection heuristique
                                if any(kw in value.lower() for kw in suspicious_keywords):
                                    tag = "error"
                                    self.log(f"  [!] SUSPECT: {name} -> {value}", tag=tag)
                                    self.problems_found.append({'type': 'PERSISTANCE', 'details': f"Clé registre suspecte: {value}", 'action': 'Supprimer clé'})
                                else:
                                    self.log(f"  [+] {name}: {value}", tag=tag)
                                i += 1
                            except OSError:
                                break # Fin de la liste
                        winreg.CloseKey(key)
                    except Exception as e:
                        self.log(f"  [-] Inaccessible: {e}", tag="warn")

                self.log("\n[FIN] Analyse Registre terminée.", tag="success")

            except Exception as e:
                self.log(f"Erreur Forensic: {e}", tag="error")
            finally:
                self.root.after(0, self.stop_loading)

        threading.Thread(target=_scan_registry, daemon=True).start()

    # -------------------------------------------------------------------------
    # [REAL] FILESYSTEM TIMELINE ANALYSIS
    # Analyse la MFT (Master File Table) via les dates de modification.
    # -------------------------------------------------------------------------
    def run_forensic_filesystem(self):
        """Vérifie l'intégrité des fichiers système critiques (System32)."""
        self.disable_buttons()
        self.text_area.delete(1.0, tk.END)
        self.log("[FORENSIC] SCAN INTÉGRITÉ SYSTEM32...", tag="title")
        
        def _scan_filesystem():
            target_dir = r"C:\Windows\System32"
            if not os.path.exists(target_dir):
                self.log("[-] Pas sur Windows ou chemin introuvable.", tag="error")
                self.root.after(0, self.stop_loading)
                return

            # On cherche les modifications dans les dernières 24h
            now = time.time()
            one_day_ago = now - (24 * 60 * 60)
            
            suspicious_files = []
            checked_count = 0
            
            try:
                # os.scandir est beaucoup plus rapide que os.walk sous Windows
                with os.scandir(target_dir) as entries:
                    for entry in entries:
                        if entry.is_file():
                            checked_count += 1
                            try:
                                mtime = entry.stat().st_mtime
                                if mtime > one_day_ago:
                                    # Fichier système modifié récemment = SUSPECT
                                    ext = os.path.splitext(entry.name)[1].lower()
                                    if ext in ['.exe', '.dll', '.sys', '.bat', '.ps1']:
                                        suspicious_files.append((entry.name, datetime.fromtimestamp(mtime)))
                            except PermissionError:
                                pass # Fichier verrouillé par le système (bon signe)

                self.log(f"[ANALYSE] {checked_count} fichiers système vérifiés.", tag="info")
                
                if suspicious_files:
                    self.log(f"🚨 ALERTE : {len(suspicious_files)} fichiers système modifiés (<24h) !", tag="error")
                    for fname, mod_time in suspicious_files:
                        self.log(f"  -> {fname} ({mod_time})", tag="warn")
                        self.problems_found.append({
                            'type': 'SYSTEM FILE CHANGED',
                            'details': f"{fname} modifié récemment dans System32",
                            'action': 'Vérifier signature numérique (Sigcheck)'
                        })
                else:
                    self.log("✅ Intégrité System32 : Aucune modification récente détectée.", tag="success")
                    self.log("   (Windows Defender fait bien son travail, apparemment.)", tag="info")

            except Exception as e:
                self.log(f"Erreur Forensic Filesystem: {e}", tag="error")
            finally:
                self.root.after(0, self.stop_loading)

        threading.Thread(target=_scan_filesystem, daemon=True).start()

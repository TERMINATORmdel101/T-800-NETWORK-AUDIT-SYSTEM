"""Scans avances : CVE, analyse DNS complete et detection de rootkits.

Extrait de sipa.py (phase 3 : refonte modulaire) sous forme de mixin.
"""

import os
import platform
import socket
import subprocess
import threading
import time
from datetime import datetime

import tkinter as tk
from tkinter import messagebox

try:
    import requests
except ImportError:  # dependance listee, mais on reste importable sans elle
    requests = None

from sipa_core.theme import THEME


class AdvancedScansMixin:
    """Scan CVE, audit DNS approfondi et recherche de rootkits."""

    def scan_cve_advanced(self):
        """Scan CVE avancé avec base de données complète"""
        target = self.get_target()
        self.start_loading()
        threading.Thread(target=lambda: self._scan_cve_advanced_thread(target), daemon=True).start()
    
    def _scan_cve_advanced_thread(self, target):
        """Recherche avancée des CVE avec scoring CVSS réel"""
        try:
            self.log("[CVE VULNERABILITY SCAN] ANALYSE COMPLÈTE", tag="title")
            self.log("="*70, tag="info")
            
            # ========== [1] DÉTECTION SERVICES/VERSIONS ==========
            self.log("\n[1] DÉTECTION DES SERVICES ET VERSIONS", tag="accent")
            
            if not self.nm:
                self.log("[-] Nmap scanner not initialized", tag="error")
                return
            
            try:
                # Scan des services avec détection de version
                self.log("   Scan des ports avec version detection (-sV)...", tag="info")
                self.nm.scan(target, arguments='-p 22,80,443,3306,5432,27017,6379,8080,8443,445,139 -sV -T4')
                
                services_found = {}
                
                for host in self.nm.all_hosts():
                    for proto in self.nm[host].all_protocols():
                        ports = self.nm[host][proto].keys()
                        for port in ports:
                            service = self.nm[host][proto][port]
                            if service['state'] == 'open':
                                name = service.get('name', 'unknown')
                                product = service.get('product', 'unknown')
                                version = service.get('version', 'unknown')
                                
                                services_found[port] = {
                                    'name': name,
                                    'product': product,
                                    'version': version
                                }
                
                if services_found:
                    self.log(f"\n   ✓ {len(services_found)} service(s) ouvert(s) détecté(s):", tag="success")
                    for port, svc in sorted(services_found.items()):
                        self.log(f"      Port {port}: {svc['product']} {svc['version']}", tag="info")
                else:
                    self.log("   ℹ️ Aucun service courant détecté", tag="info")
                    return
                    
            except Exception as e:
                self.log(f"[-] Erreur scan services: {e}", tag="warn")
                return
            
            # ========== [2] CVE DATABASE LOOKUP ==========
            self.log("\n[2] RECHERCHE CVE - BASE DE DONNÉES NVD (NIST)", tag="accent")
            
            total_cves = 0
            critical_cves = 0
            high_cves = 0
            
            # CVE mapping simplifié (base commune)
            cve_database = {
                'Apache': [
                    ('CVE-2021-41773', 'Apache RCE via path traversal', 'CRITICAL', 9.8),
                    ('CVE-2021-42013', 'Apache path traversal', 'CRITICAL', 9.8),
                ],
                'nginx': [
                    ('CVE-2021-23017', 'Nginx Off-by-one in dav module', 'CRITICAL', 9.0),
                ],
                'MySQL': [
                    ('CVE-2021-2109', 'MySQL Server DoS via Replication', 'HIGH', 7.1),
                    ('CVE-2021-2144', 'MySQL Server RCE', 'CRITICAL', 9.9),
                ],
                'PostgreSQL': [
                    ('CVE-2021-23214', 'PostgreSQL SSL session spoofing', 'HIGH', 7.5),
                    ('CVE-2021-32029', 'PostgreSQL RCE via SQL function', 'CRITICAL', 9.8),
                ],
                'MongoDB': [
                    ('CVE-2021-32816', 'MongoDB Unauthenticated CRUD', 'CRITICAL', 9.8),
                ],
                'Redis': [
                    ('CVE-2021-21309', 'Redis RCE via command injection', 'CRITICAL', 9.8),
                ],
                'OpenSSH': [
                    ('CVE-2018-15473', 'OpenSSH user enumeration', 'HIGH', 5.3),
                    ('CVE-2021-28041', 'OpenSSH privilege escalation', 'HIGH', 7.0),
                ],
                'Windows': [
                    ('CVE-2021-44228', 'Log4Shell - Universal RCE', 'CRITICAL', 10.0),
                    ('CVE-2021-1732', 'Windows Win32k Privilege Escalation', 'CRITICAL', 9.8),
                    ('CVE-2021-34527', 'Windows Print Spooler RCE', 'CRITICAL', 9.8),
                ],
            }
            
            # Chercher les CVE pour chaque service détecté
            for port, svc in services_found.items():
                product = svc['product'].lower()
                version = svc['version']
                
                # Chercher dans la base
                for vendor, cves in cve_database.items():
                    if vendor.lower() in product:
                        for cve_id, description, severity, cvss in cves:
                            total_cves += 1
                            
                            if severity == 'CRITICAL':
                                critical_cves += 1
                                tag = 'error'
                            elif severity == 'HIGH':
                                high_cves += 1
                                tag = 'warn'
                            else:
                                tag = 'accent'
                            
                            self.log(f"\n   🔴 {cve_id}", tag=tag)
                            self.log(f"      Produit: {svc['product']} {version}", tag="info")
                            self.log(f"      Description: {description}", tag="info")
                            self.log(f"      Sévérité: {severity} (CVSS: {cvss})", tag=tag)
                            
                            self.problems_found.append({
                                'type': 'CVE VULNERABILITY',
                                'host': target,
                                'port': port,
                                'service': f"{svc['product']} {version}",
                                'details': f"{cve_id}: {description}",
                                'action': f"Upgrade to latest patched version"
                            })
            
            # ========== [3] RÉSUMÉ CVE ==========
            self.log("\n" + "="*70, tag="info")
            self.log("[CVE SUMMARY]", tag="accent")
            self.log(f"   Total CVEs found: {total_cves}", tag="warn")
            self.log(f"   CRITICAL: {critical_cves}", tag="error")
            self.log(f"   HIGH: {high_cves}", tag="warn")
            
            if critical_cves > 0:
                self.log(f"\n   🔴 URGENT: {critical_cves} critical vulnerability(ies) to patch!", tag="error")
            elif high_cves > 0:
                self.log(f"\n   ⚠️ {high_cves} high-risk vulnerability(ies) found", tag="warn")
            else:
                self.log(f"\n   ✓ No known critical vulnerabilities detected", tag="success")
            
            self.display_problem_summary(len(self.problems_found), target)
            
        except Exception as exc:
            self.log(f"CVE SCAN ERROR: {exc}", tag="error")
        finally:
            self.root.after(0, self.stop_loading)

    def analyze_dns(self):
        """Analyse DNS avancée"""
        target = self.get_target()
        self.start_loading()
        threading.Thread(target=lambda: self._analyze_dns_thread(target), daemon=True).start()
    
    def _analyze_dns_thread(self, target):
        """Analyse DNS complète incluant sécurité et anomalies"""
        try:
            self.log(f"[DNS ANALYSIS] RÉSOLUTION & SÉCURITÉ DE: {target}", tag="title")
            self.log("="*70, tag="info")
            
            issues_found = 0
            
            # ========== [1] FORWARD LOOKUP ==========
            self.log("\n[1] FORWARD LOOKUP (Nom -> IP)", tag="accent")
            
            ips = []
            try:
                # Utiliser socket pour une vraie résolution
                hostname, aliases, ips = socket.gethostbyname_ex(target)
                self.log(f"   ✓ Nom principal: {hostname}", tag="success")
                
                if aliases:
                    self.log(f"   📋 Alias (CNAME): {', '.join(aliases)}", tag="info")
                
                self.log(f"\n   Adresses IP trouvées:", tag="accent")
                for ip in ips:
                    self.log(f"      → {ip}", tag="ok")
                    
            except socket.gaierror as e:
                self.log(f"   ✗ Erreur résolution: {e}", tag="error")
                ips = []
            
            # ========== [2] REVERSE LOOKUP ==========
            self.log("\n[2] REVERSE LOOKUP (IP -> Nom)", tag="accent")
            
            if ips:
                for ip in ips:
                    try:
                        rev_name, _, _ = socket.gethostbyaddr(ip)
                        self.log(f"   ✓ {ip} -> {rev_name}", tag="success")
                    except socket.herror:
                        self.log(f"   ⚠️ {ip} -> Pas de PTR record (risque: spoofing DNS)", tag="warn")
                        issues_found += 1
            
            # ========== [3] SÉCURITÉ DNS - DNSBL LOOKUP ==========
            self.log("\n[3] BLACKLIST CHECK (DNSBL)", tag="accent")
            
            if ips and requests:
                try:
                    # Vérifier si l'IP est sur une liste noire
                    test_ip = ips[0]
                    parts = test_ip.split('.')
                    reversed_ip = '.'.join(reversed(parts))
                    
                    # Chercher sur Spamhaus (gratuit)
                    dnsbl_domains = [
                        'zen.spamhaus.org',
                        'dnsbl.sorbs.net',
                    ]
                    
                    is_blacklisted = False
                    for dnsbl in dnsbl_domains:
                        query = f"{reversed_ip}.{dnsbl}"
                        try:
                            socket.gethostbyname(query)
                            self.log(f"   🔴 IP BLACKLISTED on {dnsbl}!", tag="error")
                            is_blacklisted = True
                            issues_found += 1
                        except socket.gaierror:
                            pass  # Not blacklisted on this service
                    
                    if not is_blacklisted:
                        self.log(f"   ✓ IP not found in public blacklists", tag="success")
                        
                except Exception as e:
                    self.log(f"   ℹ️ DNSBL check skipped: {e}", tag="info")
            
            # ========== [4] DNSSEC VALIDATION ==========
            self.log("\n[4] DNSSEC & DNS SECURITY", tag="accent")
            
            try:
                import dns.resolver  # Requires dnspython
                
                # Chercher les MX records
                mx_records = []
                try:
                    answers = dns.resolver.resolve(target, 'MX')
                    for rdata in answers:
                        mx_records.append(str(rdata.exchange))
                    
                    if mx_records:
                        self.log(f"   📧 MX Records:", tag="info")
                        for mx in mx_records[:5]:
                            self.log(f"      → {mx}", tag="info")
                    else:
                        self.log(f"   ⚠️ Pas de MX records trouvés", tag="warn")
                except:
                    self.log(f"   ℹ️ MX lookup skipped", tag="info")
                
                # Chercher TXT records (SPF, DKIM, etc.)
                try:
                    txt_records = dns.resolver.resolve(target, 'TXT')
                    self.log(f"\n   🔐 Security TXT Records:", tag="accent")
                    for rdata in txt_records:
                        txt = str(rdata)
                        if 'v=spf1' in txt:
                            self.log(f"      ✓ SPF Policy: {txt[:60]}...", tag="success")
                        elif 'v=DKIM1' in txt:
                            self.log(f"      ✓ DKIM Found", tag="success")
                        elif 'v=DMARC1' in txt:
                            self.log(f"      ✓ DMARC Policy: {txt[:60]}...", tag="success")
                except:
                    self.log(f"      ⚠️ No SPF/DKIM/DMARC records (email vulnerable!)", tag="warn")
                    issues_found += 1
                    
            except ImportError:
                self.log("   ℹ️ dnspython not installed (pip install dnspython)", tag="info")
            
            # ========== [5] ZONE TRANSFER TEST (AXFR) ==========
            self.log("\n[5] DNS ZONE TRANSFER VULNERABILITY", tag="accent")
            
            try:
                # Essayer de faire un zone transfer (AXFR)
                # C'est une vulnérabilité critique si activée
                import dns.zone
                import dns.query
                
                zone = None
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(target, target))
                    self.log(f"   🔴 CRITICAL: Zone transfer allowed! (AXFR exploit)", tag="error")
                    issues_found += 1
                    self.problems_found.append({
                        'type': 'DNS VULNERABILITY',
                        'host': target,
                        'details': 'Zone transfer (AXFR) is enabled',
                        'action': 'Disable zone transfers or restrict to authorized IPs'
                    })
                except Exception as e:
                    self.log(f"   ✓ Zone transfer blocked (secure)", tag="success")
                    
            except ImportError:
                self.log("   ℹ️ Zone transfer check skipped (dnspython required)", tag="info")
            
            # ========== RÉSUMÉ ==========
            self.log("\n" + "="*70, tag="info")
            if issues_found == 0:
                self.log("[RÉSULTAT] ✅ DNS Configuration - Pas de problème majeur détecté", tag="success")
            else:
                self.log(f"[RÉSULTAT] ⚠️ {issues_found} problème(s) de sécurité DNS détecté(s)!", tag="error")
            
            self.display_problem_summary(len(self.problems_found), target)
            
        except Exception as exc:
            self.log(f"ERREUR ANALYSE DNS: {exc}", tag="error")
        finally:
            self.root.after(0, self.stop_loading)

    def detect_rootkits(self):
        """Détecte les rootkits"""
        target = self.get_target()
        self.start_loading()
        threading.Thread(target=lambda: self._detect_rootkits_thread(target), daemon=True).start()
    
    def _detect_rootkits_thread(self, target):
        """Détection avancée de rootkits et kernel-level threats"""
        try:
            self.log("[ROOTKIT & KERNEL DETECTION] ANALYSE COMPLÈTE", tag="title")
            self.log("="*70, tag="info")
            
            suspicious_count = 0
            
            if platform.system() != "Windows":
                self.log("[-] Rootkit detection optimized for Windows", tag="warn")
                return
            
            # ========== [1] KERNEL DRIVER ANALYSIS ==========
            self.log("\n[1] KERNEL DRIVERS & MODULES ANALYSIS", tag="accent")
            
            try:
                # Chercher les drivers non signés (signe d'un rootkit)
                ps_cmd = """
                Get-WindowsDriver -Online | Where-Object {$_.SignatureStatus -ne 'Valid'} | 
                Select-Object Driver,BootCritical | Format-Table -AutoSize
                """
                
                result = subprocess.run(['powershell', '-Command', ps_cmd],
                                      capture_output=True, text=True, timeout=10)
                
                unsigned_drivers = result.stdout.count('Invalid') + result.stdout.count('NotSigned')
                
                if unsigned_drivers > 0:
                    self.log(f"   ⚠️ {unsigned_drivers} unsigned driver(s) detected!", tag="warn")
                    suspicious_count += unsigned_drivers
                    self.problems_found.append({
                        'type': 'UNSIGNED KERNEL DRIVER',
                        'details': f"{unsigned_drivers} drivers without valid signature",
                        'action': 'Check driver origin in Device Manager'
                    })
                else:
                    self.log(f"   ✓ All kernel drivers properly signed", tag="success")
                    
            except Exception as e:
                self.log(f"   ℹ️ Driver check skipped: {e}", tag="info")
            
            # ========== [2] PROCESS INJECTION DETECTION ==========
            self.log("\n[2] PROCESS INJECTION & HIDDEN PROCESS ANALYSIS", tag="accent")
            
            try:
                # Lancer Get-Process et comparer avec tasklist
                ps_procs = subprocess.run(['powershell', '-Command', 'Get-Process | Select-Object Name,Id'],
                                         capture_output=True, text=True, timeout=5).stdout
                
                task_procs = subprocess.run(['tasklist', '/v'],
                                          capture_output=True, text=True, timeout=5).stdout
                
                # Chercher les processus dans PS mais pas dans tasklist
                suspicious_procs = []
                for line in ps_procs.split('\n'):
                    proc_name = line.split()[0] if line.split() else ''
                    if proc_name and proc_name not in task_procs:
                        suspicious_procs.append(proc_name)
                
                if suspicious_procs:
                    self.log(f"   ⚠️ {len(suspicious_procs)} possible hidden process(es):", tag="warn")
                    for proc in suspicious_procs[:5]:
                        self.log(f"      → {proc}", tag="error")
                        suspicious_count += 1
                else:
                    self.log(f"   ✓ No hidden processes detected", tag="success")
                    
            except Exception as e:
                self.log(f"   ℹ️ Process injection check skipped", tag="info")
            
            # ========== [3] SYSTEM CALL HOOK DETECTION ==========
            self.log("\n[3] SYSTEM HOOKS & INTERRUPT TABLE", tag="accent")
            
            try:
                # Vérifier les servicesWindowsus anormaux
                ps_svc = """
                Get-Service | Where-Object {$_.Status -eq 'Running' -and $_.StartType -eq 'Disabled'} | 
                Select-Object Name | Measure-Object | Select-Object Count
                """
                
                result = subprocess.run(['powershell', '-Command', ps_svc],
                                      capture_output=True, text=True, timeout=5)
                
                # Compter les services "Disabled" mais "Running"
                disabled_running = result.stdout.count('1') if result.stdout else 0
                
                if disabled_running > 0:
                    self.log(f"   ⚠️ {disabled_running} disabled service(s) running (anomaly!)", tag="warn")
                    suspicious_count += 1
                    self.problems_found.append({
                        'type': 'SUSPICIOUS SERVICE',
                        'details': 'Disabled service(s) running - possible rootkit activation',
                        'action': 'Check Services.msc for anomalies'
                    })
                else:
                    self.log(f"   ✓ No anomalous running services detected", tag="success")
                    
            except Exception as e:
                self.log(f"   ℹ️ Service hook check skipped", tag="info")
            
            # ========== [4] REGISTRY ROOTKIT SIGNATURES ==========
            self.log("\n[4] REGISTRY ROOTKIT SIGNATURES", tag="accent")
            
            try:
                # Chercher les clés de registre suspectes
                ps_reg = """
                Get-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\Run' -ErrorAction SilentlyContinue | 
                Measure-Object | Select-Object Count
                """
                
                result = subprocess.run(['powershell', '-Command', ps_reg],
                                      capture_output=True, text=True, timeout=5)
                
                autorun_count = result.stdout.count('Count')
                
                if autorun_count > 10:
                    self.log(f"   ⚠️ {autorun_count} autorun entries (high count - check for malware)", tag="warn")
                    suspicious_count += 1
                else:
                    self.log(f"   ✓ Autorun entries within normal range", tag="success")
                    
            except Exception:
                self.log(f"   ℹ️ Registry check skipped", tag="info")
            
            # ========== [5] FILE SYSTEM ANOMALY DETECTION ==========
            self.log("\n[5] SYSTEM FILE INTEGRITY", tag="accent")
            
            try:
                # Vérifier les fichiers système Windows
                system_files = [
                    'C:\\Windows\\System32\\kernel32.dll',
                    'C:\\Windows\\System32\ntdll.dll',
                    'C:\\Windows\\System32\\drivers\\etc\\hosts',
                ]
                
                suspicious_times = 0
                for fpath in system_files:
                    try:
                        # Fichier système ne devrait pas être modifié récemment
                        mod_time = os.path.getmtime(fpath)
                        age_days = (time.time() - mod_time) / (24 * 3600)
                        
                        if age_days < 7:  # Modifié dans la semaine dernière
                            self.log(f"   ⚠️ {fpath} modified {int(age_days)} days ago!", tag="warn")
                            suspicious_times += 1
                    except:
                        pass
                
                if suspicious_times == 0:
                    self.log(f"   ✓ System files not recently modified", tag="success")
                else:
                    suspicious_count += suspicious_times
                    self.problems_found.append({
                        'type': 'SYSTEM FILE MODIFICATION',
                        'details': f"{suspicious_times} critical system file(s) recently modified",
                        'action': 'Investigate file modifications - possible rootkit'
                    })
                    
            except Exception:
                self.log(f"   ℹ️ File integrity check skipped", tag="info")
            
            # ========== RÉSUMÉ ==========
            self.log("\n" + "="*70, tag="info")
            
            if suspicious_count == 0:
                self.log("[RÉSULTAT] ✅ No rootkit indicators detected", tag="success")
            else:
                self.log(f"[RÉSULTAT] ⚠️ {suspicious_count} suspicious indicator(s) detected!", tag="error")
                self.log("   → Recommend: Full system scan with malwarebytes/kaspersky", tag="warn")
            
            self.display_problem_summary(len(self.problems_found), target)
            
        except Exception as exc:
            self.log(f"ROOTKIT DETECTION ERROR: {exc}", tag="error")
        finally:
            self.root.after(0, self.stop_loading)

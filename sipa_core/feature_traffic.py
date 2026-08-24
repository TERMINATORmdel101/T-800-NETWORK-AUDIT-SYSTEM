"""Analyse de trafic reseau : raw sockets, scapy, netstat.

Extrait de sipa.py (phase 3 : refonte modulaire) sous forme de mixin.
"""

import platform
import random
import socket
import struct
import threading
import time
from collections import defaultdict

import tkinter as tk
from tkinter import messagebox

#: Scapy est optionnel : sans lui, le mode d'analyse profonde est grise.
SCAPY_AVAILABLE = False
try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    scapy = None

from sipa_core.theme import THEME


class TrafficAnalysisMixin:
    """Capture et analyse du trafic reseau selon trois moteurs au choix."""

    def analyze_traffic(self):
        """Ouvre un sélecteur tactique pour choisir le mode d'analyse trafic."""
        
        # Création de la fenêtre de sélection
        dialog = tk.Toplevel(self.root)
        dialog.title("SÉLECTION DU MODE D'INTERCEPTION")
        # Taille adaptee au DPI (500x450 en pixels bruts est illisible sur un
        # ecran haute densite) et redimensionnable en cas de debordement.
        _scale = max(1.0, dialog.winfo_fpixels('1i') / 96.0)
        dialog.geometry(f"{int(500 * _scale)}x{int(450 * _scale)}")
        dialog.configure(bg=THEME["bg"])
        dialog.resizable(True, True)

        # Header
        tk.Label(dialog, text="CHOOSE YOUR WEAPON", 
                 font=THEME["font_header"], bg=THEME["bg"], fg=THEME["fg"]).pack(pady=15)
        
        tk.Label(dialog, text="Sélectionnez la méthode de capture réseau :", 
                 font=THEME["font_label"], bg=THEME["bg"], fg=THEME["accent"]).pack(pady=5)

        # Variable de choix
        choice_var = tk.StringVar(value="raw")

        # --- OPTION 1 : RAW SOCKETS (La Puissance Windows) ---
        frame_raw = tk.LabelFrame(dialog, text=" MODE 1 : RAW SOCKETS (Ultra-Performant)", 
                                  bg=THEME["bg"], fg=THEME["fg"], font=("Arial", 10, "bold"))
        frame_raw.pack(fill="x", padx=20, pady=5)
        
        tk.Radiobutton(frame_raw, text="INTERCEPTION NOYAU (Kernel)", variable=choice_var, value="raw",
                       bg=THEME["bg"], fg="white", selectcolor=THEME["bg_secondary"], 
                       activebackground=THEME["bg"]).pack(anchor="w", padx=10)
        tk.Label(frame_raw, text="   • Vitesse maximale (Temps réel)\n   • Utilise le driver natif Windows (Admin requis)\n   • Recommandé pour gros trafic", 
                 justify="left", bg=THEME["bg"], fg="#888", font=("Consolas", 8)).pack(anchor="w", padx=25, pady=2)

        # --- OPTION 2 : SCAPY (La Précision) ---
        frame_scapy = tk.LabelFrame(dialog, text=" MODE 2 : SCAPY (Deep Analysis)", 
                                    bg=THEME["bg"], fg="#00CCFF", font=("Arial", 10, "bold"))
        frame_scapy.pack(fill="x", padx=20, pady=5)
        
        scapy_state = "normal" if SCAPY_AVAILABLE else "disabled"
        scapy_txt = "ANALYSE PROFONDE" if SCAPY_AVAILABLE else "ANALYSE PROFONDE (Module manquant)"
        
        tk.Radiobutton(frame_scapy, text=scapy_txt, variable=choice_var, value="scapy", state=scapy_state,
                       bg=THEME["bg"], fg="white", selectcolor=THEME["bg_secondary"], 
                       activebackground=THEME["bg"]).pack(anchor="w", padx=10)
        tk.Label(frame_scapy, text="   • Plus lent mais très détaillé\n   • Décode tous les protocoles (DNS, HTTP...)\n   • Idéal pour le débogage précis", 
                 justify="left", bg=THEME["bg"], fg="#888", font=("Consolas", 8)).pack(anchor="w", padx=25, pady=2)

        # --- OPTION 3 : NETSTAT (Le Snapshot) ---
        frame_net = tk.LabelFrame(dialog, text=" MODE 3 : NETSTAT (Snapshot)", 
                                  bg=THEME["bg"], fg="#FFFFFF", font=("Arial", 10, "bold"))
        frame_net.pack(fill="x", padx=20, pady=5)
        
        tk.Radiobutton(frame_net, text="CONNEXIONS ACTIVES", variable=choice_var, value="netstat",
                       bg=THEME["bg"], fg="white", selectcolor=THEME["bg_secondary"], 
                       activebackground=THEME["bg"]).pack(anchor="w", padx=10)
        tk.Label(frame_net, text="   • Pas de capture temps réel\n   • Photo instantanée des connexions\n   • Sûr et ne nécessite pas de drivers", 
                 justify="left", bg=THEME["bg"], fg="#888", font=("Consolas", 8)).pack(anchor="w", padx=25, pady=2)

        # Bouton d'action
        def launch():
            mode = choice_var.get()
            dialog.destroy()
            self._dispatch_traffic_analysis(mode)

        btn = tk.Button(dialog, text="[ ENGAGE SYSTEM ]", command=launch,
                        bg=THEME["fg"], fg="black", font=("Arial", 11, "bold"),
                        activebackground="white", activeforeground="black",
                        relief="raised", bd=3)
        btn.pack(pady=20, fill="x", padx=50)

    def _dispatch_traffic_analysis(self, mode):
        """Routeur qui lance le bon thread selon le choix."""
        self.disable_buttons()
        self.progress.start(10)
        self.text_area.delete(1.0, tk.END)
        
        if mode == "raw":
            self.typewriter_log("INITIALIZING RAW SOCKETS (WIN-KERNEL)...", speed=0.02, tag="title")
            thread = threading.Thread(target=self._capture_packets_raw)
        elif mode == "scapy":
            self.typewriter_log("LOADING SCAPY INTERCEPTOR...", speed=0.02, tag="title")
            thread = threading.Thread(target=self._capture_packets_scapy)
        else:
            self.typewriter_log("QUERING SYSTEM NETWORK STACK (NETSTAT)...", speed=0.02, tag="title")
            thread = threading.Thread(target=self._capture_packets_netstat)
            
        self.matrix_processing(lines=3, duration=0.3)
        thread.start()

    # --- IMPLEMENTATION 1 : RAW SOCKETS (Performant) ---
    def _capture_packets_raw(self):
        sniffer = None
        promiscuous_on = False
        try:
            host = socket.gethostbyname(socket.gethostname())
            self.log(f"[RAW] Binding sur {host}...", tag="info")

            # Création du socket
            sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sniffer.bind((host, 0))
            sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            if platform.system() == "Windows":
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                promiscuous_on = True

            self.log("="*60)
            self.log(f"[*] CAPTURE HAUTE VITESSE EN COURS (Max 50 paquets)", tag="warn")
            self.log(f"[*] Ce mode voit TOUT (Windows is watching you).", tag="info")

            for i in range(50):
                raw_buffer = sniffer.recvfrom(65535)[0]
                ip_header = raw_buffer[0:20]
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

                protocol = iph[6]
                s_addr = socket.inet_ntoa(iph[8])
                d_addr = socket.inet_ntoa(iph[9])

                proto_name = "TCP" if protocol == 6 else "UDP" if protocol == 17 else "ICMP" if protocol == 1 else "RAW"
                color = "ok" if protocol == 6 else "accent"

                self.log(f"[{proto_name}] {s_addr} -> {d_addr} | Size: {len(raw_buffer)}", tag=color)

            self.log("[RAW] Capture terminée.", tag="success")

        except PermissionError:
            self.log("ERREUR : Lancez en ADMIN pour utiliser les Raw Sockets !", tag="error")
        except Exception as e:
            self.log(f"Erreur Raw:{e}", tag="error")
        finally:
            # Toujours désactiver le mode promiscuous et fermer le socket,
            # même si la capture s'est arrêtée sur une exception en cours de
            # boucle (sinon la carte réseau reste en mode promiscuous et le
            # handle du socket fuit pour la durée de vie du processus).
            if sniffer is not None:
                if promiscuous_on:
                    try:
                        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                    except Exception:
                        pass
                try:
                    sniffer.close()
                except Exception:
                    pass
            self.root.after(0, self.stop_loading)

    # --- IMPLEMENTATION 2 : SCAPY (Détaillé) ---
    def _capture_packets_scapy(self):
        try:
            self.log("[SCAPY] Démarrage du moteur d'analyse profonde...", tag="info")
            
            if not SCAPY_AVAILABLE:
                self.log("[-] Scapy non installé.", tag="error")
                return

            # Capture
            packets = scapy.sniff(count=20, timeout=10)
            self.log(f"{len(packets)} paquets capturés et analysés.", tag="success")
            
            for pkt in packets:
                if pkt.haslayer('IP'):
                    src = pkt['IP'].src
                    dst = pkt['IP'].dst
                    proto = pkt['IP'].proto
                    summary = pkt.summary()
                    
                    # Détection DNS spécifique
                    if pkt.haslayer('DNS') and pkt.haslayer('DNSQR'):
                        query = pkt['DNSQR'].qname.decode('utf-8', 'ignore')
                        self.log(f"[DNS] Query:{query} (from {src})", tag="warn")
                    elif pkt.haslayer('TCP'):
                        flags = pkt['TCP'].flags
                        self.log(f"[TCP]{src} -> {dst} | Flags: {flags}", tag="info")
                    else:
                        self.log(f"{summary}", tag="accent")
                        
            self.log("[SCAPY] Analyse terminée.", tag="success")

        except Exception as e:
            self.log(f"Erreur Scapy: {e}", tag="error")
        finally:
            self.root.after(0, self.stop_loading)

    # --- IMPLEMENTATION 3 : NETSTAT (Snapshot) ---
    def _capture_packets_netstat(self):
        try:
            self.log("[NETSTAT] Photo instantanée des connexions...", tag="info")
            if platform.system() == "Windows":
                output = self.run_safe_command(['netstat', '-ano'])
                
                self.log(f"{'PROTO':<6} {'LOCAL IP':<22} {'REMOTE IP':<22} {'STATE':<12} {'PID'}", tag="title")
                self.log("-" * 75)
                
                count = 0
                for line in output.split('\n'):
                    if 'ESTABLISHED' in line or 'LISTEN' in line or 'SYN_SENT' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            proto = parts[0]
                            local = parts[1]
                            remote = parts[2]
                            state = parts[3]
                            pid = parts[4] if len(parts) > 4 else "?"
                            
                            tag = "info"
                            if "SYN_SENT" in state: tag = "warn" # Scan sortant potentiel
                            if "ESTABLISHED" in state: tag = "ok"
                            
                            if count < 50: # Limite d'affichage
                                self.log(f"{proto:<6} {local:<22} {remote:<22} {state:<12} {pid}", tag=tag)
                            count += 1
                
                self.log(f"\n[NETSTAT] {count} connexions actives listées.", tag="success")
        except Exception as e:
            self.log(f"Erreur Netstat: {e}", tag="error")
        finally:
            self.root.after(0, self.stop_loading)

    def _simulate_traffic(self):
        """
        REMPLACEMENT: Analyse RÉELLE du trafic via psutil (Sockets & Connexions).
        Ne nécessite pas de drivers Npcap complexes comme Scapy.
        """
        try:
            import psutil
        except ImportError:
            self.log("Erreur: Module 'psutil' manquant.", tag="error")
            return

        self.log("\n[LIVE TRAFFIC ANALYSIS - SOCKETS]", tag="title")
        self.log("="*60)

        try:
            # Récupère toutes les connexions réseau du système
            connections = psutil.net_connections(kind='inet')
            
            stats = {
                'ESTABLISHED': 0,
                'SYN_SENT': 0, # Signe de scan sortant
                'LISTEN': 0,
                'TIME_WAIT': 0,
                'Remote_IPs': set()
            }

            suspicious_ports = [4444, 5555, 6666, 1337, 31337] # Ports souvent utilisés par les malwares
            
            self.log(f"{'PROTO':<6} {'L.ADDR':<25} {'R.ADDR':<25} {'STATUS':<15} {'PID':<6}")
            self.log("-" * 80)

            for conn in connections:
                # Mise à jour des stats
                stats[conn.status] = stats.get(conn.status, 0) + 1
                
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "*"
                proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                
                # Enregistrement des IPs distantes uniques
                if conn.raddr:
                    stats['Remote_IPs'].add(conn.raddr.ip)

                # Affichage des connexions établies ou suspectes
                if conn.status == 'ESTABLISHED' or conn.laddr.port in suspicious_ports:
                    tag = "warn" if conn.laddr.port in suspicious_ports else "info"
                    self.log(f"{proto:<6} {laddr:<25} {raddr:<25} {conn.status:<15} {conn.pid:<6}", tag=tag)

            # Analyse des risques basés sur les données réelles
            self.log("\n[ANALYSE HEURISTIQUE]", tag="accent")
            
            if stats['SYN_SENT'] > 10:
                self.log(f"ALERTE:{stats['SYN_SENT']} connexions SYN_SENT détectées. Possible infection (Scanning).", tag="warn")
                self.problems_found.append({'type': 'TRAFIC SUSPECT', 'details': 'Nombreux SYN_SENT (Scan sortant?)', 'action': 'Vérifier processus'})
            
            self.log(f"Connexions actives: {stats['ESTABLISHED']}", tag="ok")
            self.log(f"Ports en écoute:   {stats['LISTEN']}", tag="info")
            self.log(f"IPs distantes uniques: {len(stats['Remote_IPs'])}", tag="info")

        except Exception as e:
            self.log(f"Erreur d'analyse trafic: {e}", tag="error")

    def _analyze_packet_stats(self, packets):
        """Analyser les statistiques des paquets"""
        if not packets:
            self.log("\nNo packets captured", tag="warn")
            return
        
        self.log("\n[PACKET STATISTICS]", tag="info")
        
        protocols = defaultdict(int)
        data_by_ip = defaultdict(int)
        
        for pkt in packets:
            if hasattr(pkt, 'proto'):
                protocols[pkt.proto] += 1
            if hasattr(pkt, 'src'):
                data_by_ip[pkt.src] += 1
        
        self.log("Protocol Distribution:", tag="info")
        for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True)[:10]:
            self.log(f"  {proto}: {count} packets")

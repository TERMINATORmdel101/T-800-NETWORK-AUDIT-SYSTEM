"""Console de commandes integree (saisie, historique, favoris, execution).

Extrait de sipa.py (phase 3 : refonte modulaire) sous forme de mixin.
L'execution est restreinte a une liste blanche de commandes de diagnostic.
"""

import shlex
import subprocess
import threading
from datetime import datetime

import tkinter as tk
from tkinter import messagebox, filedialog

from sipa_core.theme import THEME


class CommandConsoleMixin:
    """Console de diagnostic : liste blanche, historique, favoris, export."""

    def insert_command(self, command):
        """Insère une commande dans l'entrée"""
        self.cmd_entry.delete(0, tk.END)
        self.cmd_entry.insert(0, command)
        self.cmd_entry.focus()

    # Liste blanche des commandes de diagnostic autorisées dans la console
    # intégrée. Remplace les anciennes implémentations execute_secure_command
    # et run_secure_command_shell (jamais appelées) qui définissaient la même
    # whitelist sans que le champ de commande de l'UI ne les utilise jamais.
    ALLOWED_CONSOLE_COMMANDS = frozenset([
        "ping", "ipconfig", "netstat", "nslookup", "tracert",
        "whoami", "hostname", "arp", "tasklist",
    ])

    def execute_custom_command(self):
        """Exécute une commande de diagnostic (liste blanche) avec gestion timeout"""
        import subprocess
        import threading

        cmd = self.cmd_entry.get().strip()
        if not cmd:
            return

        # Ajouter à l'historique
        if cmd not in self.command_history:
            self.command_history.append(cmd)
        self.history_position = len(self.command_history) - 1
        self.update_history_combo()

        # Afficher la commande
        self.cmd_result.config(state="normal")
        self.cmd_result.insert(tk.END, f"\n$ {cmd}\n", "command")
        self.cmd_result.see(tk.END)

        # Exécuter en thread pour ne pas bloquer l'UI. Le thread ne touche
        # jamais cmd_result directement (Tkinter n'est pas thread-safe) : il
        # planifie l'écriture sur le thread principal via root.after.
        def write_result(text, tag):
            def _do_write():
                self.cmd_result.config(state="normal")
                self.cmd_result.insert(tk.END, text, tag)
                self.cmd_result.see(tk.END)
            self.root.after(0, _do_write)

        def run_cmd():
            try:
                timeout = self.timeout_var.get()
                # ⚠️ SÉCURITÉ: Utiliser shlex.split pour éviter injection de commandes
                # Ne JAMAIS utiliser shell=True avec entrée utilisateur!
                try:
                    cmd_list = shlex.split(cmd) if isinstance(cmd, str) else cmd
                except ValueError as e:
                    # shlex.split échoue si commande mal formée
                    write_result(f"\n❌ Erreur: Commande mal formée: {e}\n", "error")
                    return

                if not cmd_list:
                    return

                base_cmd = cmd_list[0].lower()
                if base_cmd not in self.ALLOWED_CONSOLE_COMMANDS:
                    write_result(
                        f"\n🚫 Commande interdite : {base_cmd}\n"
                        f"   Commandes autorisées : {', '.join(sorted(self.ALLOWED_CONSOLE_COMMANDS))}\n",
                        "error",
                    )
                    return

                # text=False puis decodage manuel : la console Windows sort en
                # cp850 (accents de ping/ipconfig). Avec text=True, Python
                # tentait un decodage UTF-8, echouait, laissait stdout a None,
                # et la concatenation levait "unsupported operand NoneType".
                result = subprocess.run(
                    cmd_list,
                    capture_output=True,  # Au lieu de shell=True
                    text=False,
                    timeout=timeout
                )

                def _decode(raw):
                    if not raw:
                        return ""
                    for encoding in ("utf-8", "cp850", "cp1252"):
                        try:
                            return raw.decode(encoding)
                        except UnicodeDecodeError:
                            continue
                    return raw.decode("utf-8", errors="replace")

                output = _decode(result.stdout) + _decode(result.stderr)
                write_result(output, "success" if result.returncode == 0 else "error")

            except subprocess.TimeoutExpired:
                write_result(f"\n[ERREUR] Timeout après {timeout}s\n", "error")
            except Exception as e:
                write_result(f"\n[ERREUR] {str(e)}\n", "error")

        thread = threading.Thread(target=run_cmd, daemon=True)
        thread.start()

    def history_previous(self):
        """Navigation historique vers le haut"""
        if self.command_history:
            if self.history_position > 0:
                self.history_position -= 1
                self.cmd_entry.delete(0, tk.END)
                self.cmd_entry.insert(0, self.command_history[self.history_position])

    def history_next(self):
        """Navigation historique vers le bas"""
        if self.command_history:
            if self.history_position < len(self.command_history) - 1:
                self.history_position += 1
                self.cmd_entry.delete(0, tk.END)
                self.cmd_entry.insert(0, self.command_history[self.history_position])
            else:
                self.cmd_entry.delete(0, tk.END)

    def update_history_combo(self):
        """Met à jour la liste déroulante historique"""
        if hasattr(self, 'hist_combo'):
            self.hist_combo.config(values=self.command_history[::-1])

    def load_from_history(self, combo):
        """Charge une commande depuis l'historique"""
        selection = combo.get()
        if selection:
            self.cmd_entry.delete(0, tk.END)
            self.cmd_entry.insert(0, selection)
            self.cmd_entry.focus()

    def add_favorite_command(self):
        """Ajoute la commande actuelle aux favoris"""
        cmd = self.cmd_entry.get().strip()
        if cmd and cmd not in self.command_favorites:
            self.command_favorites.append(cmd)
            self.update_favorites_combo()
            self.log(f"✓ Commande ajoutée aux favoris: {cmd}", "ok")

    def update_favorites_combo(self):
        """Met à jour la liste déroulante favoris"""
        if hasattr(self, 'fav_combo'):
            self.fav_combo.config(values=self.command_favorites)

    def load_from_favorites(self, combo):
        """Charge une commande depuis les favoris"""
        selection = combo.get()
        if selection:
            self.cmd_entry.delete(0, tk.END)
            self.cmd_entry.insert(0, selection)
            self.cmd_entry.focus()

    def autocomplete_command(self, event):
        """Autocomplete avec TAB key"""
        import re
        current_text = self.cmd_entry.get()
        
        # Suggérer les commandes Windows courantes
        suggestions = {
            "ip": "ipconfig /all",
            "task": "tasklist",
            "net": "netstat -an",
            "arp": "arp -a",
            "dns": "nslookup",
            "trace": "tracert",
            "ping": "ping",
            "who": "whoami",
            "sys": "systeminfo",
            "dir": "dir",
        }
        
        # Chercher une correspondance
        for prefix, cmd in suggestions.items():
            if current_text.startswith(prefix):
                self.cmd_entry.delete(0, tk.END)
                self.cmd_entry.insert(0, cmd)
                return "break"

    def copy_results(self):
        """Copie les résultats dans le presse-papiers"""
        try:
            results = self.cmd_result.get("1.0", tk.END)
            self.root.clipboard_clear()
            self.root.clipboard_append(results)
            self.log("✓ Résultats copiés!", "ok")
        except Exception as e:
            self.log(f"✗ Erreur copie: {e}", "error")

    def save_results(self):
        """Sauvegarde les résultats dans un fichier"""
        from tkinter import filedialog
        import os
        
        results = self.cmd_result.get("1.0", tk.END)
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialdir=os.path.expanduser("~")
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(results)
                self.log(f"✓ Fichier sauvegardé: {filename}", "ok")
            except Exception as e:
                self.log(f"✗ Erreur sauvegarde: {e}", "error")

    def log_command(self, command, status="executed"):
        """Log une commande exécutée"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {status.upper()}: {command}"
        
        # Sauvegarder localement
        if not hasattr(self, '_cmd_log'):
            self._cmd_log = []
        self._cmd_log.append(log_entry)

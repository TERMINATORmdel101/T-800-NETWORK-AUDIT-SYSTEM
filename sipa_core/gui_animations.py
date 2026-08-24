"""Effets visuels de l'interface : pluie Matrix, particules, radar, alertes.

Extrait de sipa.py (phase 3 : refonte modulaire) sous forme de mixin.
Purement decoratif : desactivable via le mode performance.
"""

import math
import random
import time

import tkinter as tk

from sipa_core.theme import THEME


class AnimationsMixin:
    """Animations decoratives du terminal T-800."""

    def start_matrix_rain(self):
        """Animation Matrix Rain sur l'arrière-plan"""
        if not hasattr(self, 'matrix_chars'):
            self.matrix_chars = []
        
        # Créer des caractères Matrix si pas déjà fait
        if len(self.matrix_chars) < 20:
            chars = "01アイウエオカキクケコサシスセソタチツテト"
            for _ in range(20):
                x = random.randint(0, 1000)
                y = random.randint(-500, 0)
                char = random.choice(chars)
                self.matrix_chars.append({'x': x, 'y': y, 'char': char, 'speed': random.randint(2, 8)})
        
        # Animer les caractères
        for mc in self.matrix_chars:
            mc['y'] += mc['speed']
            if mc['y'] > 1900:
                mc['y'] = -50
                mc['x'] = random.randint(0, 1000)
                mc['char'] = random.choice("01アイウエオカキクケコサシスセソタチツテト")
        
        self.root.after(100, self.start_matrix_rain)
    
    def animate_progress_pulse(self):
        """Animation de pulsation sur la barre de progression"""
        if not hasattr(self, 'pulse_alpha'):
            self.pulse_alpha = 0
        
        self.pulse_alpha = (self.pulse_alpha + 0.1) % (3.14159 * 2)
        # Effet de pulsation visuelle (via la mise à jour du style)
        
        self.root.after(50, self.animate_progress_pulse)
    
    def animate_button_glow(self, button):
        """Effet de glow/brillance sur un bouton – STRICT ROUGE"""
        original_bg = button.cget("bg")
        colors = [THEME["accent"], "#FF3333", "#FF5555", "#FF0000", THEME["accent"]]  # Variations de rouge
        
        def glow_cycle(index=0):
            if index < len(colors):
                button.config(bg=colors[index])
                self.root.after(50, lambda: glow_cycle(index + 1))
        
        glow_cycle()
    
    def show_particle_burst(self, x=500, y=300, color=None):
        """Affiche une explosion de particules (pour alertes)"""
        if not hasattr(self, 'particle_list'):
            self.particle_list = []
        
        # Créer des particules
        if color is None:
            color = THEME["warn"]
        
        for _ in range(10):
            angle = random.uniform(0, 3.14159 * 2)
            speed = random.uniform(2, 8)
            particle = {
                'x': x,
                'y': y,
                'dx': math.cos(angle) * speed,
                'dy': math.sin(angle) * speed,
                'life': 20,
                'color': color
            }
            self.particle_list.append(particle)
        
        self.animate_particles()
    
    def animate_particles(self):
        """Anime les particules"""
        if not hasattr(self, 'particle_list'):
            return
        
        # Mettre à jour les particules
        for p in self.particle_list[:]:
            p['x'] += p['dx']
            p['y'] += p['dy']
            p['life'] -= 1
            if p['life'] <= 0:
                self.particle_list.remove(p)
        
        if len(self.particle_list) > 0:
            self.root.after(30, self.animate_particles)
    
    def show_scan_radar(self):
        """Affiche une animation de scan radar rotatif"""
        if not hasattr(self, 'scan_angle'):
            self.scan_angle = 0
        
        self.scan_angle = (self.scan_angle + 10) % 360
        
        # Effet visuel dans les logs
        radar_chars = ["◜", "◝", "◞", "◟"]
        radar_idx = (self.scan_angle // 90) % 4
        radar_symbol = radar_chars[radar_idx]
        
        # Mettre à jour un label si disponible
        if hasattr(self, 'radar_label'):
            self.radar_label.config(text=f"{radar_symbol} SCANNING...")
        
        self.root.after(100, self.show_scan_radar)
    
    def animate_log_fadein(self, text, tag=None):
        """Log avec effet fade-in animé"""
        colors = ["#330000", "#550000", "#770000", "#990000", "#BB0000", THEME["fg"]]
        
        def fadein_cycle(index=0):
            if index < len(colors):
                # Ajouter du texte avec couleur progressive
                self.text_area.insert(tk.END, f"\n> {text}", tag)
                self.text_area.tag_config(tag, foreground=colors[index])
                self.text_area.see(tk.END)
                self.root.after(50, lambda: fadein_cycle(index + 1))
            else:
                # Couleur finale
                self.text_area.tag_config(tag, foreground=THEME["fg"])
        
        fadein_cycle()
    
    def show_loading_spinner(self, duration=2.0):
        """Affiche un spinner de chargement animé dans les logs"""
        spinner_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        start_time = time.time()
        idx = 0
        
        def spinner_cycle():
            nonlocal idx
            if time.time() - start_time < duration:
                char = spinner_chars[idx % len(spinner_chars)]
                self.log(f"\r{char} PROCESSING...", tag="info")
                idx += 1
                self.root.after(100, spinner_cycle)
        
        spinner_cycle()
    
    def animate_threat_alert(self):
        """Animation spéciale pour les alertes de menaces"""
        alert_frames = [
            "⚠️  [!] THREAT DETECTED [!]  ⚠️",
            "🔴  [!] THREAT DETECTED [!]  🔴",
            "⚠️  [!] THREAT DETECTED [!]  ⚠️"
        ]
        
        for i, frame in enumerate(alert_frames):
            self.root.after(i * 200, lambda f=frame: self.log(f"\n{f}", tag="warn"))
        
        # Explosion de particules
        self.root.after(600, lambda: self.show_particle_burst(500, 300, THEME["warn"]))

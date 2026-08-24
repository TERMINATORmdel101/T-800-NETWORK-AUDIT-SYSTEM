"""Widgets Tkinter personnalises du theme T-800.

Extrait de sipa.py (phase 3 : refonte modulaire), sans modification de
comportement.
"""

import tkinter as tk
from tkinter import ttk

from sipa_core.theme import THEME, ensure_contrast


class HoverButton(tk.Button):
    """Bouton T-800 STRICT : Rouge/Noir/Blanc – ZÉRO animation"""
    def __init__(self, parent, text, command=None, width=18, color=None, fg=None, **kwargs):
        # `color` designe la couleur du TEXTE, pas du fond. Le fond reste
        # sombre, ce qui garantit un libelle lisible quelle que soit la teinte
        # demandee. ensure_contrast eclaircit au besoin une couleur trop sombre.
        self.normal_bg = THEME["btn_bg"]
        self.hover_bg = THEME["btn_bg_hover"]
        self.normal_fg = ensure_contrast(fg or color or THEME["btn_action"],
                                         self.normal_bg)
        self.hover_fg = THEME["btn_fg_hover"]
        
        super().__init__(parent, text=text, command=command, width=width,
                        bg=self.normal_bg, fg=self.normal_fg, relief="flat",
                        font=THEME["font_button"], bd=0,
                        highlightthickness=1,
                        highlightbackground=self.normal_fg,
                        highlightcolor=self.normal_fg,
                        activebackground=self.hover_bg,
                        activeforeground=self.hover_fg,
                        cursor="hand2", **kwargs)
        
        # Survols directs – PAS d'animation, changement IMMÉDIAT
        self.bind("<Enter>", lambda e: self.config(bg=self.hover_bg, fg=self.hover_fg))
        self.bind("<Leave>", lambda e: self.config(bg=self.normal_bg, fg=self.normal_fg))


class DarkCombobox(ttk.Combobox):
    """Combobox sombre avec style STRICT rouge/blanc"""
    def __init__(self, parent, values=None, **kwargs):
        style = ttk.Style()
        
        # Style pour dark combobox – STRICT ROUGE
        style.configure('Dark.TCombobox',
                       fieldbackground="#0f0f0f",
                       background="#0a0a0a",
                       foreground="#FF0000")      # Rouge pur
        style.map('Dark.TCombobox',
                 fieldbackground=[('readonly', '#0f0f0f'), ('disabled', '#0a0a0a')],
                 foreground=[('readonly', '#FF0000'), ('disabled', '#CCCCCC')])
        
        kwargs.setdefault('style', 'Dark.TCombobox')
        kwargs.setdefault('foreground', '#FF0000')
        
        super().__init__(parent, values=values or [], **kwargs)

class StyledFrame(tk.Frame):
    """Frame avec bordure élégante et glow effect"""
    def __init__(self, parent, title="", bg="#0a0a0a", fg="#FF0000", **kwargs):
        super().__init__(parent, bg=bg, **kwargs)
        
        # Bordure supérieure glow
        top_glow = tk.Frame(self, bg=fg, height=2)
        top_glow.pack(fill="x", padx=0, pady=0)
        
        # Contenu
        self.content_frame = tk.Frame(self, bg=bg)
        self.content_frame.pack(fill="both", expand=True, padx=8, pady=8)
        
        # Titre optionnel
        if title:
            title_label = tk.Label(self.content_frame, text=f"[ {title.upper()} ]",
                                 bg=bg, fg=fg, font=("Courier New", 11, "bold"))
            title_label.pack(anchor="w", pady=(0, 8))
        
        # Bordure inférieure glow
        bottom_glow = tk.Frame(self, bg=fg, height=1)
        bottom_glow.pack(fill="x", padx=0, pady=0)


class ProgressBar(tk.Canvas):
    """Barre de progression élégante avec animation"""
    def __init__(self, parent, width=200, height=20, color="#FF0000", bg="#0a0a0a"):
        super().__init__(parent, width=width, height=height, bg=bg, relief="flat", bd=1, highlightthickness=0)
        self.progress = 0
        self.target = 0
        self.color = color
        self.bg_color = bg
        self.border_color = "#333333"
        
        # Dessiner cadre initial
        self.create_rectangle(1, 1, width-1, height-1, outline=self.border_color, fill=bg)
    
    def set_progress(self, value):
        """Définir le progrès (0-100) avec animation"""
        self.target = max(0, min(100, value))
        self._animate_progress()
    
    def _animate_progress(self):
        """Animer la barre progressivement"""
        if self.progress < self.target:
            self.progress += 2
            self._draw_bar()
            self.after(20, self._animate_progress)
        elif self.progress > self.target:
            self.progress -= 2
            self._draw_bar()
            self.after(20, self._animate_progress)
    
    def _draw_bar(self):
        """Redessiner la barre avec progrès courant"""
        self.delete("progress")
        width = int(self.winfo_width() * self.progress / 100)
        height = self.winfo_height()
        self.create_rectangle(1, 1, width, height, fill=self.color, outline="", tags="progress")
        
        # Texte du pourcentage
        self.create_text(self.winfo_width()//2, height//2, 
                        text=f"{int(self.progress)}%", 
                        fill="#FFFFFF", font=("Courier New", 10, "bold"), tags="progress")


class DarkThemeManager:
    """Gestionnaire central de thème et d'UI moderne"""
    
    @staticmethod
    def apply_dark_style(root):
        """Applique le style sombre global"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Couleurs du thème
        bg = "#0a0a0a"
        fg = "#FF0000"
        accent = "#FF0000"  # Strict rouge (pas de vert)
        bg_secondary = "#0f0f0f"
        
        # Configuration globale
        style.configure(".", background=bg, foreground=fg)
        
        # Scrollbar
        style.configure("Vertical.TScrollbar",
                       background=bg_secondary,
                       troughcolor=bg,
                       arrowcolor=fg)
        style.map("Vertical.TScrollbar",
                 background=[("active", fg), ("!active", bg_secondary)])
        
        # Combobox
        style.configure("TCombobox", fieldbackground=bg, background=bg_secondary,
                        foreground=accent, font=THEME["font_label"], padding=4)
        
        # Notebook
        style.configure("TNotebook", background=bg, borderwidth=0)
        style.configure("TNotebook.Tab", background=bg_secondary, foreground=accent,
                        padding=[14, 10], font=THEME["font_button"])
        style.map("TNotebook.Tab",
                 background=[("selected", fg), ("!selected", bg_secondary)],
                 foreground=[("selected", bg), ("!selected", accent)])
    
    @staticmethod
    def create_button(parent, text, command=None, icon="", width=18, color=None, fg=None):
        """Crée un bouton stylisé avec hover effects"""
        btn_text = f"{icon} {text}" if icon else text
        return HoverButton(parent, btn_text, command=command, width=width, color=color, fg=fg)
    
    @staticmethod
    def create_frame(parent, title="", **kwargs):
        """Crée un frame stylisé avec bordure glow"""
        return StyledFrame(parent, title=title, **kwargs)


class Tooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip = None
        self.widget.bind("<Enter>", self.show_tooltip)
        self.widget.bind("<Leave>", self.hide_tooltip)

    def show_tooltip(self, event):
        if self.tooltip:
            return
        x = event.x_root + 10
        y = event.y_root + 10
        self.tooltip = tk.Toplevel(self.widget)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{x}+{y}")
        
        # Style moderne du tooltip
        label = tk.Label(self.tooltip, text=self.text,
                        background=THEME["bg_secondary"], 
                        foreground=THEME["accent"],
                        relief="flat", bd=1,
                        font=THEME["font_label"], wraplength=300,
                        padx=8, pady=4)
        label.pack()

    def hide_tooltip(self, event):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None

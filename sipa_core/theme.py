"""Mise a l'echelle DPI et palettes de couleurs/polices de SIPA.

Extrait de sipa.py (phase 3 : refonte modulaire). L'appel a
SetProcessDpiAwareness doit rester le plus tot possible dans le demarrage :
importer ce module suffit a le declencher.

Deux palettes existent : "sombre" (par defaut) et "claire".
`THEME` est un dictionnaire VIVANT : `apply_palette()` le met a jour en place
plutot que de le remplacer, pour que les modules qui ont fait
`from sipa_core.theme import THEME` voient le changement sans etre reimportes.
"""

# --- DÉBUT CONFIGURATION 4K ULTRA-NETTE ---
try:
    import ctypes
    # Indispensable pour que Windows ne floute pas l'app
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
    # Facteur d'échelle réel (1.0, 1.5, 2.0...)
    ScaleFactor = ctypes.windll.shcore.GetScaleFactorForDevice(0) / 100
except Exception:
    ScaleFactor = 1.0


def scaled(size: float) -> int:
    """Adapte les tailles (polices/espaces) à l'écran 4K"""
    return int(size * ScaleFactor)
# --- FIN CONFIGURATION ---


# =============================================================================
# Elements independants de la palette : polices, espacements, transparence.
# =============================================================================
_COMMUN = {
    # POLICES 4K
    "font_main": ("Segoe UI", 11),
    "font_mono": ("Consolas", 11),
    "font_header": ("Segoe UI Black", 19),    # Réduit de 26 à 19 (plus équilibré)
    "font_title": ("Segoe UI Semibold", 14),  # Augmenté de 12 à 14
    "font_label": ("Segoe UI", 11),           # Augmenté de 10 à 11
    "font_button": ("Segoe UI", 11, "bold"),  # Augmenté de 10 à 11

    # PADDING
    "padding_std": scaled(12),
    "padding_lg": scaled(20),
    "padding_xl": scaled(24),
    "border_glow": scaled(2),

    # Transparence (alpha 0-255)
    "alpha_bg": 240,
    "alpha_overlay": 200,
}


# =============================================================================
# PALETTE SOMBRE — rouge et noir profond (8.0.0 : plus agressive, zero gris terne).
# Fonds noirs teintes de rouge (jamais gris), rouge vif, blanc chaud. Les
# neutres tirent vers le rouge pour se lire comme choisis, pas subis.
# =============================================================================
_SOMBRE = {
    # FOND : noir profond legerement chaud, pas un gris ardoise.
    "bg": "#0C0A0B",             # Noir chaud, base de tout l'ecran
    "bg_secondary": "#17090C",   # Panneaux : noir teinte de rouge
    "bg_input": "#0A0809",       # Zones de saisie et de journal
    "bg_tertiary": "#17090C",    # Compatibilite widgets

    # TEXTE & ACCENTS : rouge vif / noir / blanc chaud.
    "fg": "#FF4D4D",             # Rouge vif, l'accent identitaire
    "fg_text": "#F5EDEE",        # Blanc chaud, net (pas de gris casse)
    "fg_dim": "#8A4044",         # Rouge eteint (traits, decor)
    "fg_bright": "#FF6B6B",      # Rouge appuye

    "accent": "#FF4D4D",
    "accent_bright": "#FF6B6B",
    "accent_dim": "#8A4044",
    "success": "#F5EDEE",
    "warn": "#FF4D4D",
    "error": "#FF6B6B",
    "info": "#D8BFC2",           # Neutre chaud clair, jamais gris ardoise

    "scrollbar_bg": "#0A0809",
    "scrollbar_fg": "#FF4D4D",

    # ---- JOURNAL D'ACTIVITE ----------------------------------------------
    # Chaque niveau se distingue des autres ET reste lisible sur le fond du
    # journal. Couleurs vives assumees : c'est le seul endroit ou l'on quitte
    # le rouge/noir, parce qu'un journal doit trier vert/orange/rouge d'un
    # coup d'oeil.
    "log_title": "#FFFFFF",     # titres de section
    "log_accent": "#FFC24D",    # sous-titres et etapes (or vif)
    "log_info": "#D8BFC2",      # information neutre (chaud)
    "log_ok": "#3FD07E",        # succes (vert vif)
    "log_warn": "#FFA23E",      # avertissement (orange vif)
    "log_error": "#FF5C5C",     # erreur : doit sauter aux yeux
    "log_faint": "#2A1E20",     # decor (pluie de caracteres)

    # ---- ROLES DE BOUTONS -------------------------------------------------
    # La couleur d'un bouton designe son TEXTE, pas son fond. Fond commun tres
    # sombre teinte de rouge ; texte rouge vif ou blanc chaud net.
    "btn_bg": "#1E1214",          # Fond commun a tous les boutons
    "btn_bg_hover": "#FF4D4D",    # Survol : rouge plein
    "btn_fg_hover": "#0C0A0B",    # Texte au survol : noir sur rouge
    "btn_action": "#FF5A54",      # Actions principales (scans)
    "btn_critical": "#FF6B6B",    # Operations sensibles ou destructrices
    "btn_tool": "#EDE4E5",        # Outils : blanc chaud net (pas de gris)
    "btn_muted": "#D89DA1",       # Actions secondaires : rose neutre chaud
}


# =============================================================================
# PALETTE CLAIRE — blanc, noir et accents vifs (8.0.0 : contraste maximal).
# Fond blanc pur, texte quasi noir, rouge franc. Les couleurs semantiques du
# journal sont vives et tres visibles, jamais des gris delaves.
# Chaque role atteint au moins 4.5:1 sur son fond (verifie par les tests).
# =============================================================================
_CLAIR = {
    "bg": "#FFFFFF",             # Blanc pur, base de tout l'ecran
    "bg_secondary": "#F4EFEF",   # Panneaux : blanc casse a peine teinte
    "bg_input": "#FFFFFF",       # Zones de saisie et de journal
    "bg_tertiary": "#F4EFEF",    # Compatibilite widgets

    "fg": "#C41E1E",             # Rouge franc, lisible sur blanc
    "fg_text": "#0A0A0A",        # Texte principal quasi noir
    "fg_dim": "#C99BA0",         # Rouge delave (traits, decor)
    "fg_bright": "#A81414",      # Rouge appuye

    "accent": "#C41E1E",
    "accent_bright": "#A81414",
    "accent_dim": "#C99BA0",
    "success": "#0A0A0A",
    "warn": "#C41E1E",
    "error": "#A81414",
    "info": "#3A2E30",           # Brun tres fonce, net (pas un gris moyen)

    "scrollbar_bg": "#F4EFEF",
    "scrollbar_fg": "#C41E1E",

    # ---- JOURNAL D'ACTIVITE ----------------------------------------------
    # Couleurs vives et franches, assombries juste assez pour tenir 4.5:1 sur
    # le blanc. C'est ici que vit le contraste maximal demande.
    "log_title": "#0A0A0A",
    "log_accent": "#9A6A00",    # or fonce
    "log_info": "#3A2E30",
    "log_ok": "#0B7A44",        # vert vif
    "log_warn": "#B85C00",      # orange vif
    "log_error": "#C41E1E",     # rouge vif
    "log_faint": "#D9CFD0",

    "btn_bg": "#FFFFFF",          # Fond commun a tous les boutons
    "btn_bg_hover": "#C41E1E",    # Survol : rouge plein
    "btn_fg_hover": "#FFFFFF",    # Texte au survol : blanc sur rouge
    "btn_action": "#C41E1E",      # Actions principales (scans)
    "btn_critical": "#A00000",    # Operations sensibles ou destructrices
    "btn_tool": "#1A1416",        # Outils : noir net (pas de gris)
    "btn_muted": "#5B2E30",       # Actions secondaires : brun-rouge fonce
}


#: Palettes disponibles, fusionnees avec les elements communs.
PALETTES = {
    "sombre": dict(_COMMUN, **_SOMBRE),
    "clair": dict(_COMMUN, **_CLAIR),
}

#: Nom de la palette actuellement appliquee.
CURRENT_PALETTE = "sombre"

#: Dictionnaire VIVANT partage par tous les modules. Ne jamais le reassigner :
#: `apply_palette()` le met a jour en place pour que les imports existants
#: (`from sipa_core.theme import THEME`) refletent le changement.
THEME = dict(PALETTES["sombre"])


def apply_palette(nom):
    """Applique une palette en place et renvoie son nom effectif.

    Un nom inconnu retombe sur "sombre" plutot que de lever : un fichier de
    configuration abime ne doit pas empecher l'application de demarrer.
    """
    global CURRENT_PALETTE
    if nom not in PALETTES:
        nom = "sombre"
    THEME.clear()
    THEME.update(PALETTES[nom])
    CURRENT_PALETTE = nom
    return nom


def current_palette():
    """Nom de la palette active ("sombre" ou "clair")."""
    return CURRENT_PALETTE


# =============================================================================
# CONTRASTE : garantit qu'aucun texte ne devienne illisible sur son fond.
# Formules officielles WCAG 2.1 (luminance relative + ratio de contraste).
# =============================================================================

def _srgb_to_linear(channel):
    """Convertit un canal sRGB [0-1] en valeur lineaire (WCAG 2.1)."""
    return channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4


def relative_luminance(hex_color):
    """Luminance relative d'une couleur #RRGGBB, entre 0 (noir) et 1 (blanc)."""
    hex_color = hex_color.lstrip("#")
    r, g, b = (int(hex_color[i:i + 2], 16) / 255 for i in (0, 2, 4))
    return (0.2126 * _srgb_to_linear(r)
            + 0.7152 * _srgb_to_linear(g)
            + 0.0722 * _srgb_to_linear(b))


def contrast_ratio(color_a, color_b):
    """Ratio de contraste entre deux couleurs (1 = identiques, 21 = noir/blanc).

    Le seuil WCAG AA pour du texte normal est 4.5 ; 3.0 suffit pour du texte
    large ou en gras, ce qui est le cas des libelles de boutons.
    """
    lum_a, lum_b = relative_luminance(color_a), relative_luminance(color_b)
    lighter, darker = max(lum_a, lum_b), min(lum_a, lum_b)
    return (lighter + 0.05) / (darker + 0.05)


def ensure_contrast(fg, bg, minimum=3.0):
    """Ajuste `fg` jusqu'a atteindre le contraste minimal sur `bg`.

    Sert de filet de securite : meme si une couleur mal choisie est passee a
    un bouton, son libelle reste lisible au lieu de disparaitre dans le fond.
    L'ajustement va vers le blanc sur fond sombre, vers le noir sur fond clair.
    """
    if contrast_ratio(fg, bg) >= minimum:
        return fg

    vers_le_clair = relative_luminance(bg) < 0.5
    r, g, b = (int(fg.lstrip("#")[i:i + 2], 16) for i in (0, 2, 4))
    for _ in range(20):
        if vers_le_clair:
            r, g, b = (min(255, int(c * 1.25) + 12) for c in (r, g, b))
        else:
            r, g, b = (max(0, int(c * 0.75) - 12) for c in (r, g, b))
        candidate = f"#{r:02X}{g:02X}{b:02X}"
        if contrast_ratio(candidate, bg) >= minimum:
            return candidate
    return "#FFFFFF" if vers_le_clair else "#000000"

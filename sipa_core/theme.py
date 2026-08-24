"""Mise a l'echelle DPI et palettes de couleurs/polices de SIPA.

Extrait de sipa.py (phase 3 : refonte modulaire). L'appel a
SetProcessDpiAwareness doit rester le plus tot possible dans le demarrage :
importer ce module suffit a le declencher.

Deux palettes existent : "sombre" (identite T-800, par defaut) et "clair".
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
# PALETTE SOMBRE — identite T-800 : rouge, noir et gris neutres.
# =============================================================================
_SOMBRE = {
    # FOND : Vantablack absolu – zéro clémence
    "bg": "#050505",             # 99% noir Vantablack
    "bg_secondary": "#0a0a0a",   # Panneaux latéraux
    "bg_input": "#0f0f0f",       # Zones de texte
    "bg_tertiary": "#0a0a0a",    # Compatibilité widgets

    # TEXTE & ACCENTS : STRICT Rouge/Noir/Blanc
    "fg": "#FF0000",             # Rouge pur – laser Terminator
    "fg_text": "#FFFFFF",        # Blanc éclatant (pas de gris cassé)
    "fg_dim": "#660000",         # Rouge sombre (matrices)
    "fg_bright": "#FF0000",      # Toujours le même rouge

    "accent": "#FF0000",         # Rouge pur
    "accent_bright": "#FF0000",
    "accent_dim": "#660000",
    "success": "#FFFFFF",        # Blanc pour succès (STRICT)
    "warn": "#FF0000",           # Rouge pour avertissement (PAS d'orange)
    "error": "#880000",          # Bordeaux sombre pour erreurs
    "info": "#CCCCCC",           # Gris léger pour info (minimaliste)

    "scrollbar_bg": "#0f0f0f",
    "scrollbar_fg": "#FF0000",

    # ---- ROLES DE BOUTONS -------------------------------------------------
    # La couleur d'un bouton designe son TEXTE, pas son fond : le fond reste
    # sombre, ce qui rend toute combinaison lisible. Avant, une couleur claire
    # (#FFFFFF, #CCCCCC) devenait le fond et le libelle blanc devenait
    # invisible -- c'etait le cas de 42 boutons.
    "btn_bg": "#121212",          # Fond commun a tous les boutons
    "btn_bg_hover": "#FF0000",    # Survol : rouge plein
    "btn_fg_hover": "#000000",    # Texte au survol : noir sur rouge
    "btn_action": "#FF5252",      # Actions principales (scans)
    "btn_critical": "#FF1A1A",    # Operations sensibles ou destructrices
    "btn_tool": "#D6D6D6",        # Outils et utilitaires (gris clair)
    "btn_muted": "#9AA3AD",       # Actions secondaires
}


# =============================================================================
# PALETTE CLAIRE — meme identite rouge/noir, valeurs inversees.
# Les couleurs de texte sont assombries pour rester lisibles sur fond clair :
# chaque role atteint au moins 4.5:1 sur son fond (verifie par les tests).
# =============================================================================
_CLAIR = {
    "bg": "#F2F2F2",             # Gris tres clair, moins agressif que le blanc
    "bg_secondary": "#E4E4E4",   # Panneaux lateraux
    "bg_input": "#FFFFFF",       # Zones de saisie et de texte
    "bg_tertiary": "#E4E4E4",    # Compatibilite widgets

    "fg": "#B00000",             # Rouge profond, lisible sur fond clair
    "fg_text": "#111111",        # Texte principal quasi noir
    "fg_dim": "#C98A8A",         # Rouge delave (traits, matrices)
    "fg_bright": "#8B0000",      # Rouge appuye

    "accent": "#B00000",
    "accent_bright": "#8B0000",
    "accent_dim": "#C98A8A",
    "success": "#111111",        # Noir : le blanc serait invisible ici
    "warn": "#B00000",
    "error": "#7A0000",
    "info": "#444444",

    "scrollbar_bg": "#E4E4E4",
    "scrollbar_fg": "#B00000",

    "btn_bg": "#FFFFFF",          # Fond commun a tous les boutons
    "btn_bg_hover": "#B00000",    # Survol : rouge plein
    "btn_fg_hover": "#FFFFFF",    # Texte au survol : blanc sur rouge
    "btn_action": "#A32020",      # Actions principales (scans)
    "btn_critical": "#8B0000",    # Operations sensibles ou destructrices
    "btn_tool": "#333333",        # Outils et utilitaires (gris fonce)
    "btn_muted": "#4A5560",       # Actions secondaires
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

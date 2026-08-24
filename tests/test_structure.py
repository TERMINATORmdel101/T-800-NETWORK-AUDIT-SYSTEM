"""Tests structurels : protegent la refonte modulaire en cours.

Ces tests ne verifient pas des correctifs precis (c'est le role de
test_fixes.py) mais l'integrite de la structure elle-meme. Ils sont concus
pour attraper les degats typiques d'une extraction de code :

  * une methode perdue en route ;
  * un bouton de l'interface pointant vers une methode qui n'existe plus ;
  * deux mixins definissant le meme nom (l'un ecrase l'autre en silence) ;
  * un module du paquet sipa_core qui ne s'importe plus tout seul.

Lancer depuis la racine du projet :
    python tests/test_structure.py
"""

import ast
import importlib
import importlib.util
import inspect
import os
import pkgutil
import re
import sys
import textwrap

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def _is_red_or_grey(hex_color):
    """Vrai si la couleur est un rouge ou un gris neutre (identite T-800).

    Ecarte les teintes etrangeres au theme : cyan, vert, magenta, orange.
    """
    hex_color = hex_color.lstrip("#")
    r, g, b = (int(hex_color[i:i + 2], 16) for i in (0, 2, 4))
    if abs(r - g) <= 16 and abs(g - b) <= 16:
        return True                      # gris neutre
    return r > g and r > b and g == b or (r >= g and r >= b and abs(g - b) <= 24)


results = []


def check(name, condition, detail=""):
    results.append((name, bool(condition), detail))
    print(f"[{'PASS' if condition else 'ECHEC'}] {name}")
    if detail and not condition:
        print(f"         -> {detail}")


def load_sipa():
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    spec = importlib.util.spec_from_file_location("sipa", os.path.join(ROOT, "sipa.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    print("=" * 70)
    print("TESTS STRUCTURELS DU PAQUET sipa_core")
    print("=" * 70)

    sipa = load_sipa()
    App = sipa.AuditIA_Ultimate

    # --- 1. Chaque module du paquet s'importe isolement -----------------------
    import sipa_core
    modules = [m.name for m in pkgutil.iter_modules(sipa_core.__path__)]
    check("Le paquet sipa_core expose des modules", len(modules) >= 8,
          f"modules trouves : {modules}")
    for name in sorted(modules):
        try:
            importlib.import_module(f"sipa_core.{name}")
            ok, detail = True, ""
        except Exception as exc:
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        check(f"sipa_core.{name} s'importe seul", ok, detail)

    # --- 2. Aucune collision de noms entre mixins -----------------------------
    # Avec l'heritage multiple, deux mixins definissant la meme methode se
    # masquent silencieusement : seul le premier dans le MRO est appele.
    mixins = [c for c in App.__mro__ if c not in (App, object)]
    owners = {}
    collisions = {}
    for cls in mixins:
        for attr, value in vars(cls).items():
            if attr.startswith("__") or not callable(value):
                continue
            if attr in owners:
                collisions.setdefault(attr, [owners[attr]]).append(cls.__name__)
            else:
                owners[attr] = cls.__name__
    check("Aucune methode definie par deux mixins a la fois",
          not collisions,
          "; ".join(f"{k} defini dans {v}" for k, v in collisions.items()))

    # Une methode de mixin masquee par la classe principale est legitime, mais
    # doit rester exceptionnelle : on la signale sans faire echouer le test.
    shadowed = [a for a in owners if a in vars(App)]
    if shadowed:
        print(f"         (info) masquees par AuditIA_Ultimate : {shadowed}")

    # --- 3. Les boutons de l'interface pointent vers des methodes reelles -----
    # build_controls cable les boutons soit par command=self.X, soit par des
    # tuples ("LIBELLE", self.X, couleur) ou des lambdas. On repere ces trois
    # formes par analyse AST, ce qui evite de confondre une action de bouton
    # avec un simple attribut d'instance (self.root, self.command_history...).
    ctrl_tree = ast.parse(textwrap.dedent(inspect.getsource(App.build_controls)))

    def self_attr(node):
        if (isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "self"):
            return node.attr
        return None

    referenced = set()
    for node in ast.walk(ctrl_tree):
        if isinstance(node, ast.keyword) and node.arg == "command":
            referenced.add(self_attr(node.value))
        elif isinstance(node, ast.Call):
            referenced.add(self_attr(node.func))
        elif (isinstance(node, ast.Tuple) and len(node.elts) >= 2
                and isinstance(node.elts[0], ast.Constant)
                and isinstance(node.elts[0].value, str)):
            referenced.add(self_attr(node.elts[1]))
    referenced.discard(None)

    missing = sorted(n for n in referenced if not hasattr(App, n))
    check("Tous les boutons de build_controls ciblent une methode existante",
          not missing, f"introuvables : {missing}")
    print(f"         (info) {len(referenced)} actions de bouton verifiees")

    # --- 3b. Lisibilite : contraste de CHAQUE bouton --------------------------
    # Historiquement la couleur d'un bouton servait de fond avec un libelle
    # blanc : "#FFFFFF" donnait un ratio de 1.00 (texte invisible). Desormais
    # la couleur est celle du texte sur fond sombre ; on le verifie pour tous.
    from sipa_core.theme import THEME as TH, contrast_ratio, ensure_contrast

    btn_bg = TH["btn_bg"]
    colors = []
    for node in ast.walk(ctrl_tree):
        if not (isinstance(node, ast.Tuple) and len(node.elts) >= 3):
            continue
        if not (isinstance(node.elts[0], ast.Constant)
                and isinstance(node.elts[0].value, str)):
            continue
        # HoverButton utilise `fg or color` : un 4e element l'emporte donc
        # sur le 3e. On evalue la couleur reellement appliquee.
        spec = node.elts[3] if len(node.elts) >= 4 else node.elts[2]
        if (isinstance(spec, ast.Constant) and isinstance(spec.value, str)
                and re.fullmatch(r"#[0-9A-Fa-f]{6}", spec.value)):
            colors.append((node.elts[0].value, spec.value))
        elif (isinstance(spec, ast.Subscript) and isinstance(spec.slice, ast.Constant)
                and spec.slice.value in TH):
            colors.append((node.elts[0].value, TH[spec.slice.value]))

    unreadable = [
        (label, color, round(contrast_ratio(ensure_contrast(color, btn_bg), btn_bg), 2))
        for label, color in colors
        if contrast_ratio(ensure_contrast(color, btn_bg), btn_bg) < 3.0
    ]
    check("Chaque bouton atteint le contraste minimal (WCAG >= 3.0)",
          not unreadable, f"illisibles : {unreadable}")
    if colors:
        worst = min(contrast_ratio(ensure_contrast(c, btn_bg), btn_bg) for _, c in colors)
        print(f"         (info) {len(colors)} boutons colores, pire ratio : {worst:.2f}")

    check("Aucune couleur de bouton hors identite rouge/noir/gris",
          all(_is_red_or_grey(c) for _, c in colors),
          f"hors palette : {sorted({c for _, c in colors if not _is_red_or_grey(c)})}")

    # --- 3c. Sous-categories : boutons segmentes, pas une liste deroulante ----
    # Une liste deroulante cachait les categories derriere un clic alors qu'il
    # n'y en a que deux par onglet.
    controls = inspect.getsource(App.build_controls)
    check("Les sous-categories sont des boutons segmentes",
          "segments[name]" in controls and "ttk.Combobox(header" not in controls)
    check("La categorie active est marquee visuellement",
          'THEME["fg"] if active' in controls)

    # --- 4. Inventaire minimal des methodes cles ------------------------------
    essential = [
        "start_scan", "run_nmap", "export_reports", "show_help",
        "execute_custom_command", "analyze_traffic", "analyze_dns",
        "detect_rootkits", "scan_cve_advanced", "start_api_server",
        "auto_save_scan", "log", "check_queue",
    ]
    absent = [m for m in essential if not hasattr(App, m)]
    check("Toutes les methodes essentielles sont presentes", not absent,
          f"absentes : {absent}")

    total = len([a for a in dir(App) if not a.startswith("__") and callable(getattr(App, a, None))])
    check("La classe expose un nombre plausible de methodes", total >= 150,
          f"{total} methodes trouvees")

    # --- 5. Logique pure : evaluation du risque -------------------------------
    app = object.__new__(App)
    check("is_risky_service signale les ports a risque",
          all(app.is_risky_service(p, "", "") for p in (21, 23, 445, 3389)))
    check("is_risky_service ignore les ports courants surs",
          not any(app.is_risky_service(p, "", "") for p in (22, 80, 443)))
    check("get_service_name reconnait les ports connus",
          app.get_service_name(443) == "HTTPS" and app.get_service_name(3389) == "RDP")
    check("get_service_name gere un port inconnu",
          app.get_service_name(64999) == "Port-64999")

    # --- 5b. Aucun renvoi vers un fichier qui n'existe pas --------------------
    # L'application citait FEATURES_ENTREPRISE_V6.0.md, QUICKSTART_V6.md et
    # DOCUMENTATION_V6.0.3_COMPLETE.md ; aucun des trois n'a jamais existe.
    import glob as _glob

    referenced = set()
    for path in [os.path.join(ROOT, "sipa.py")] + _glob.glob(os.path.join(ROOT, "sipa_core", "*.py")):
        text = open(path, encoding="utf-8-sig").read()
        referenced.update(re.findall(r"[A-Za-z0-9_.\-]+\.md", text))
    ghosts = sorted(
        name for name in referenced
        if not os.path.exists(os.path.join(ROOT, name))
        and not os.path.exists(os.path.join(ROOT, "docs", name)))
    check("Aucun fichier de documentation inexistant n'est cite",
          not ghosts, f"fichiers fantomes : {ghosts}")

    # --- 5c. La version n'est plus recopiee en dur ----------------------------
    from sipa_core import APP_VERSION as _version
    hardcoded = []
    for path in [os.path.join(ROOT, "sipa.py")] + _glob.glob(os.path.join(ROOT, "sipa_core", "*.py")):
        if os.path.basename(path) == "__init__.py":
            continue
        if "6.0.3" in open(path, encoding="utf-8-sig").read():
            hardcoded.append(os.path.basename(path))
    check("Plus aucune version 6.0.3 codee en dur", not hardcoded,
          f"encore present dans : {hardcoded}")
    print(f"         (info) version courante : {_version}")

    # --- 5d. La licence annoncee correspond au fichier LICENSE ----------------
    # L'aide affichait "GPL-3.0" alors que le depot est sous MIT : deux licences
    # aux obligations tres differentes pour qui reutilise le code.
    license_file = open(os.path.join(ROOT, "LICENSE"), encoding="utf-8-sig").read()
    actual = "MIT" if "MIT License" in license_file else "?"
    check("Le fichier LICENSE est identifiable", actual != "?")

    from sipa_core.locales import LICENSE_TEXT
    check("Le contrat affiche cite la licence de distribution dans les 5 langues",
          all(actual in text for text in LICENSE_TEXT.values()),
          f"manquant : {[k for k, v in LICENSE_TEXT.items() if actual not in v]}")

    conflicting = []
    for path in [os.path.join(ROOT, "sipa.py"), os.path.join(ROOT, "README.md")] +             _glob.glob(os.path.join(ROOT, "sipa_core", "*.py")):
        text = open(path, encoding="utf-8-sig").read()
        if "GPL" in text and actual != "GPL":
            conflicting.append(os.path.basename(path))
    check("Aucun texte n'annonce une licence contredisant LICENSE",
          not conflicting, f"mentionnent GPL : {conflicting}")

    # --- 5e. Mode ligne de commande ------------------------------------------
    from sipa_core import cli

    parser = cli.build_parser()
    parsed = parser.parse_args(["--cible", "10.0.0.1", "--scan", "cve",
                                "--export", "html"])
    check("Le mode console analyse correctement les arguments",
          parsed.target == "10.0.0.1" and parsed.scan == "cve"
          and parsed.export == "html")
    check("Tous les types de scan de l'interface sont accessibles en console",
          set(cli.SCAN_TYPES.values()) == {"fast", "full", "vuln", "backdoor"},
          str(cli.SCAN_TYPES))
    check("Les codes de sortie sont distincts (0 / 1 / 2)",
          len({cli.EXIT_CLEAN, cli.EXIT_FINDINGS, cli.EXIT_ERROR}) == 3)

    headless = cli.build_headless_app(App, "127.0.0.1", quiet=True)
    check("L'instance console se construit sans widget Tk",
          headless.problems_found == [] and headless.entry_ip.get() == "127.0.0.1")
    check("L'instance console est marquee headless",
          getattr(headless, "headless", False))

    # Une tache planifiee ne doit pas ouvrir de navigateur sur une session
    # que personne ne surveille.
    html_src = inspect.getsource(App._generate_html)
    check("Le rapport HTML n'ouvre pas de navigateur en mode console",
          'getattr(self, "headless"' in html_src)

    entry = open(os.path.join(ROOT, "sipa.py"), encoding="utf-8-sig").read()
    check("Un argument en ligne de commande court-circuite l'interface",
          "from sipa_core.cli import run" in entry and "len(sys.argv) > 1" in entry)

    # --- 6. sipa.py ne redefinit pas ce qu'il importe -------------------------
    tree = ast.parse(open(os.path.join(ROOT, "sipa.py"), encoding="utf-8-sig").read())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("sipa_core"):
            imported.update(a.asname or a.name for a in node.names)
    redefined = sorted(
        n.name for n in tree.body
        if isinstance(n, (ast.ClassDef, ast.FunctionDef)) and n.name in imported)
    check("sipa.py ne redefinit aucun symbole importe de sipa_core",
          not redefined, f"redefinis : {redefined}")

    passed = sum(1 for _, ok, _ in results if ok)
    print("=" * 70)
    print(f"RESULTAT : {passed}/{len(results)} tests reussis")
    if passed != len(results):
        print("\nEchecs :")
        for name, ok, detail in results:
            if not ok:
                print(f"  - {name}" + (f" ({detail})" if detail else ""))
    print("=" * 70)
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())

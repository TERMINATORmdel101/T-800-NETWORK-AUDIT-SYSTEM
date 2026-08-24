"""Mode ligne de commande : lancer un audit sans ouvrir l'interface.

Permet d'utiliser SIPA depuis une tache planifiee Windows, un serveur sans
ecran ou un script. Exemples :

    python sipa.py --cible 192.168.1.0/24
    python sipa.py --cible 10.0.0.5 --scan complet --export html
    python sipa.py --cible scanme.nmap.org --scan cve --export tout --silencieux

Codes de sortie (utiles en automatisation) :
    0  aucun constat
    1  des constats ont ete releves
    2  le scan n'a pas pu s'executer (Nmap absent, cible injoignable...)
"""

import argparse
import os
import sys

from sipa_core import APP_NAME, APP_VERSION

#: Correspondance entre les noms lisibles et les types internes de run_nmap.
SCAN_TYPES = {
    "rapide": "fast",
    "complet": "full",
    "cve": "vuln",
    "backdoor": "backdoor",
}

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


class _NullProgress:
    """Barre de progression inerte : le mode console n'en a pas."""

    def start(self, *args, **kwargs):
        pass

    def stop(self, *args, **kwargs):
        pass


class _NullRoot:
    """Remplace la fenetre Tk : execute directement au lieu de differer."""

    def after(self, _delay, func=None, *args):
        if func is not None:
            func(*args)

    def update_idletasks(self):
        pass


class _Entry:
    def __init__(self, value):
        self._value = value

    def get(self):
        return self._value


def build_headless_app(app_class, target, quiet=False):
    """Instance utilisable en console, sans passer par __init__ (donc sans Tk).

    Les methodes de scan ne touchent plus aucun widget : elles passent toutes
    par self.log. Il suffit donc de rediriger ce journal vers la sortie
    standard et de neutraliser les quelques appels a la fenetre.
    """
    app = object.__new__(app_class)

    tags = {"error": "[ERREUR]", "warn": "[ALERTE]", "success": "[OK]",
            "ok": "[OK]", "title": "\n===", "accent": "  ", "info": ""}

    def log(message, tag="info", speed=0.01):
        if quiet and tag not in ("error", "warn"):
            return
        prefix = tags.get(tag, "")
        print(f"{prefix} {message}".strip() if prefix else str(message))

    app.log = log
    app.root = _NullRoot()
    app.progress = _NullProgress()
    app.entry_ip = _Entry(target)
    app.problems_found = []
    app.scan_history = []
    app.scan_results_cache = {}
    app.threat_scores = {}
    app.network_baseline = {}
    app.performance_mode = True          # aucune animation en console
    app.logs_file = "network_audit_logs.txt"
    app.nm = None
    import threading as _threading
    app.scan_cancel = _threading.Event()
    # Marqueur lu par les methodes partagees : pas d'ouverture de
    # navigateur ni de boite de dialogue en mode console.
    app.headless = True

    app.disable_buttons = lambda: None
    app.enable_buttons = lambda: None
    app.stop_loading = lambda: None
    app.start_loading = lambda: None
    app.send_notification = lambda *a, **k: None

    class _NullText:
        def insert(self, *a, **k):
            pass

        def delete(self, *a, **k):
            pass

        def see(self, *a, **k):
            pass

        def config(self, *a, **k):
            pass

    app.text_area = _NullText()

    import logging
    app.logger = logging.getLogger("sipa.cli")

    # Les memes services qu'en mode graphique : sans eux, une derive detectee
    # lors d'un scan planifie ne declencherait aucune alerte.
    from sipa_core.services import ConfigManager, EmailNotifier, WebhookNotifier
    app.config_manager = ConfigManager("config.json")
    app.email_notifier = EmailNotifier(app.config_manager)
    app.webhook_notifier = WebhookNotifier(app.config_manager)
    app.scan_scheduler = None

    app.knowledge = None
    try:
        from sipa_core.knowledge import KnowledgeBase
        app.knowledge = KnowledgeBase(log=app.log)
    except Exception:
        pass

    app.cve_db = None
    if (app.config_manager.get("cve", {}) or {}).get("enabled", True):
        try:
            from sipa_core.cve import CVEDatabase
            app.cve_db = CVEDatabase(
                api_key=(app.config_manager.get("nvd", {}) or {}).get("api_key"),
                log=app.log)
        except Exception:
            pass

    app.init_database()
    app.init_nmap()
    return app


def build_parser():
    parser = argparse.ArgumentParser(
        prog="sipa",
        description=f"{APP_NAME} {APP_VERSION} — audit reseau en ligne de commande",
        epilog="Sans argument, l'interface graphique s'ouvre normalement.")
    parser.add_argument("--cible", "--target", dest="target", required=True,
                        help="adresse IP, nom d'hote ou plage CIDR")
    parser.add_argument("--scan", choices=sorted(SCAN_TYPES), default="rapide",
                        help="type de scan (defaut : rapide)")
    parser.add_argument("--export", choices=["html", "json", "tout", "aucun"],
                        default="aucun", help="format de rapport a produire")
    parser.add_argument("--dossier", default=".",
                        help="dossier de sortie des rapports (defaut : courant)")
    parser.add_argument("--silencieux", action="store_true",
                        help="n'afficher que les alertes et les erreurs")
    parser.add_argument("--version", action="version",
                        version=f"{APP_NAME} {APP_VERSION}")
    return parser


def run(app_class, argv=None):
    """Point d'entree du mode console. Retourne le code de sortie."""
    args = build_parser().parse_args(argv)

    target = args.target.strip()
    if not target:
        print("[ERREUR] Cible vide.", file=sys.stderr)
        return EXIT_ERROR

    app = build_headless_app(app_class, target, quiet=args.silencieux)

    if app.nm is None:
        print("[ERREUR] Nmap est introuvable. Installez-le depuis "
              "https://nmap.org/download.html et verifiez qu'il est dans le PATH.",
              file=sys.stderr)
        return EXIT_ERROR

    if not args.silencieux:
        print(f"=== {APP_NAME} {APP_VERSION} ===")
        print(f"Cible : {target} | Scan : {args.scan}\n")

    try:
        app.run_nmap(target, SCAN_TYPES[args.scan])
    except KeyboardInterrupt:
        app.scan_cancel.set()
        print("\n[STOP] Interrompu par l'utilisateur.", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:
        print(f"[ERREUR] Le scan a echoue : {exc}", file=sys.stderr)
        return EXIT_ERROR

    counts = app.count_by_severity()
    print(f"\n--- Bilan : {len(app.problems_found)} constat(s) ---")
    for level in app.SEVERITIES:
        if counts[level]:
            print(f"  {level:9} {counts[level]}")

    if args.export != "aucun":
        previous = os.getcwd()
        destination = os.path.abspath(args.dossier)
        os.makedirs(destination, exist_ok=True)
        os.chdir(destination)
        try:
            if args.export in ("html", "tout"):
                app._generate_html()
            if args.export in ("json", "tout"):
                app._export_all_formats()
            print(f"Rapport(s) ecrit(s) dans : {destination}")
        finally:
            os.chdir(previous)

    return EXIT_FINDINGS if app.problems_found else EXIT_CLEAN

"""Tests EN CONDITIONS REELLES : verifie que les appels reseau fonctionnent.

Contrairement a tests/test_fixes.py (hors ligne, instantane), ce script fait de
vrais appels sortants. Il sert a valider la correction du bug `requests = None`,
que seule une execution reelle peut confirmer.

Lancer depuis la racine du projet :
    python tests/test_live.py

Necessite une connexion Internet. Un echec ici peut venir du reseau
(pare-feu, proxy, service indisponible) et pas forcement du code : le script
distingue les deux cas quand il le peut.
"""

import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# La console Windows est en cp1252 par defaut : les sorties de l'app contiennent
# des caracteres Unicode (cases a cocher, fleches) qui la font planter.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


results = []


def check(name, condition, detail=""):
    results.append((name, bool(condition), detail))
    print(f"[{'PASS' if condition else 'ECHEC'}] {name}")
    if detail:
        print(f"         -> {detail}")


def load_sipa():
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    spec = importlib.util.spec_from_file_location("sipa", os.path.join(ROOT, "sipa.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeEntry:
    def __init__(self, value):
        self._value = value

    def get(self):
        return self._value


class FakeRoot:
    def after(self, delay, func=None, *args):
        pass

    def update_idletasks(self):
        pass


class FakeText:
    """Suffit aux methodes qui ecrivent dans la zone de logs."""

    def insert(self, *a, **k):
        pass

    def see(self, *a, **k):
        pass

    def config(self, *a, **k):
        pass

    def delete(self, *a, **k):
        pass


def make_app(App, target="8.8.8.8"):
    app = object.__new__(App)
    app.logged = []
    app.log = lambda msg, tag="info", speed=0.01: app.logged.append((str(msg), tag))
    app.root = FakeRoot()
    app.problems_found = []
    app.scan_history = []
    app.scan_results_cache = {}
    app.entry_ip = FakeEntry(target)
    app.text_area = FakeText()
    app.performance_mode = True   # coupe les animations pendant les tests
    app.disable_buttons = lambda: None
    app.enable_buttons = lambda: None
    app.stop_loading = lambda: None
    return app


def main():
    print("=" * 70)
    print("TESTS RESEAU REELS (necessitent Internet)")
    print("=" * 70)

    sipa = load_sipa()
    App = sipa.AuditIA_Ultimate

    # --- 1. requests est utilisable ------------------------------------------
    if sipa.requests is None:
        check("Le module requests est disponible", False,
              "requests n'est pas installe : pip install requests")
        return 1
    check("Le module requests est disponible", True)

    # --- 2. MAC vendor lookup (le bug le plus visible) ------------------------
    # Avant correction, requests valait None -> AttributeError avalee par un
    # except nu -> la fonction renvoyait toujours "Inconnu".
    app = make_app(App)
    vendor = app.get_mac_vendor("00:1A:2B:3C:4D:5E")
    check(
        "MAC Lookup renvoie un constructeur (et non 'Inconnu')",
        vendor and vendor != "Inconnu",
        f"reponse de l'API : {vendor!r}"
        + ("  <- si 'Inconnu', verifiez votre connexion avant d'incriminer le code"
           if vendor == "Inconnu" else ""),
    )

    # --- 3. Threat intelligence (telechargement d'une blocklist) --------------
    app = make_app(App, target="8.8.8.8")
    app.check_threat_intelligence()
    text = " ".join(m for m, _ in app.logged)
    check(
        "Threat Intel telecharge bien la base EmergingThreats",
        "IPs connues" in text or "liste noire" in text.lower(),
        text[-200:] if len(text) > 200 else text,
    )

    # --- 4. VirusTotal sans cle : pas de fausses donnees ----------------------
    app = make_app(App)
    app._virustotal_check(None)
    check(
        "VirusTotal sans cle n'invente aucune menace",
        app.problems_found == [],
        f"{len(app.problems_found)} fausse(s) menace(s) ajoutee(s)",
    )

    passed = sum(1 for _, ok, _ in results if ok)
    print("=" * 70)
    print(f"RESULTAT : {passed}/{len(results)} tests reussis")
    print("=" * 70)
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())

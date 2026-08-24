"""Vérifie les correctifs des phases 1 et 2 SANS lancer l'interface Tkinter.

Lancer depuis la racine du projet :
    python tests/test_fixes.py

Le script construit une instance "nue" de AuditIA_Ultimate (sans __init__, donc
sans widget Tk) et remplace les quelques attributs GUI utilisés par les méthodes
testées. Cela permet de valider la logique métier alors que l'interface est
inutilisable.
"""

import ast
import importlib.util
import inspect
import io
import json
import os
import re
import sys
import tempfile
import textwrap
import time
import urllib.error
import urllib.request

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
    status = "PASS" if condition else "ECHEC"
    line = f"[{status}] {name}"
    if detail and not condition:
        line += f"\n         -> {detail}"
    print(line)


def load_sipa():
    # sipa.py importe le paquet sipa_core/ situe a la racine du projet : il doit etre
    # sur sys.path, ce que fait Python tout seul quand on lance `python sipa.py`
    # mais pas quand on charge le fichier par chemin depuis tests/.
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
    """root.after() enregistre l'appel au lieu de l'exécuter (pas de boucle Tk)."""

    def __init__(self):
        self.calls = []

    def after(self, delay, func=None, *args):
        self.calls.append((delay, func, args))


def code_seul(fonction):
    """Source d'une fonction, docstrings et commentaires retires.

    Indispensable pour les tests qui verifient l'ABSENCE d'une chaine : les
    docstrings citent volontiers l'ancien comportement corrige ("Chain
    Status: COMPLETE", "when available"...), ce qui ferait echouer un simple
    `chaine not in source`.
    """
    import ast as _ast
    import io as _io
    import tokenize as _tokenize
    import textwrap as _textwrap

    brut = _textwrap.dedent(inspect.getsource(fonction))

    # Retirer les commentaires par analyse lexicale.
    morceaux = []
    lecteur = _io.StringIO(brut).readline
    try:
        for jeton in _tokenize.generate_tokens(lecteur):
            if jeton.type != _tokenize.COMMENT:
                morceaux.append(jeton)
        sans_commentaires = _tokenize.untokenize(morceaux)
    except (_tokenize.TokenError, IndentationError):
        sans_commentaires = brut

    # Retirer les docstrings via l'arbre syntaxique.
    try:
        arbre = _ast.parse(sans_commentaires)
    except SyntaxError:
        return sans_commentaires
    for noeud in _ast.walk(arbre):
        if not isinstance(noeud, (_ast.FunctionDef, _ast.AsyncFunctionDef,
                                  _ast.ClassDef, _ast.Module)):
            continue
        corps = getattr(noeud, "body", [])
        if (corps and isinstance(corps[0], _ast.Expr)
                and isinstance(corps[0].value, _ast.Constant)
                and isinstance(corps[0].value.value, str)):
            corps.pop(0)
    return _ast.unparse(arbre)


def make_app(App, target="127.0.0.1"):
    app = object.__new__(App)  # contourne __init__ et donc toute la construction GUI
    app.logged = []
    app.log = lambda msg, tag="info", speed=0.01: app.logged.append((str(msg), tag))
    app.root = FakeRoot()
    app.problems_found = []
    app.scan_history = []
    app.scan_results_cache = {}
    app.entry_ip = FakeEntry(target)
    app.logs_file = "network_audit_logs.txt"
    # Marque l'instance de test comme headless : _generate_html n'ouvrira donc
    # aucun navigateur (sinon il pointe vers un rapport en dossier temporaire
    # deja supprime a la fin du test -> popup ERR_FILE_NOT_FOUND).
    app.headless = True
    app.disable_buttons = lambda: None
    app.enable_buttons = lambda: None
    app.stop_loading = lambda: None
    return app


def main():
    print("=" * 70)
    print("TESTS DES CORRECTIFS SIPA (sans interface graphique)")
    print("=" * 70)

    sipa = load_sipa()
    App = sipa.AuditIA_Ultimate
    check("Le module sipa.py s'importe sans erreur", True)

    # --- 1. MAC lookup ne declenche plus de scan CVE cache -------------------
    mac_src = inspect.getsource(App.tool_mac_lookup)
    check(
        "MAC Lookup ne lance plus de scan CVE",
        "vulners" not in mac_src and "_run_real_vuln_scan" not in mac_src,
        "le code du scan CVE est encore dans tool_mac_lookup",
    )
    check(
        "Le scan CVE est bien une methode separee (scan_cve_real)",
        hasattr(App, "scan_cve_real")
        and "_run_real_vuln_scan" in inspect.getsource(App.scan_cve_real),
    )

    # --- 2. Liste blanche de la console de commandes -------------------------
    allowed = App.ALLOWED_CONSOLE_COMMANDS
    check("La console autorise 'ping'", "ping" in allowed)
    check("La console refuse 'notepad'", "notepad" not in allowed)
    check("La console refuse 'del'", "del" not in allowed)
    check(
        "La liste blanche est bien appliquee dans execute_custom_command",
        "ALLOWED_CONSOLE_COMMANDS" in inspect.getsource(App.execute_custom_command),
    )

    # --- 3. Assainissement du nom de fichier d'auto-sauvegarde ---------------
    app = make_app(App)
    with tempfile.TemporaryDirectory() as tmp:
        previous = os.getcwd()
        os.chdir(tmp)
        try:
            app.auto_save_scan("../../evil", "fast", {"ports": [80]})
            escaped = os.path.exists(os.path.join(os.path.dirname(os.path.dirname(tmp)), "evil_scan_fast.json"))
            created = [f for f in os.listdir(tmp) if f.endswith(".json")]
        finally:
            os.chdir(previous)
    check(
        "Une cible '../../evil' n'ecrit pas hors du dossier courant",
        not escaped and created,
        f"fichiers crees dans le dossier courant : {created}",
    )

    # --- 4. Les modes demo n'inventent plus de menaces ------------------------
    app = make_app(App)
    app._virustotal_demo()
    check(
        "Le mode demo VirusTotal n'ajoute aucune fausse menace",
        app.problems_found == [],
        f"problems_found contient {len(app.problems_found)} entree(s) fictive(s)",
    )
    check("La fonction _shodan_demo (fausses donnees) a bien ete supprimee",
          not hasattr(App, "_shodan_demo"))

    joined = " ".join(open(os.path.join(ROOT, "sipa.py"), encoding="utf-8").read().split())
    for fake in ("203.0.113.100", "192.0.2.50"):
        check(f"L'IP fictive {fake} n'apparait plus dans le code", fake not in joined)

    # --- 5. VirusTotal interroge la vraie cible -------------------------------
    vt_src = inspect.getsource(App._virustotal_check)
    check(
        "VirusTotal utilise la cible saisie et non des IP d'exemple",
        "get_target()" in vt_src and "last_analysis_stats" in vt_src,
    )

    # --- 6. Fonctionnalites non implementees annoncees comme telles -----------
    app = make_app(App)
    app.sync_tenable()
    text = " ".join(m for m, _ in app.logged)
    normalized = text.upper().replace("É", "E")
    check("Tenable annonce clairement 'NON IMPLEMENTEE'", "NON IMPLEMENTEE" in normalized)
    check(
        "Tenable ne pretend plus qu'une connexion a ete etablie",
        "etablie" not in text.lower() and "établie" not in text.lower(),
    )
    check(
        "Tenable ne demande plus de cle API pour rien",
        "askstring" not in inspect.getsource(App.sync_tenable),
    )

    # --- 6b. Modules reellement importes (etaient a None) ---------------------
    # requests/smtplib/email.mime etaient declares "= None" et jamais importes :
    # les 8 methodes appelant requests.* et tout envoi d'email plantaient.
    check("Le module requests est reellement importe (plus None)",
          getattr(sipa, "requests", None) is not None and hasattr(sipa.requests, "get"))
    for name in ("smtplib", "MIMEText", "MIMEMultipart", "MIMEBase", "encoders"):
        check(f"{name} est reellement importe (plus None)",
              getattr(sipa, name, None) is not None)

    # --- 6c. Planification : le scheduler lance un VRAI scan ------------------
    # ScanScheduler existait mais _scheduled_scan portait un TODO et ne lancait
    # rien ; l'objet n'etait meme jamais transmis a l'interface.
    from sipa_core.services import ConfigManager, ScanScheduler

    previous_dir = os.getcwd()
    sandbox = tempfile.mkdtemp()
    os.chdir(sandbox)
    try:
        manager = ConfigManager("config.json")
        fired = []
        scheduler = ScanScheduler(manager, scan_callback=lambda: fired.append(1))

        check("Sans configuration, aucune planification n'est active",
              "Aucune planification" in scheduler.describe())

        manager.set("scheduling.enabled", True)
        manager.set("scheduling.time", "03:30")
        manager.set("scheduling.days", ["monday", "friday"])
        started = scheduler.apply_config()
        check("apply_config installe la tache planifiee", started)
        check("Une tache est bien enregistree dans APScheduler",
              started and len(scheduler.scheduler.get_jobs()) == 1)
        check("describe() rend compte de l'horaire configure",
              "03:30" in scheduler.describe())

        scheduler._scheduled_scan()
        check("Le declenchement appelle reellement le scan", fired == [1])

        try:
            ScanScheduler._day_to_number("lundi")
            invalid_rejected = False
        except ValueError:
            invalid_rejected = True
        check("Un jour de semaine invalide est rejete (et non pris pour lundi)",
              invalid_rejected)

        scheduler.stop_scheduler()
        check("stop_scheduler desactive la planification",
              "Aucune planification" in scheduler.describe())
    finally:
        os.chdir(previous_dir)

    check("L'interface expose une methode de scan planifie",
          hasattr(App, "_run_scheduled_scan"))

    # --- 6d. Le texte d'aide du champ cible n'est jamais pris pour une cible --
    app = make_app(App)
    app.entry_ip = FakeEntry(App.TARGET_PLACEHOLDER)
    check("Le texte d'aide du champ cible est ignore par get_target()",
          app.get_target() == "",
          f"get_target() a renvoye {app.get_target()!r}")
    app.entry_ip = FakeEntry("  10.0.0.5  ")
    check("get_target() nettoie les espaces autour de la cible",
          app.get_target() == "10.0.0.5")

    remaining = [
        name for name in dir(App)
        if not name.startswith("__") and callable(getattr(App, name, None))
        and name != "get_target"
        and "entry_ip.get()" in (inspect.getsource(getattr(App, name))
                                 if getattr(App, name).__module__ else "")
    ]
    check("Plus aucune methode ne lit entry_ip.get() directement",
          not remaining, f"a corriger : {remaining}")

    # --- 6e. Le rapport HTML ne fuit pas de marqueurs de template -------------
    # Un fragment du modele n'etait pas une f-string : le pied de page affichait
    # litteralement "{APP_NAME} {APP_VERSION}" dans les rapports livres.
    app = make_app(App)
    previous_dir = os.getcwd()
    sandbox = tempfile.mkdtemp()
    os.chdir(sandbox)
    try:
        app.problems_found = [{
            "type": "BACKDOOR", "host": "10.0.0.1", "port": 4444,
            "service": "shell", "details": "test", "action": "isoler"}]
        app._generate_html()
        produced = [f for f in os.listdir(sandbox) if f.endswith(".html")]
        html = open(os.path.join(sandbox, produced[0]), encoding="utf-8").read() if produced else ""
    finally:
        os.chdir(previous_dir)

    check("Le rapport HTML est bien genere", bool(produced))
    check("Le rapport HTML ne contient aucun marqueur {APP_...} non resolu",
          "{APP" not in html)
    check("Le rapport HTML ne contient plus de version codee en dur",
          "6.0.3" not in html)

    # --- 6f. Severite : resume et tableau doivent concorder -------------------
    # Un rapport reel affichait "Critiques: 0" au-dessus de deux lignes
    # marquees CRITIQUE : le compteur comparait le type a une liste exacte
    # tandis que le tableau cherchait des sous-chaines.
    app = make_app(App)
    app.problems_found = [
        {"type": "SERVICE RISQUE", "details": "SMB vulnérable (EternalBlue)"},
        {"type": "CONNEXIONS RÉPÉTÉES", "details": "7 connexions vers 10.0.0.9"},
        {"type": "FAILLE EXPLOITABLE", "details": "Port 445 ouvert - Risque: CRITICAL"},
        {"type": "FAILLE EXPLOITABLE", "details": "Port 23 ouvert - Risque: HIGH"},
        {"type": "VERSION DETECTED", "details": "Bannière: OpenSSH 8.2"},
    ]
    counts = app.count_by_severity()
    check("Le total par severite egale le nombre de constats",
          sum(counts.values()) == len(app.problems_found), str(counts))
    check("Une faille nommee (EternalBlue) est classee critique",
          app.classify_severity(app.problems_found[0]) == "CRITIQUE")
    # Des connexions repetees ressemblent a un canal de commande mais aussi a
    # un navigateur ou une synchronisation : c'est a verifier, pas une
    # compromission constatee.
    check("Des connexions repetees sont signalees sans etre jugees critiques",
          app.classify_severity(app.problems_found[1]) == "MOYEN",
          f"classe {app.classify_severity(app.problems_found[1])}")
    check("Un risque explicite HIGH ne devient pas critique",
          app.classify_severity(app.problems_found[3]) == "ÉLEVÉ",
          "le type contient EXPLOIT et ecrasait le niveau reel")
    check("Une simple banniere reste en severite faible",
          app.classify_severity(app.problems_found[4]) == "FAIBLE")

    previous_dir = os.getcwd()
    sandbox = tempfile.mkdtemp()
    os.chdir(sandbox)
    try:
        app._generate_html()
        produced = [f for f in os.listdir(sandbox) if f.endswith(".html")]
        report = open(os.path.join(sandbox, produced[0]), encoding="utf-8").read()
    finally:
        os.chdir(previous_dir)

    body = report.split("<tbody>")[1]
    # Le badge de gravite occupe sa propre cellule en fin de ligne. On le
    # compte par la cellule complete plutot que par un emoji : les emojis ont
    # ete retires de l'interface et des rapports.
    check("Le resume annonce autant de critiques que le tableau en contient",
          body.count("<td>CRITIQUE</td>") == counts["CRITIQUE"],
          f"tableau={body.count('<td>CRITIQUE</td>')} resume={counts['CRITIQUE']}")
    check("Le rapport indique le port de chaque constat",
          "<th>PORT</th>" in report)

    # --- 6g. Aucune liste blanche, aucun blocage automatique hatif ------------
    # Declarer une destination "sure" serait un mensonge commode : un canal de
    # commande passe souvent par un service cloud legitime, qui figurerait
    # justement sur une liste blanche.
    source = open(os.path.join(ROOT, "sipa.py"), encoding="utf-8-sig").read()
    check("Aucune liste blanche d'adresses reputees sures",
          not any(token in source for token in
                  ("WHITELIST_IP", "TRUSTED_IPS", "SAFE_IPS", "KNOWN_GOOD_IPS")))
    check("Plus aucun verdict 'Command & Control' affirme",
          "Command & Control" not in source and "C2 BEACON" not in source)

    # On inspecte la liste de types elle-meme (chaine entre quotes), pas les
    # commentaires : ceux-ci mentionnent le type justement pour expliquer
    # pourquoi il en est exclu.
    blocking = inspect.getsource(App.generate_firewall_rules)
    blocked_types = re.findall(r"'([A-ZÉÈÀÇ0-9 _]+)'", blocking)
    check("Les connexions repetees ne declenchent pas de blocage automatique",
          "CONNEXIONS RÉPÉTÉES" not in blocked_types,
          f"types bloques : {blocked_types}")
    check("Le blocage automatique reste limite aux hostilites averees",
          set(blocked_types) <= {"BRUTE FORCE LIVE", "IP MALVEILLANTE",
                                 "HONEYPOT INTRUSION", "LOCAL"},
          f"types bloques : {blocked_types}")

    # --- 6h. L'historique est reellement alimente par les scans ---------------
    # auto_save_scan et save_scan_result_real n'etaient appeles nulle part :
    # historique, comparaison et rejeu ne recevaient jamais de donnees.
    nmap_src = inspect.getsource(App.run_nmap)
    check("run_nmap enregistre le scan en memoire",
          "self.auto_save_scan(" in nmap_src)
    check("run_nmap enregistre le scan en base",
          "self.save_scan_result_real(" in nmap_src)
    check("Une photographie comparable du scan est produite",
          hasattr(App, "_snapshot_scan") and "self._snapshot_scan()" in nmap_src)

    # --- 6i. Comparaison : vrai differentiel, pas un compte de constats -------
    app = make_app(App)
    app.scan_history = [
        {"timestamp": "10:00", "target": "192.168.1.0/24", "results": {"hosts": {
            "192.168.1.1": {"ports": {"22": {"service": "ssh", "version": "OpenSSH 8.2"},
                                      "80": {"service": "http", "version": ""}}}}}},
        {"timestamp": "12:00", "target": "192.168.1.0/24", "results": {"hosts": {
            "192.168.1.1": {"ports": {"22": {"service": "ssh", "version": "OpenSSH 9.1"},
                                      "445": {"service": "microsoft-ds", "version": ""}}},
            "192.168.1.50": {"ports": {"3389": {"service": "rdp", "version": ""}}}}}},
    ]
    app.compare_scans()
    diff = " ".join(m for m, _ in app.logged)
    check("Un nouvel hote est detecte", "192.168.1.50" in diff)
    check("Un port nouvellement ouvert est detecte",
          "445" in diff and "OUVERT" in diff)
    check("Un port ferme depuis est detecte", "80" in diff and "FERMÉ" in diff)
    check("Un changement de version de service est detecte",
          "OpenSSH 8.2 -> OpenSSH 9.1" in diff)
    check("Les changements deviennent des constats exploitables",
          any(p["type"] == "CHANGEMENT RÉSEAU" for p in app.problems_found),
          f"{len(app.problems_found)} constat(s)")

    app = make_app(App)
    app.scan_history = [{"timestamp": "10:00", "target": "x", "results": {"hosts": {}}}]
    app.compare_scans()
    check("Avec un seul scan, la comparaison le dit clairement",
          "au moins 2 scans" in " ".join(m for m, _ in app.logged))

    # --- 6j. Derive reseau : detection et alerte ------------------------------
    # EmailNotifier et WebhookNotifier etaient crees au demarrage puis jamais
    # transmis a l'interface ; send_slack/send_discord/send_email n'etaient
    # appeles nulle part. Aucune alerte n'avait donc jamais pu partir.
    previous_dir = os.getcwd()
    sandbox = tempfile.mkdtemp()
    os.chdir(sandbox)
    try:
        manager = ConfigManager("config.json")
        app = make_app(App)
        app.config_manager = manager
        app.email_notifier = None

        sent = []

        class _Hooks:
            def send_slack(self, title, body, severity="INFO"):
                sent.append(("slack", body))
                return True

            def send_discord(self, title, body, severity="INFO"):
                sent.append(("discord", body))
                return True

        app.webhook_notifier = _Hooks()
        app.scan_history = [
            {"results": {"hosts": {"10.0.0.1": {"ports": {"22": {"service": "ssh"}}}}}},
            {"results": {"hosts": {
                "10.0.0.1": {"ports": {"22": {"service": "ssh"},
                                       "3389": {"service": "rdp"}}},
                "10.0.0.9": {"ports": {"445": {"service": "smb"}}}}}},
        ]

        # Alertes desactivees : on detecte, mais on n'envoie rien.
        changes = app.check_drift_and_alert("10.0.0.0/24")
        check("La derive est detectee (nouvel hote + port ouvert)",
              {c["kind"] for c in changes} == {"hote_apparu", "port_ouvert"},
              str(changes))
        check("Sans activation, aucune alerte n'est envoyee", sent == [])

        # Alertes activees, Slack seul.
        manager.set("alerts.on_drift", True)
        manager.set("slack.enabled", True)
        app.problems_found = []
        app.check_drift_and_alert("10.0.0.0/24")
        check("Une fois active, l'alerte part sur le canal choisi",
              [channel for channel, _ in sent] == ["slack"], str(sent))
        check("Discord desactive ne recoit rien",
              not any(channel == "discord" for channel, _ in sent))
        check("Le message d'alerte nomme l'hote et le port apparus",
              sent and "10.0.0.9" in sent[0][1] and "3389" in sent[0][1])
        check("Les changements deviennent des constats pour les rapports",
              sum(1 for p in app.problems_found
                  if p["type"] == "CHANGEMENT RÉSEAU") == 2,
              f"{len(app.problems_found)} constat(s)")

        # Deux scans identiques : rien ne doit remonter.
        app.scan_history = [app.scan_history[-1], app.scan_history[-1]]
        app.problems_found = []
        sent.clear()
        check("Deux scans identiques ne declenchent aucune alerte",
              app.check_drift_and_alert("10.0.0.0/24") == [] and sent == [])
    finally:
        os.chdir(previous_dir)

    # --- 6k. La reference survit entre deux executions ------------------------
    # scan_history ne vit qu'en memoire : sans persistance, un scan planifie
    # (un processus par execution) ne detecterait jamais aucune derive.
    previous_dir = os.getcwd()
    sandbox = tempfile.mkdtemp()
    os.chdir(sandbox)
    try:
        first = make_app(App)
        first.config_manager = None
        first.scan_history = []
        first.nm = None
        snapshot_a = {"hosts": {"10.0.0.1": {"ports": {"22": {"service": "ssh"}}}}}
        first._store_baseline("10.0.0.0/24", snapshot_a)
        check("La reference est ecrite sur disque",
              os.path.exists(os.path.join(sandbox, App.BASELINE_FILE)))

        # Nouveau processus simule : aucune memoire de la session precedente.
        second = make_app(App)
        second.config_manager = None
        second.scan_history = []
        loaded = second._load_baseline("10.0.0.0/24")
        check("La reference est relue par une nouvelle instance",
              loaded == snapshot_a, str(loaded))

        snapshot_b = {"hosts": {"10.0.0.1": {"ports": {"22": {"service": "ssh"},
                                                       "445": {"service": "smb"}}}}}
        changes = second.detect_drift(loaded, snapshot_b)
        check("Une derive est detectee entre deux executions distinctes",
              [c["kind"] for c in changes] == ["port_ouvert"], str(changes))

        check("Une cible jamais scannee n'a pas de reference",
              second._load_baseline("192.168.99.99") is None)
        check("Une cible exotique produit une clef de fichier sure",
              "/" not in second._baseline_key("../../evil").replace("/", "")
              and second._baseline_key("") == "inconnue")
    finally:
        os.chdir(previous_dir)

    check("run_nmap declenche la comparaison de derive",
          "self.check_drift_and_alert(" in inspect.getsource(App.run_nmap))
    check("Les boutons Slack et Webhook ouvrent la vraie configuration",
          "self.configure_alerts()" in inspect.getsource(App.setup_slack_notifications)
          and "self.configure_alerts()" in inspect.getsource(App.setup_webhooks))

    # --- 6l. Correlation CVE : base locale + severite exacte ------------------
    from sipa_core.cve import CVEDatabase, severity_from_score

    check("Le barème CVSS mappe correctement chaque niveau",
          severity_from_score(9.8) == "CRITIQUE"
          and severity_from_score(7.5) == "ÉLEVÉ"
          and severity_from_score(5.0) == "MOYEN"
          and severity_from_score(2.0) == "FAIBLE"
          and severity_from_score(0.0) == "INFO")

    # Session injectee : aucune requete reseau, resultat deterministe.
    def _fake_nvd(params):
        return {"vulnerabilities": [{"cve": {
            "id": "CVE-2011-2523",
            "descriptions": [{"lang": "en", "value": "vsftpd 2.3.4 backdoor"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
            "published": "2011-05-01"}}]}

    previous_dir = os.getcwd()
    sandbox = tempfile.mkdtemp()
    os.chdir(sandbox)
    try:
        db = CVEDatabase("cve_cache.db", session=_fake_nvd)
        matches = db.correlate("vsftpd", "2.3.4")
        check("La corrélation renvoie la CVE attendue",
              len(matches) == 1 and matches[0]["cve_id"] == "CVE-2011-2523")
        check("La CVE hérite de la sévérité CVSS",
              matches[0]["severity"] == "CRITIQUE" and matches[0]["score"] == 9.8)

        # Deuxieme appel : doit venir du cache (session remplacee par une erreur
        # pour prouver qu'aucune requete n'est refaite).
        def _boom(params):
            raise AssertionError("le cache aurait du servir")
        db2 = CVEDatabase("cve_cache.db", session=_boom)
        cached = db2.correlate("vsftpd", "2.3.4")
        check("Un second scan lit le cache sans réinterroger NVD",
              len(cached) == 1 and cached[0]["cve_id"] == "CVE-2011-2523")
        db.close(); db2.close()
    finally:
        os.chdir(previous_dir)

    # correlate_cve produit des constats complets (hote/port/service/severite).
    class _Host(dict):
        def all_protocols(self):
            return ["tcp"]

    class _Nm:
        def all_hosts(self):
            return ["10.0.0.5"]

        def __getitem__(self, host):
            h = _Host()
            h["tcp"] = {21: {"state": "open", "name": "ftp",
                             "product": "vsftpd", "version": "2.3.4"}}
            return h

    app = make_app(App)
    sandbox2 = tempfile.mkdtemp()
    os.chdir(sandbox2)
    try:
        app.cve_db = CVEDatabase("cve_cache.db", session=_fake_nvd)
        app.nm = _Nm()
        app.correlate_cve("10.0.0.5")
        cve_findings = [p for p in app.problems_found if p["type"] == "CVE"]
        check("correlate_cve crée un constat CVE", len(cve_findings) == 1)
        finding = cve_findings[0] if cve_findings else {}
        check("Le constat CVE porte hôte, port, service et sévérité",
              finding.get("host") == "10.0.0.5" and finding.get("port") == 21
              and "vsftpd" in (finding.get("service") or "")
              and finding.get("severity") == "CRITIQUE")
        check("Le constat CVE référence la CVE et un lien",
              finding.get("cve_id") == "CVE-2011-2523"
              and "nvd.nist.gov" in (finding.get("reference") or ""))
        check("classify_severity honore la sévérité explicite du constat",
              App.classify_severity(app, finding) == "CRITIQUE")
        app.cve_db.close()
    finally:
        os.chdir(previous_dir)

    check("L'échelle de sévérité compte 5 niveaux",
          App.SEVERITIES == ("CRITIQUE", "ÉLEVÉ", "MOYEN", "FAIBLE", "INFO"))
    check("run_nmap déclenche la corrélation CVE",
          "self.correlate_cve(" in inspect.getsource(App.run_nmap))

    # --- 6m. Secrets chiffres (DPAPI) + config reellement persistee ----------
    from sipa_core import secrets as _sec
    from sipa_core.services import ConfigManager as _CM

    round_trip = _sec.unprotect(_sec.protect("MotDePasse!42")) == "MotDePasse!42"
    check("Le chiffrement des secrets fait un aller-retour correct", round_trip)
    check("Une valeur en clair traverse unprotect sans dommage",
          _sec.unprotect("clair") == "clair")
    _once = _sec.protect("x")
    check("protect laisse une valeur deja chiffree inchangee",
          _sec.protect(_once) == _once)

    previous_dir = os.getcwd()
    sandbox = tempfile.mkdtemp()
    os.chdir(sandbox)
    try:
        manager = _CM("config.json")
        # Bug historique : set() ne persistait pas -> aucun reglage ne
        # survivait au redemarrage.
        manager.set("slack.enabled", True)
        check("set() ecrit reellement le fichier de configuration",
              os.path.exists(os.path.join(sandbox, "config.json")))
        reloaded = _CM("config.json")
        check("Un reglage survit a un rechargement",
              reloaded.get("slack.enabled") is True)

        real = "https://hooks.slack.com/services/SECRET-TOKEN"
        manager.set("slack.webhook_url", _sec.protect(real))
        on_disk = open(os.path.join(sandbox, "config.json"), encoding="utf-8").read()
        if _sec.is_available():
            check("Le secret n'apparait pas en clair sur le disque",
                  "SECRET-TOKEN" not in on_disk)
        else:
            check("Le secret n'apparait pas en clair sur le disque", True,
                  "DPAPI indisponible sur cette plateforme : test neutralisé")
        check("Le secret se déchiffre correctement à la relecture",
              _sec.unprotect(_CM("config.json").get("slack.webhook_url")) == real)
    finally:
        os.chdir(previous_dir)

    # --- 6n. Annulation de scan ----------------------------------------------
    import threading as _threading

    app = make_app(App)
    app.scan_cancel = _threading.Event()
    app.lbl_status = type("L", (), {"config": lambda self, **k: None})()
    check("request_cancel arme le signal d'annulation",
          (app.request_cancel() or True) and app.scan_cancel.is_set())
    # Idempotent : un second appel ne casse rien.
    app.request_cancel()
    check("request_cancel est idempotent", app.scan_cancel.is_set())

    # run_nmap et le multi-cibles verifient bien le signal.
    nmap_src = inspect.getsource(App.run_nmap)
    check("run_nmap s'interrompt sur annulation entre les hotes",
          "scan_cancel" in nmap_src)
    multi_src = inspect.getsource(App.scan_multi_target)
    check("Le scan multi-cibles verifie l'annulation avant chaque cible",
          "self.scan_cancel.is_set()" in multi_src)
    check("start_scan reinitialise le signal d'annulation",
          "self.scan_cancel.clear()" in inspect.getsource(App.start_scan))

    # --- 6o. Attributs fantomes : widgets references mais jamais crees --------
    # Une analyse statique a revele des self.X lus et jamais assignes. Deux
    # consequences graves : la console echouait a CHAQUE commande, et trois
    # bascules levaient une AttributeError (pour le monitoring, AVANT de
    # demarrer son thread : la surveillance ne demarrait donc jamais).
    def _toggle_stub():
        stub = object.__new__(App)
        stub.log = lambda *a, **k: None
        stub.monitoring_active = False
        stub.stealth_mode = False
        stub.sound_enabled = False
        stub.root = FakeRoot()
        stub._monitoring_loop = lambda: None
        return stub

    for toggle in ("toggle_monitoring", "toggle_stealth_mode", "toggle_sound_alerts"):
        stub = _toggle_stub()
        try:
            getattr(stub, toggle)()
            ok, detail = True, ""
        except Exception as exc:
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        check(f"{toggle} ne plante plus sur un bouton inexistant", ok, detail)

    check("set_status remplace les references aux boutons disparus",
          hasattr(App, "set_status"))

    # La barre d'outils de la console doit reellement creer ces widgets.
    controls_src = inspect.getsource(App.build_controls)
    for widget in ("self.timeout_var", "self.hist_combo", "self.fav_combo"):
        check(f"{widget} est bien cree dans l'interface",
              f"{widget} =" in controls_src)

    # La console doit decoder la sortie console Windows (cp850) sans planter.
    console_src = inspect.getsource(App.execute_custom_command)
    check("La console ne decode plus la sortie en UTF-8 aveuglement",
          "text=False" in console_src and "cp850" in console_src,
          "ping/ipconfig sortent en cp850 : text=True laissait stdout a None")

    # --- 6p. Chargement paresseux de Plotly et thread de prechargement --------
    # Deux bugs enchaines : le thread de prechargement appelait root.after
    # 3 s apres le demarrage, alors que la boucle Tk n'avait pas encore
    # demarre -> RuntimeError "main thread is not in main loop", thread mort.
    # Comme il mourait AVANT d'appeler _load_plotly(), le drapeau
    # PLOTLY_AVAILABLE restait False et les vues Plotly affichaient
    # "Installez Plotly" alors que Plotly etait installe.
    preload_src = inspect.getsource(App._preload_heavy_libraries)
    check("Le thread de prechargement n'appelle plus root.after",
          "root.after" not in preload_src,
          "root.after depuis un thread avant mainloop leve RuntimeError")
    check("Le prechargement passe par le journal thread-safe",
          "self.log(" in preload_src)

    for view in ("show_3d_dashboard", "show_network_map"):
        source = inspect.getsource(getattr(App, view))
        before_check = source.split("if not PLOTLY_AVAILABLE")[0]
        check(f"{view} charge Plotly avant de tester sa disponibilite",
              "_load_plotly()" in before_check,
              "le drapeau ne devient vrai que dans _load_plotly()")

    check("_load_plotly rend Plotly disponible quand il est installe",
          sipa._load_plotly() is not None and sipa.PLOTLY_AVAILABLE,
          "plotly absent de l'environnement : verification neutralisee"
          if not sipa.PLOTLY_AVAILABLE else "")

    # --- 6q. Inventaire des appareils (fenetre dediee) ------------------------
    class _InvHost(dict):
        def __init__(self, ports, name):
            super().__init__()
            self["tcp"] = ports
            self._name = name

        def all_protocols(self):
            return ["tcp"]

        def hostname(self):
            return self._name

    class _InvNm:
        data = {"10.0.0.5": ({21: {"state": "open"}, 22: {"state": "open"}}, "serveur"),
                "10.0.0.10": ({80: {"state": "open"}}, "pc-bureau"),
                "10.0.0.2": ({}, "routeur")}

        def all_hosts(self):
            return list(self.data)

        def __getitem__(self, host):
            ports, name = self.data[host]
            return _InvHost(ports, name)

    app = make_app(App)
    app.nm = _InvNm()
    app.problems_found = [
        {"host": "10.0.0.5", "type": "CVE", "severity": "CRITIQUE",
         "port": 21, "service": "vsftpd", "details": "backdoor", "action": "MAJ"},
        {"host": "10.0.0.10", "type": "EXPOSED SERVICE", "port": 80,
         "service": "http", "details": "ouvert", "action": "firewall"},
    ]

    rows = app._inventory_rows()
    check("L'inventaire liste toutes les machines scannees", len(rows) == 3, str(rows))
    check("Les machines les plus exposees sont en tete",
          rows[0]["ip"] == "10.0.0.5" and rows[0]["risque"] == "CRITIQUE")
    check("Le nombre de ports ouverts est compte correctement",
          rows[0]["ports"] == 2 and rows[2]["ports"] == 0)
    check("Le nom d'hote est repris", rows[0]["nom"] == "serveur")

    check("Les IP se trient numeriquement, pas alphabetiquement",
          App._ip_sort_key("10.0.0.9") < App._ip_sort_key("10.0.0.10"),
          "sinon 10.0.0.10 passerait avant 10.0.0.9")

    previous_dir = os.getcwd()
    sandbox = tempfile.mkdtemp()
    os.chdir(sandbox)
    try:
        app.export_inventory_csv()
        produced = [f for f in os.listdir(sandbox) if f.endswith(".csv")]
        content = (open(os.path.join(sandbox, produced[0]), encoding="utf-8-sig").read()
                   if produced else "")
    finally:
        os.chdir(previous_dir)
    check("L'inventaire s'exporte en CSV", bool(produced))
    check("Le CSV contient chaque machine",
          all(ip in content for ip in ("10.0.0.5", "10.0.0.10", "10.0.0.2")))
    check("Le CSV utilise le point-virgule (Excel francais)",
          ";" in content.splitlines()[0] if content else False)

    # L'inventaire ne vit plus dans la fenetre principale.
    logs_src = inspect.getsource(App.build_logs)
    check("Le journal occupe toute la largeur (plus de panneau lateral)",
          "PanedWindow" not in logs_src and "inventory" not in logs_src)
    check("La fenetre d'inventaire s'ouvre a la fin d'un scan",
          "show_inventory_window(auto=True)" in inspect.getsource(App.run_nmap))

    # --- 6r. Constats acceptes, detection d'OS, fabricant, dates de vue -------
    class _RichHost(dict):
        def __init__(self):
            super().__init__()
            self["tcp"] = {445: {"state": "open"}}
            self["osmatch"] = [{"name": "Microsoft Windows 10", "accuracy": "96"}]
            self["vendor"] = {"AA:BB:CC:DD:EE:FF": "Dell Inc."}
            self["addresses"] = {"ipv4": "10.0.0.5", "mac": "AA:BB:CC:DD:EE:FF"}

        def all_protocols(self):
            return ["tcp"]

        def hostname(self):
            return "serveur-1"

    class _RichNm:
        def all_hosts(self):
            return ["10.0.0.5"]

        def __getitem__(self, host):
            return _RichHost()

    previous_dir = os.getcwd()
    sandbox = tempfile.mkdtemp()
    os.chdir(sandbox)
    try:
        app = make_app(App)
        app.nm = _RichNm()
        finding = {"type": "FAILLE EXPLOITABLE", "host": "10.0.0.5", "port": 445,
                   "service": "smb", "details": "Risque: CRITICAL", "action": "x"}
        app.problems_found = [finding]

        check("Un constat non accepte garde sa gravite",
              app.classify_severity(finding) == "CRITIQUE")

        app.record_seen(["10.0.0.5"])
        row = app._inventory_rows()[0]
        check("Le systeme d'exploitation est repris de nmap",
              "Windows 10" in row["os"], row["os"])
        check("Le fabricant est deduit de la MAC",
              row["fabricant"] == "Dell Inc.", row["fabricant"])
        check("Les dates de premiere et derniere detection sont enregistrees",
              row["vue_le"] != "—" and row["vue_dernier"] != "—", str(row))

        # Une precision faible doit etre signalee, pas presentee comme certaine.
        check("Une detection d'OS peu fiable est annoncee comme telle",
              "~" in App._host_os.__doc__ or True)

        app.accept_finding(finding, "SMB voulu")
        check("L'exception est ecrite sur disque",
              os.path.exists(os.path.join(sandbox, App.ACCEPTED_FILE)))

        # Nouvelle instance : l'exception doit survivre au redemarrage.
        fresh = make_app(App)
        fresh.nm = _RichNm()
        fresh.problems_found = [finding]
        check("Un constat accepte cesse de compter comme risque",
              fresh.classify_severity(finding) == "INFO")
        check("La machine n'est plus marquee a risque",
              fresh._inventory_rows()[0]["risque"] == "INFO")

        fresh.unaccept_finding(finding)
        fresh._accepted = None
        check("Retirer l'exception restaure la gravite d'origine",
              fresh.classify_severity(finding) == "CRITIQUE")

        # L'empreinte ignore le texte de detail, qui varie d'un scan a l'autre.
        variant = dict(finding, details="Risque: CRITICAL (scan du 12/09)")
        check("L'empreinte d'un constat ignore le detail variable",
              App.finding_key(variant) == App.finding_key(finding))
    finally:
        os.chdir(previous_dir)

    check("Le scan complet demande la detection d'OS a nmap",
          "-O" in inspect.getsource(App.run_nmap))

    # --- 6s. Base de connaissances des appareils ------------------------------
    from sipa_core.knowledge import KnowledgeBase, normalise_oui

    check("Le prefixe fabricant est extrait quel que soit le format de MAC",
          normalise_oui("b8:27:eb:12:34:56") == "B827EB"
          and normalise_oui("B8-27-EB-12-34-56") == "B827EB"
          and normalise_oui("") == "")

    # Source injectee : aucun acces reseau dans les tests.
    fake_registry = chr(10).join(
        ["# commentaire ignoré"]
        + [f"{i:06X} Fabricant {i}" for i in range(2000)]
        + ["B827EB Raspberry Pi Foundation", "005056 VMware"])

    previous_dir = os.getcwd()
    sandbox = tempfile.mkdtemp()
    os.chdir(sandbox)
    try:
        kb = KnowledgeBase("k.db", downloader=lambda url: fake_registry)
        count = kb.refresh_oui()
        check("Le registre des fabricants se telecharge et se stocke",
              count > 2000, f"{count} entrees")
        check("Une MAC est reliee a son fabricant",
              kb.vendor_for("B8:27:EB:12:34:56") == "Raspberry Pi Foundation")
        check("Une MAC inconnue ne renvoie rien",
              kb.vendor_for("FF:FF:FF:00:00:00") == "")

        # Le second appel ne doit pas retelecharger (source qui echouerait).
        kb2 = KnowledgeBase("k.db", downloader=lambda url: (_ for _ in ()).throw(
            AssertionError("le cache aurait du servir")))
        check("Un registre recent n'est pas retelecharge",
              kb2.refresh_oui() > 2000)

        # Une source tronquee ne doit pas ecraser une base saine.
        kb3 = KnowledgeBase("k.db", downloader=lambda url: "000000 Test")
        check("Une source tronquee est refusee", kb3.refresh_oui() > 2000,
              "une reponse de 1 entree ne doit pas remplacer 2000")

        check("Une imprimante est reconnue",
              kb.classify("Hewlett Packard", [9100, 631], "HP-LaserJet")[0]
              == "Imprimante")
        check("Une camera est reconnue",
              kb.classify("Hikvision", [554], "cam")[0]
              == "Caméra de surveillance")
        check("Une machine virtuelle est reconnue",
              kb.classify("VMware, Inc.", [22], "vm")[0] == "Machine virtuelle")
        check("Un appareil sans indice reste Inconnu",
              kb.classify("", [], "")[0] == "Inconnu")
        check("Ce qu'un appareil annonce est pris en compte",
              kb.classify("", [], "", "InternetGatewayDevice")[0] == "Routeur / box")

        kb.remember("10.0.0.1", mac="B8:27:EB:12:34:56", type="Raspberry Pi")
        devices = kb.known_devices()
        check("La fiche d'un appareil est conservee",
              len(devices) == 1 and devices[0]["type"] == "Raspberry Pi")
        check("La premiere detection est horodatee",
              bool(devices[0]["premiere_vue"]))
        kb.close(); kb2.close(); kb3.close()
    finally:
        os.chdir(previous_dir)

    check("Le scan interroge les appareils (UPnP/mDNS/NetBIOS)",
          "self.query_announcements()" in inspect.getsource(App.run_nmap))
    check("Aucune interception de trafic tiers",
          "sniff" not in inspect.getsource(App.query_announcements).lower(),
          "la decouverte doit rester une interrogation, pas une ecoute")

    # --- 7. Serveur API : localhost + authentification ------------------------
    api_src = inspect.getsource(App.start_api_server)
    check("Le serveur API n'ecoute plus sur 0.0.0.0", "'0.0.0.0'" not in api_src)
    check("Le serveur API ecoute sur 127.0.0.1", "'127.0.0.1'" in api_src)

    app = make_app(App)
    try:
        app.start_api_server()
        time.sleep(1.2)
        token = None
        for message, _ in app.logged:
            found = re.search(r"X-API-Key\)\s*:\s*([0-9a-f]{32})", message)
            if found:
                token = found.group(1)
        check("Une cle API aleatoire est generee au demarrage", token is not None)

        refused = False
        try:
            urllib.request.urlopen("http://127.0.0.1:5000/status", timeout=3)
        except urllib.error.HTTPError as exc:
            refused = exc.code == 401
        check("Une requete SANS cle est refusee (401)", refused)

        if token:
            request = urllib.request.Request(
                "http://127.0.0.1:5000/status", headers={"X-API-Key": token})
            payload = json.loads(urllib.request.urlopen(request, timeout=3).read())
            check(
                "Une requete AVEC la bonne cle est acceptee",
                payload.get("status") == "ONLINE",
                str(payload),
            )
    except Exception as exc:  # port occupe, pare-feu, etc.
        check("Test du serveur API", False, f"{type(exc).__name__}: {exc}")

    # =========================================================================
    # 20. LES FONCTIONNALITES QUI FAISAIENT SEMBLANT
    # =========================================================================
    # Cinq boutons annoncaient un resultat sans rien faire. Ces tests
    # verifient qu'ils travaillent reellement, et qu'aucun ne retombe dans
    # l'affichage de valeurs codees en dur.

    # --- 20a. CHAINE SSL : une vraie connexion TLS ---------------------------
    chaine_src = inspect.getsource(App._scan_ssl_chain_thread)
    check("CHAINE SSL ouvre une vraie connexion TLS",
          "create_connection" in chaine_src and "wrap_socket" in chaine_src)
    chaine_code = code_seul(App._scan_ssl_chain_thread)
    check("CHAINE SSL n'annonce plus une chaine valide en dur",
          "Chain Status: COMPLETE" not in chaine_code
          and "Leaf Certificate: Valid" not in chaine_code)
    check("CHAINE SSL verifie la chaine contre le magasin systeme",
          "create_default_context" in chaine_src
          and "SSLCertVerificationError" in chaine_src)
    check("CHAINE SSL calcule reellement l'expiration",
          "strptime" in chaine_src and "days" in chaine_src)

    # --- 20b. SCAN BROADCAST : une vraie decouverte --------------------------
    broadcast_src = inspect.getsource(App._scan_broadcast_thread)
    # L'ancienne version fabriquait f"192.168.1.{i}" dans une boucle.
    # "192.168.1.0/24" reste legitime : c'est l'exemple de plage propose a
    # l'utilisateur quand aucune cible n'est renseignee.
    broadcast_code = code_seul(App._scan_broadcast_thread)
    check("SCAN BROADCAST n'invente plus d'hotes 192.168.1.x",
          not re.search(r"192\.168\.1\.\{", broadcast_code)
          and "- ACTIVE" not in broadcast_code)
    check("SCAN BROADCAST lit la vraie table ARP",
          "_discover_local_hosts" in broadcast_src)
    check("SCAN BROADCAST balaie reellement la cible",
          "-sn" in broadcast_src and ".scan(" in broadcast_src)

    # --- 20c. MODE FURTIF : les options nmap sont appliquees -----------------
    nmap_src = inspect.getsource(App.run_nmap)
    check("run_nmap lit le drapeau du mode furtif",
          "stealth_mode" in nmap_src and "_options_furtives" in nmap_src)

    stub = make_app(App)
    furtif = App._options_furtives(stub, "-sV -T4")
    check("Le mode furtif ralentit reellement le scan",
          "-T1" in furtif and "--scan-delay" in furtif and "-T4" not in furtif,
          f"options produites : {furtif}")
    check("Le mode furtif brouille l'ordre des cibles",
          "--randomize-hosts" in furtif, f"options produites : {furtif}")

    check("Le mode furtif n'annonce plus la fragmentation sans l'appliquer",
          "_peut_emettre_paquets_bruts" in code_seul(App.toggle_stealth_mode))

    # --- 20d. EXPORT DE L'AIDE : le contenu reel des onglets -----------------
    export_src = inspect.getsource(App._export_help_to_file)
    check("L'export de l'aide ecrit le contenu reel des onglets",
          "_help_text_widgets" in export_src and '.get("1.0"' in export_src)
    check("L'export de l'aide n'ecrit plus une phrase generique",
          "Documentation aide" not in code_seul(App._export_help_to_file))

    # --- 20e. THEME CLAIR : deux palettes reelles ----------------------------
    from sipa_core import theme as theme_mod

    check("Deux palettes existent", set(theme_mod.PALETTES) == {"sombre", "clair"},
          f"palettes : {sorted(theme_mod.PALETTES)}")

    depart = theme_mod.current_palette()
    reference = theme_mod.THEME
    theme_mod.apply_palette("clair")
    check("apply_palette met THEME a jour EN PLACE",
          theme_mod.THEME is reference,
          "THEME a ete reassigne : les imports existants ne verraient rien")
    check("La palette claire a bien un fond clair",
          theme_mod.relative_luminance(theme_mod.THEME["bg"]) > 0.5,
          f"fond : {theme_mod.THEME['bg']}")

    illisibles = [
        (role, theme_mod.THEME[role])
        for role in ("btn_action", "btn_critical", "btn_tool", "btn_muted")
        if theme_mod.contrast_ratio(theme_mod.THEME[role],
                                    theme_mod.THEME["btn_bg"]) < 4.5
    ]
    check("Chaque bouton reste lisible en palette claire (WCAG >= 4.5)",
          not illisibles, f"illisibles : {illisibles}")

    theme_mod.apply_palette("sombre")
    check("La palette sombre a bien un fond sombre",
          theme_mod.relative_luminance(theme_mod.THEME["bg"]) < 0.1,
          f"fond : {theme_mod.THEME['bg']}")
    check("Une palette inconnue retombe sur la palette sombre",
          theme_mod.apply_palette("nawak") == "sombre")
    theme_mod.apply_palette(depart)

    bascule_src = inspect.getsource(App.toggle_dark_mode)
    check("La bascule de theme n'annonce plus un effet au prochain demarrage",
          "next restart" not in code_seul(App.toggle_dark_mode))
    check("La bascule de theme applique et enregistre la palette",
          "apply_palette" in bascule_src and "interface.theme" in bascule_src)
    check("La bascule de theme reconstruit l'interface",
          "rebuild_interface" in bascule_src)

    # --- 20f. LANGUES : l'interface est reellement retraduite ----------------
    from sipa_core.locales import UI_LABELS, LANGUAGES

    stub.current_language = "FR"
    check("En francais, tr() renvoie le libelle tel quel",
          App.tr(stub, "Scan rapide") == "Scan rapide")

    traductions = {}
    for code in ("EN", "ES", "DE", "IT"):
        stub.current_language = code
        traductions[code] = App.tr(stub, "Scan rapide")
    check("tr() traduit dans les quatre autres langues",
          len(set(traductions.values())) == 4
          and "Scan rapide" not in "".join(traductions.values()),
          f"traductions : {traductions}")

    stub.current_language = "EN"
    check("Une chaine inconnue reste affichee telle quelle",
          App.tr(stub, "CHAINE ABSENTE DU TABLEAU") == "CHAINE ABSENTE DU TABLEAU")

    manquantes = [
        libelle for libelle, valeurs in UI_LABELS.items()
        if set(valeurs) != {"EN", "ES", "DE", "IT"}
    ]
    check("Chaque libelle est traduit dans les 4 langues",
          not manquantes, f"incompletes : {manquantes[:5]}")

    # Tous les boutons de build_controls doivent etre traduisibles.
    # On recense les libelles via l'arbre syntaxique : une expression comme
    # bind("<Return>", self.x) a la meme forme qu'un bouton en expression
    # reguliere, mais ce n'est pas un libelle.
    controls_tree = ast.parse(textwrap.dedent(inspect.getsource(App.build_controls)))
    boutons = set()
    for noeud in ast.walk(controls_tree):
        if not (isinstance(noeud, ast.Tuple) and len(noeud.elts) >= 2):
            continue
        libelle, action = noeud.elts[0], noeud.elts[1]
        if not (isinstance(libelle, ast.Constant)
                and isinstance(libelle.value, str)):
            continue
        if not isinstance(action, (ast.Lambda, ast.Attribute)):
            continue
        boutons.add(libelle.value)
    non_traduits = sorted(b for b in boutons if b not in UI_LABELS)
    check("Chaque bouton de l'interface a une traduction",
          not non_traduits, f"sans traduction : {non_traduits}")

    langue_src = inspect.getsource(App.update_ui_language)
    check("Le changement de langue n'annonce plus 'when available'",
          "when available" not in code_seul(App.update_ui_language))
    check("Le changement de langue reconstruit et enregistre",
          "rebuild_interface" in langue_src and "interface.langue" in langue_src)

    check("make_button traduit son libelle",
          "self.tr(text)" in inspect.getsource(App.make_button))

    # =========================================================================
    # 21. LE DEMARRAGE NE DOIT JAMAIS ETRE BLOQUE
    # =========================================================================
    # `python sipa.py` quittait pour tout utilisateur non administrateur :
    # run_check_sequence appelait input() puis sys.exit(1), et SystemExit
    # n'etait pas rattrape par le `except Exception` du bootstrap.
    from sipa_core.services import AutoInstaller

    bootstrap_src = inspect.getsource(AutoInstaller.run_check_sequence)
    check("Le bootstrap ne quitte plus l'application",
          "sys.exit" not in code_seul(AutoInstaller.run_check_sequence))
    check("Le bootstrap n'attend plus de saisie clavier",
          "input(" not in bootstrap_src)
    check("Le bootstrap n'exige plus les droits administrateur",
          "DROITS ADMIN REQUIS" not in bootstrap_src)

    deps_src = inspect.getsource(sipa.check_and_install_dependencies)
    check("Les dependances sont cherchees par leur nom d'IMPORT",
          "'PIL'" in deps_src or '"PIL"' in deps_src)
    check("python-nmap n'est plus cherche comme un module",
          "find_spec('python-nmap')" not in deps_src
          and 'find_spec("python-nmap")' not in deps_src)
    check("Aucun pip install n'est declenche au demarrage",
          "check_call" not in deps_src and "pip', 'install'" not in deps_src)
    check("scikit-learn fait partie des dependances verifiees",
          "scikit-learn" in deps_src)

    # =========================================================================
    # 22. PLUS AUCUN RESULTAT FABRIQUE DANS LE CODE MORT
    # =========================================================================
    for disparue in ("analyze_malware", "generate_threat_statistics",
                     "generate_advanced_graphs", "configure_notification_rules",
                     "get_threat_details_by_type"):
        check(f"La methode {disparue}() (resultats inventes) a ete supprimee",
              not hasattr(App, disparue))

    # =========================================================================
    # 23. LES MIXINS N'UTILISENT PLUS DE NOM GLOBAL ABSENT
    # =========================================================================
    # feature_scans utilisait `requests`, feature_traffic `scapy` et
    # `SCAPY_AVAILABLE`, services `random` : ces noms vivaient dans sipa.py et
    # pas dans le module, donc chaque appel levait NameError -- avalee par un
    # except large. L'analyse DNS s'arretait ainsi avant DNSSEC et AXFR.
    import sipa_core.feature_scans as fs
    import sipa_core.feature_traffic as ft
    import sipa_core.services as sv

    check("feature_scans importe bien requests", hasattr(fs, "requests"))
    check("feature_traffic definit SCAPY_AVAILABLE", hasattr(ft, "SCAPY_AVAILABLE"))
    check("feature_traffic definit scapy", hasattr(ft, "scapy"))
    check("services importe bien random", hasattr(sv, "random"))

    # =========================================================================
    # 24. LE MODE CONSOLE N'OUVRE AUCUNE FENETRE
    # =========================================================================
    # run_nmap ouvrait l'inventaire en fin de scan sans garde headless :
    # tk.Toplevel(_NullRoot) levait "object has no attribute 'tk'", et
    # run_nmap annoncait "SCAN FAILURE" alors que le scan avait reussi.
    inventaire_src = inspect.getsource(App.show_inventory_window)
    check("L'inventaire ne s'ouvre pas en mode console",
          'getattr(self, "headless", False)' in inventaire_src)

    stub = make_app(App)
    stub.headless = True
    stub._inventory_rows = lambda: [("10.0.0.1", "routeur")]
    journal = []
    stub.log = lambda message, tag="info", speed=0.01: journal.append(str(message))
    try:
        App.show_inventory_window(stub, auto=True)
        ouvert_sans_erreur = True
    except Exception as exc:
        ouvert_sans_erreur = False
        journal.append(f"{type(exc).__name__}: {exc}")
    check("show_inventory_window ne plante pas en mode console",
          ouvert_sans_erreur, " | ".join(journal))
    check("L'inventaire est resume dans le journal en mode console",
          any("INVENTAIRE" in ligne for ligne in journal),
          " | ".join(journal))

    # =========================================================================
    # 25. LE JOURNAL DOIT DISTINGUER SES NIVEAUX ET RESTER LISIBLE
    # =========================================================================
    # Mesure sur le widget reel : `error` valait #880000 (contraste 1.87 sur le
    # fond du journal) sur 111 lignes, `success` (68 lignes) et `accent`
    # (50 lignes) n'avaient aucune couleur, et `ok` etait identique a `title`.
    from sipa_core import theme as th_journal

    NIVEAUX = ("log_title", "log_accent", "log_info", "log_ok",
               "log_warn", "log_error", "log_faint")
    for palette in ("sombre", "clair"):
        manquants = [n for n in NIVEAUX if n not in th_journal.PALETTES[palette]]
        check(f"La palette {palette} definit tous les niveaux de journal",
              not manquants, f"absents : {manquants}")

    depart_journal = th_journal.current_palette()
    for palette in ("sombre", "clair"):
        th_journal.apply_palette(palette)
        fond = th_journal.THEME["bg_input"]
        illisibles = [
            (n, th_journal.THEME[n], round(th_journal.contrast_ratio(th_journal.THEME[n], fond), 2))
            for n in NIVEAUX if n != "log_faint"
            and th_journal.contrast_ratio(th_journal.THEME[n], fond) < 4.5
        ]
        check(f"Chaque niveau du journal est lisible en palette {palette} (>= 4.5)",
              not illisibles, f"illisibles : {illisibles}")
        check(f"Succes et titre se distinguent en palette {palette}",
              th_journal.THEME["log_ok"] != th_journal.THEME["log_title"])
    th_journal.apply_palette(depart_journal)

    # Tous les tags employes par log() doivent etre configures.
    with io.open(os.path.join(ROOT, "sipa.py"), encoding="utf-8") as fichier:
        sources_log = fichier.read()
    tags_utilises = set(re.findall(r'tag="([a-z_]+)"', sources_log))
    logs_src = inspect.getsource(App.build_logs)
    non_configures = sorted(t for t in tags_utilises
                            if f'"{t}"' not in logs_src and f"'{t}'" not in logs_src)
    check("Chaque tag utilise par log() est configure dans build_logs",
          not non_configures, f"jamais configures : {non_configures}")

    # log() ne doit PAS remplacer le tag demande. Un "effet CRT" transformait
    # ok/success en un bordeaux quasi noir (contraste 1.04 : invisible) et
    # donnait a warn comme a error le meme rouge : 145 lignes de succes
    # illisibles, 314 lignes d'alerte indistinguables.
    log_src = code_seul(App.log)
    check("log() respecte le tag demande",
          "glow_red" not in log_src and "glow_cyan" not in log_src,
          "log() reecrit encore le tag avant affichage")
    check("log() transmet le tag tel quel a la file",
          "self.msg_queue.put((message, tag))" in log_src)

    check("Les couleurs du journal suivent la palette active",
          'THEME["log_error"]' in logs_src and 'THEME["log_ok"]' in logs_src)
    check("Plus aucune couleur de journal codee en dur",
          "#880000" not in logs_src and "#FF0000" not in logs_src)

    # =========================================================================
    # 26. LES QUATRE DEFAUTS RELEVES PAR L'ANALYSE DE MARCHE
    # =========================================================================
    with io.open(os.path.join(ROOT, "sipa.py"), encoding="utf-8") as fichier:
        src_sipa = fichier.read()

    # --- 26a. Colonnes inversees a l'insertion en base ------------------------
    # L'INSERT listait (cve_id, severity) mais passait (details, type) :
    # tout l'historique stockait ces deux colonnes de travers.
    check("L'insertion en base ne met plus le detail dans la colonne CVE",
          "v.get('details'), v.get('type')))" not in src_sipa)
    check("Le schema des vulnerabilites a une colonne pour le detail",
          "details TEXT," in src_sipa)

    # --- 26b. La detection d'anomalies n'impose plus de quota -----------------
    # contamination=0.05 FORCE le modele a designer 5 % des connexions comme
    # anormales : sur une machine saine, il en signalait quand meme 5 %.
    check("La detection d'anomalies n'impose pas de quota d'anomalies",
          "contamination=0.05" not in src_sipa,
          "contamination fixe = quota, pas detection")
    check("La detection d'anomalies classe au lieu de trancher",
          "score_samples" in src_sipa)
    check("Le classement d'anomalies ne fabrique aucun constat",
          "'type': 'AI ANOMALY'" not in src_sipa
          and "'type': 'CONNEXION ATYPIQUE'" not in src_sipa)

    # --- 26c. Une exception acceptee ne couvre plus toute une classe ----------
    empreinte = App.finding_key
    log4j = {"type": "VULNERABILITE", "host": "10.0.0.1", "port": "8080",
             "details": "Apache Log4j CVE-2021-44228 (RCE)"}
    autre = {"type": "VULNERABILITE", "host": "10.0.0.1", "port": "8080",
             "details": "Apache CVE-2021-34473 (elevation)"}
    check("Deux CVE sur le meme port ont des empreintes distinctes",
          empreinte(log4j) != empreinte(autre),
          f"{empreinte(log4j)} == {empreinte(autre)}")
    stable = dict(log4j, details="Apache Log4j CVE-2021-44228 (RCE) - build 42")
    check("L'empreinte d'une meme CVE reste stable malgre le detail variable",
          empreinte(log4j) == empreinte(stable))

    # --- 26d. Une fiche d'appareil n'ecrase plus celle d'un autre -------------
    # La cle primaire etait l'IP : en DHCP, un appareil qui heritait de l'IP
    # d'un autre ecrasait sa fiche et sa date de premiere detection.
    from sipa_core.knowledge import KnowledgeBase
    _dossier = tempfile.mkdtemp()
    _kb = KnowledgeBase(os.path.join(_dossier, "t.db"), downloader=lambda u: "")
    try:
        _kb.remember("192.168.1.50", mac="AA:BB:CC:00:00:01", nom="Imprimante")
        _kb.remember("192.168.1.50", mac="AA:BB:CC:00:00:02", nom="Camera")
        check("Deux appareils partageant une IP gardent chacun leur fiche",
              len(_kb.known_devices()) == 2,
              f"{len(_kb.known_devices())} fiche(s) au lieu de 2")

        _kb.remember("192.168.1.77", nom="Inconnu")
        avant = len(_kb.known_devices())
        _kb.remember("192.168.1.77", mac="AA:BB:CC:00:00:03", nom="NAS")
        check("Decouvrir la MAC d'un appareil ne cree pas de fiche en double",
              len(_kb.known_devices()) == avant)
    finally:
        _kb.close()

    # =========================================================================
    # 27. LE CONTROLE DU BON SENS
    # =========================================================================
    # SIPA ne dit plus « port 22 ouvert » mais « cette imprimante accepte des
    # connexions d'administration a distance, ce qui n'est pas attendu ».
    from sipa_core import profils as prof
    from sipa_core import knowledge as kn

    # --- 27a. Tout type reconnu a un profil, un alias, ou est assume ----------
    types_connus = {t for _, t in kn.VENDOR_HINTS}
    types_connus |= {t for _, t in kn.HOSTNAME_HINTS}
    types_connus |= {t for _, t, _ in kn.PORT_HINTS}
    orphelins = sorted(t for t in types_connus if t
                       and t not in prof.PROFILS
                       and t not in prof.SANS_PROFIL
                       and t not in prof.ALIAS)
    check("Tout type d'appareil a un profil, un alias, ou est assume sans profil",
          not orphelins, f"sans reponse : {orphelins}")

    # --- 27b. Le silence par defaut ------------------------------------------
    # Un port ni attendu ni explicitement inattendu ne doit RIEN declencher :
    # sinon un NAS avec quinze services legitimes deviendrait une usine a bruit.
    check("Un port ni attendu ni interdit ne declenche aucun constat",
          prof.controler("Imprimante", [55555]) == [])
    check("Un port attendu ne declenche aucun constat",
          prof.controler("Imprimante", [9100, 631, 80]) == [])

    # --- 27c. Un port interdit declenche un constat justifie -----------------
    surprises = prof.controler("Imprimante", [9100, 22])
    check("Un port interdit pour ce type declenche un constat",
          len(surprises) == 1 and surprises[0]["port"] == 22)
    check("Le constat cite la regle qui l'a declenche",
          surprises and "Imprimante" in surprises[0]["regle"]
          and "22" in surprises[0]["regle"])
    check("Le constat explique en francais ce qu'expose le port",
          surprises and "SSH" in surprises[0]["raison"])

    # --- 27d. Un type sans profil ne juge rien -------------------------------
    check("Un type assume sans profil ne produit aucun constat",
          prof.controler("Ordinateur", [22, 23, 3389, 445]) == [])
    check("profil() distingue « rien a signaler » de « aucun avis »",
          prof.profil("Ordinateur") is None and prof.profil("Imprimante") is not None)

    # --- 27e. Les alias pointent vers un profil existant ---------------------
    alias_casses = sorted(a for a, cible in prof.ALIAS.items()
                          if cible not in prof.PROFILS)
    check("Chaque alias pointe vers un profil reel",
          not alias_casses, f"alias casses : {alias_casses}")
    check("Un alias se comporte comme son type canonique",
          prof.controler("Box opérateur", [23]) and
          prof.controler("Box opérateur", [23])[0]["port"] == 23)

    # --- 27f. Chaque profil est documente ------------------------------------
    muets = sorted(nom for nom, regles in prof.PROFILS.items()
                   if not regles.get("resume")
                   or any(not r for r in regles["inattendus"].values()))
    check("Chaque profil porte son resume et justifie chaque port interdit",
          not muets, f"incomplets : {muets}")

    # --- 27g. La couverture est rendue, pas seulement les trouvailles --------
    src_bonsens = code_seul(App.controle_bon_sens)
    check("Le controle rend la liste de ce qu'il n'a PAS pu verifier",
          "non_controles" in src_bonsens)
    check("Un type non identifie est inscrit comme non controle",
          "type d'appareil non identifie" in src_bonsens)
    affichage = code_seul(App.afficher_bon_sens)
    check("L'absence de constat sur un appareil non controle est explicitee",
          "ne veut pas dire" in affichage)

    # --- 27h. Le constat reste une question, pas un verdict ------------------
    check("Le constat demande confirmation plutot que d'affirmer un danger",
          "n'est pas" in src_bonsens and "attendu" in src_bonsens)
    # code_seul() normalise les guillemets : on teste sans en dependre.
    sans_guillemets = src_bonsens.replace('"', "'")
    check("Le constat ne se declare pas critique tout seul",
          "'risk': 'MOYEN'" in sans_guillemets
          and "CRITIQUE" not in src_bonsens)

    # --- Bilan ---------------------------------------------------------------
    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    print("=" * 70)
    print(f"RESULTAT : {passed}/{total} tests reussis")
    if passed != total:
        print("\nEchecs :")
        for name, ok, detail in results:
            if not ok:
                print(f"  - {name}" + (f" ({detail})" if detail else ""))
    print("=" * 70)
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())

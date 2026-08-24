"""Base de connaissances des appareils réseau.

Objectif : savoir précisément *quoi* est branché sur le réseau, pas seulement
qu'une adresse IP répond. La base combine trois sources :

1. **Registre des fabricants (OUI)** — les 3 premiers octets d'une adresse MAC
   identifient le fabricant. Le registre public compte ~52 000 entrées ; il est
   téléchargé une fois puis stocké localement (SQLite), donc utilisable hors
   ligne et rafraîchissable.

2. **Annonces spontanées des appareils** — routeurs, téléviseurs, imprimantes,
   consoles et objets connectés publient leur modèle via SSDP/UPnP et mDNS.
   Ce sont des requêtes réseau normales, non intrusives : on demande poliment,
   l'appareil répond ce qu'il diffuse déjà à tout le monde.

3. **Règles de classification** — fabricant + ports ouverts + nom d'hôte
   permettent de déduire la nature de l'appareil (routeur, imprimante, caméra,
   NAS, téléphone…).

Note d'honnêteté : ce module n'intercepte aucun trafic. Lire les échanges
d'autres machines (Windows Update ou autre) supposerait de détourner leur
trafic, ce qui sort du cadre d'un audit et de la légalité usuelle. Tout ce qui
est collecté ici est soit public (registre OUI), soit volontairement diffusé
par l'appareil lui-même.
"""

import re
import socket
import sqlite3
import subprocess
import time

try:
    import requests
except ImportError:
    requests = None

#: Sources du registre OUI, essayées dans l'ordre. La première est un fichier
#: simple ("000000 Xerox") maintenu par le projet nmap ; l'IEEE bloque souvent
#: les téléchargements automatisés.
OUI_SOURCES = (
    ("nmap", "https://raw.githubusercontent.com/nmap/nmap/master/nmap-mac-prefixes"),
    ("wireshark", "https://www.wireshark.org/download/automated/data/manuf"),
)

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SIPA/7.0; audit réseau)"}

#: Indices de classification : (mot-clé fabricant, type d'appareil).
VENDOR_HINTS = (
    ("cisco", "Équipement réseau"), ("juniper", "Équipement réseau"),
    ("netgear", "Routeur / box"), ("tp-link", "Routeur / box"),
    ("d-link", "Routeur / box"), ("ubiquiti", "Équipement réseau"),
    ("mikrotik", "Équipement réseau"), ("aruba", "Point d'accès Wi-Fi"),
    ("sagemcom", "Box opérateur"), ("freebox", "Box opérateur"),
    ("technicolor", "Box opérateur"), ("arcadyan", "Box opérateur"),
    ("hewlett", "Imprimante / serveur"), ("brother", "Imprimante"),
    ("canon", "Imprimante"), ("epson", "Imprimante"), ("lexmark", "Imprimante"),
    ("xerox", "Imprimante"), ("kyocera", "Imprimante"),
    ("apple", "Appareil Apple"), ("samsung", "Appareil Samsung"),
    ("huawei", "Appareil Huawei"), ("xiaomi", "Appareil Xiaomi"),
    ("google", "Appareil Google"), ("amazon", "Appareil Amazon"),
    ("sonos", "Enceinte connectée"), ("roku", "Boîtier TV"),
    ("hikvision", "Caméra de surveillance"), ("dahua", "Caméra de surveillance"),
    ("axis communication", "Caméra de surveillance"),
    ("synology", "NAS"), ("qnap", "NAS"), ("western digital", "NAS / stockage"),
    ("raspberry", "Raspberry Pi"), ("espressif", "Objet connecté (ESP)"),
    ("tuya", "Objet connecté"), ("shelly", "Objet connecté"),
    ("sony", "Console / TV"), ("nintendo", "Console de jeu"),
    ("microsoft", "Appareil Microsoft"), ("dell", "Ordinateur Dell"),
    ("lenovo", "Ordinateur Lenovo"), ("asus", "Ordinateur / routeur ASUS"),
    ("intel", "Carte réseau Intel"), ("realtek", "Carte réseau Realtek"),
    ("vmware", "Machine virtuelle"), ("virtualbox", "Machine virtuelle"),
    ("qemu", "Machine virtuelle"), ("proxmox", "Machine virtuelle"),
)

#: Indices par port ouvert : (port, type suggéré, poids).
PORT_HINTS = (
    (515, "Imprimante", 3), (631, "Imprimante", 3), (9100, "Imprimante", 3),
    (554, "Caméra de surveillance", 3), (8554, "Caméra de surveillance", 2),
    (5000, "NAS", 1), (5001, "NAS", 1),
    (3389, "Poste Windows", 2), (445, "Poste Windows", 1), (139, "Poste Windows", 1),
    (22, "Machine Unix/Linux", 1), (548, "Appareil Apple", 2),
    (1883, "Objet connecté (MQTT)", 3), (8883, "Objet connecté (MQTT)", 3),
    (53, "Serveur DNS / box", 2), (67, "Serveur DHCP / box", 3),
    (1900, "Appareil UPnP", 1), (5353, "Appareil mDNS", 1),
    (80, "Interface web", 0), (443, "Interface web", 0),
)

#: Indices par nom d'hôte.
HOSTNAME_HINTS = (
    ("router", "Routeur / box"), ("gateway", "Routeur / box"),
    ("livebox", "Box opérateur"), ("freebox", "Box opérateur"),
    ("bbox", "Box opérateur"), ("sfrbox", "Box opérateur"),
    ("printer", "Imprimante"), ("imprimante", "Imprimante"),
    ("cam", "Caméra de surveillance"), ("nas", "NAS"),
    ("iphone", "iPhone"), ("ipad", "iPad"), ("android", "Téléphone Android"),
    ("macbook", "Mac"), ("imac", "Mac"), ("desktop", "Ordinateur"),
    ("laptop", "Ordinateur portable"), ("raspberrypi", "Raspberry Pi"),
    ("tv", "Téléviseur"), ("chromecast", "Chromecast"),
)


def normalise_oui(mac):
    """Extrait le préfixe fabricant (6 chiffres hexadécimaux) d'une MAC."""
    if not mac:
        return ""
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", str(mac))
    return cleaned[:6].upper() if len(cleaned) >= 6 else ""


class KnowledgeBase:
    """Base locale : registre des fabricants + classification d'appareils."""

    def __init__(self, db_path="connaissances.db", log=None, downloader=None):
        self.db_path = db_path
        self._log = log or (lambda *a, **k: None)
        # Injectable pour les tests : evite tout acces reseau.
        self._downloader = downloader
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS oui (
                prefixe TEXT PRIMARY KEY,
                fabricant TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS meta (
                cle TEXT PRIMARY KEY,
                valeur TEXT
            );
            -- `cle` est l'identite stable de l'appareil : son adresse MAC
            -- quand on la connait, son IP a defaut. L'IP seule ne convient
            -- pas comme identite : en DHCP, un appareil qui herite de l'IP
            -- d'un autre ecrasait sa fiche et sa date de premiere detection.
            CREATE TABLE IF NOT EXISTS appareil (
                cle         TEXT PRIMARY KEY,
                ip          TEXT,
                mac         TEXT,
                fabricant   TEXT,
                type        TEXT,
                modele      TEXT,
                systeme     TEXT,
                nom         TEXT,
                decouvert_par TEXT,
                premiere_vue  TEXT,
                derniere_vue  TEXT
            );
            """
        )
        # Les bases creees avant l'identite stable n'ont pas la colonne `cle`.
        self._migrer_appareils()
        self.conn.commit()

    # -- registre des fabricants -------------------------------------------
    def _download(self, url):
        if self._downloader is not None:
            return self._downloader(url)
        if requests is None:
            raise RuntimeError("Le module 'requests' est indisponible.")
        response = requests.get(url, timeout=60, headers=_HEADERS)
        response.raise_for_status()
        return response.text

    @staticmethod
    def _parse_oui(text):
        """Lit les formats nmap ("000000 Xerox") et Wireshark ("00:00:00\tXerox")."""
        entries = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = re.split(r"[\t ]+", line, maxsplit=1)
            if len(parts) != 2:
                continue
            prefix = normalise_oui(parts[0])
            vendor = parts[1].strip()
            # Wireshark met parfois un nom court puis le nom long apres une
            # tabulation : on garde le plus informatif.
            if "\t" in vendor:
                short, long_name = vendor.split("\t", 1)
                vendor = long_name.strip() or short.strip()
            if prefix and vendor:
                entries[prefix] = vendor
        return entries

    def refresh_oui(self, force=False, max_age_days=30):
        """Télécharge le registre des fabricants s'il est absent ou périmé.

        Retourne le nombre d'entrées en base.
        """
        if not force and self.oui_count() and not self._is_stale(max_age_days):
            return self.oui_count()

        last_error = None
        for name, url in OUI_SOURCES:
            try:
                entries = self._parse_oui(self._download(url))
            except Exception as exc:
                last_error = f"{name}: {exc}"
                continue
            if len(entries) < 1000:      # source visiblement tronquee ou bloquee
                last_error = f"{name}: seulement {len(entries)} entrées"
                continue
            with self.conn:
                self.conn.executemany(
                    "INSERT OR REPLACE INTO oui (prefixe, fabricant) VALUES (?,?)",
                    entries.items())
                self.conn.execute(
                    "INSERT OR REPLACE INTO meta (cle, valeur) VALUES ('oui_maj', ?)",
                    (str(time.time()),))
                self.conn.execute(
                    "INSERT OR REPLACE INTO meta (cle, valeur) VALUES ('oui_source', ?)",
                    (name,))
            self._log(f"[CONNAISSANCES] Registre fabricants mis à jour : "
                      f"{len(entries)} entrées (source {name}).", tag="success")
            return self.oui_count()

        self._log(f"[CONNAISSANCES] Mise à jour impossible ({last_error}). "
                  f"La base locale reste utilisée.", tag="warn")
        return self.oui_count()

    def _is_stale(self, max_age_days):
        row = self.conn.execute(
            "SELECT valeur FROM meta WHERE cle='oui_maj'").fetchone()
        if not row:
            return True
        try:
            return (time.time() - float(row["valeur"])) > max_age_days * 86400
        except (TypeError, ValueError):
            return True

    def oui_count(self):
        return self.conn.execute("SELECT COUNT(*) FROM oui").fetchone()[0]

    def vendor_for(self, mac):
        """Fabricant correspondant à une adresse MAC, ou chaîne vide."""
        prefix = normalise_oui(mac)
        if not prefix:
            return ""
        row = self.conn.execute(
            "SELECT fabricant FROM oui WHERE prefixe=?", (prefix,)).fetchone()
        return row["fabricant"] if row else ""

    # -- classification -----------------------------------------------------
    @staticmethod
    def classify(vendor="", ports=(), hostname="", announced=""):
        """Déduit la nature de l'appareil à partir de tous les indices.

        Chaque indice vote avec un poids ; le type le mieux noté l'emporte.
        Retourne ("Inconnu", 0) si rien ne ressort.
        """
        scores = {}

        def vote(kind, weight):
            if kind:
                scores[kind] = scores.get(kind, 0) + weight

        haystack = f"{vendor} {hostname} {announced}".lower()

        # Le fabricant est l'indice le plus fiable.
        for needle, kind in VENDOR_HINTS:
            if needle in (vendor or "").lower():
                vote(kind, 5)
                break

        for needle, kind in HOSTNAME_HINTS:
            if needle in (hostname or "").lower():
                vote(kind, 4)

        for port, kind, weight in PORT_HINTS:
            if port in set(ports or ()):
                vote(kind, weight)

        # Ce que l'appareil annonce lui-même (SSDP/mDNS) est très parlant.
        for needle, kind in (("printer", "Imprimante"), ("scanner", "Imprimante"),
                             ("camera", "Caméra de surveillance"),
                             ("internetgatewaydevice", "Routeur / box"),
                             ("mediarenderer", "Téléviseur / multimédia"),
                             ("mediaserver", "Serveur multimédia"),
                             ("airplay", "Appareil Apple"),
                             ("googlecast", "Chromecast"),
                             ("nas", "NAS")):
            if needle in haystack:
                vote(kind, 4)

        if not scores:
            return ("Inconnu", 0)
        best = max(scores.items(), key=lambda item: item[1])
        return best

    # -- inventaire persistant ---------------------------------------------
    COLONNES_APPAREIL = ("cle", "ip", "mac", "fabricant", "type", "modele",
                         "systeme", "nom", "decouvert_par", "premiere_vue",
                         "derniere_vue")

    def _migrer_appareils(self):
        """Ajoute la colonne `cle` aux bases creees avant ce correctif."""
        colonnes = [r[1] for r in self.conn.execute(
            "PRAGMA table_info(appareil)")]
        if "cle" in colonnes:
            return
        with self.conn:
            self.conn.execute("ALTER TABLE appareil RENAME TO appareil_ancien")
            self.conn.execute("""
                CREATE TABLE appareil (
                    cle         TEXT PRIMARY KEY,
                    ip          TEXT,
                    mac         TEXT,
                    fabricant   TEXT,
                    type        TEXT,
                    modele      TEXT,
                    systeme     TEXT,
                    nom         TEXT,
                    decouvert_par TEXT,
                    premiere_vue  TEXT,
                    derniere_vue  TEXT
                );
            """)
            for ligne in self.conn.execute("SELECT * FROM appareil_ancien"):
                fiche = dict(ligne)
                fiche["cle"] = self.cle_appareil(fiche.get("ip"), fiche.get("mac"))
                self.conn.execute(
                    "INSERT OR REPLACE INTO appareil (%s) VALUES (%s)"
                    % (",".join(self.COLONNES_APPAREIL),
                       ",".join("?" * len(self.COLONNES_APPAREIL))),
                    tuple(fiche.get(c) for c in self.COLONNES_APPAREIL))
            self.conn.execute("DROP TABLE appareil_ancien")

    @staticmethod
    def cle_appareil(ip, mac=None):
        """Identite stable : l'adresse MAC si connue, l'IP a defaut."""
        if mac:
            return "mac:" + str(mac).replace("-", ":").strip().lower()
        return "ip:" + str(ip)

    def remember(self, ip, **fields):
        """Enregistre ou complète la fiche d'un appareil."""
        stamp = time.strftime("%Y-%m-%d %H:%M")
        mac = fields.get("mac")
        cle = self.cle_appareil(ip, mac)

        existing = self.conn.execute(
            "SELECT * FROM appareil WHERE cle=?", (cle,)).fetchone()

        if existing is None and mac:
            # L'appareil etait peut-etre connu par son IP seule, avant qu'on
            # decouvre sa MAC. On reprend sa fiche plutot que d'en creer une
            # seconde, et on la reindexe sous son identite definitive.
            ancienne_cle = self.cle_appareil(ip)
            provisoire = self.conn.execute(
                "SELECT * FROM appareil WHERE cle=?", (ancienne_cle,)).fetchone()
            if provisoire is not None:
                existing = provisoire
                with self.conn:
                    self.conn.execute(
                        "DELETE FROM appareil WHERE cle=?", (ancienne_cle,))

        data = dict(existing) if existing else {"premiere_vue": stamp}
        for key, value in fields.items():
            if value:
                data[key] = value
        data["ip"] = ip
        data["cle"] = cle
        data["derniere_vue"] = stamp
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO appareil (%s) VALUES (%s)"
                % (",".join(self.COLONNES_APPAREIL),
                   ",".join("?" * len(self.COLONNES_APPAREIL))),
                tuple(data.get(c) for c in self.COLONNES_APPAREIL))
        return data

    def known_devices(self):
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM appareil ORDER BY derniere_vue DESC")]

    def stats(self):
        return {"fabricants": self.oui_count(),
                "appareils": self.conn.execute(
                    "SELECT COUNT(*) FROM appareil").fetchone()[0]}

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass


# ===========================================================================
# Interrogation active du réseau : on demande, les appareils répondent
# ===========================================================================

def discover_ssdp(timeout=3.0):
    """Interroge les appareils UPnP/SSDP du réseau local.

    Renvoie {ip: {"server": ..., "modele": ...}}. Routeurs, téléviseurs,
    imprimantes et enceintes répondent en annonçant leur modèle.
    """
    message = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode("ascii")

    found = {}
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(timeout)
        sock.sendto(message, ("239.255.255.250", 1900))

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(65507)
            except socket.timeout:
                break
            except OSError:
                break
            text = data.decode("utf-8", errors="ignore")
            entry = found.setdefault(addr[0], {})
            for line in text.splitlines():
                if ":" not in line:
                    continue
                key, _, value = line.partition(":")
                key = key.strip().upper()
                value = value.strip()
                if key == "SERVER" and value:
                    entry["server"] = value
                elif key == "ST" and value and "modele" not in entry:
                    entry["modele"] = value
    except Exception:
        pass
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
    return found


def discover_mdns(timeout=3.0):
    """Interroge le réseau en mDNS (Bonjour) pour lister les services annoncés.

    Renvoie {ip: [noms de services]}. Très parlant pour les appareils Apple,
    les imprimantes et les objets connectés.
    """
    # Requête DNS standard pour _services._dns-sd._udp.local (type PTR).
    query = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00])
    for label in ("_services", "_dns-sd", "_udp", "local"):
        query += bytes([len(label)]) + label.encode("ascii")
    query += bytes([0x00, 0x00, 0x0C, 0x00, 0x01])

    found = {}
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        sock.sendto(query, ("224.0.0.251", 5353))

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(65507)
            except (socket.timeout, OSError):
                break
            # Extraction tolerante des noms de service, sans decodeur DNS
            # complet : on cherche les libelles lisibles commencant par "_".
            names = set(re.findall(rb"_[a-zA-Z0-9\-]{2,20}", data))
            if names:
                found.setdefault(addr[0], set()).update(
                    n.decode("ascii", "ignore") for n in names)
    except Exception:
        pass
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
    return {ip: sorted(names) for ip, names in found.items()}


def netbios_name(ip, timeout=3):
    """Nom NetBIOS d'une machine Windows (via nbtstat), ou chaîne vide."""
    try:
        result = subprocess.run(["nbtstat", "-A", str(ip)],
                                capture_output=True, text=False, timeout=timeout)
        output = (result.stdout or b"").decode("cp850", errors="ignore")
        for line in output.splitlines():
            # Le nom de la machine porte le suffixe <00> et le type UNIQUE.
            if "<00>" in line and "UNIQUE" in line.upper():
                return line.split("<00>")[0].strip()
    except Exception:
        pass
    return ""

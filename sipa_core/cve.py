"""Base de vulnerabilites locale, alimentee depuis Internet (NVD).

Ce module constitue une petite base SQLite des CVE connues et met en
correspondance les services detectes par un scan (produit + version) avec
elles. Il ne tente JAMAIS d'exploiter une faille : il signale celles qui
s'appliquent, comme le font Nessus ou OpenVAS. La verification reelle
d'exploitabilite reste a la charge de l'operateur.

Source : National Vulnerability Database (services.nvd.nist.gov), API 2.0,
gratuite et sans cle. Une cle API (facultative) releve simplement la limite
de debit ; elle se configure dans config.json sous nvd.api_key.

Aucune dependance a l'interface : utilisable depuis le mode graphique comme
depuis la ligne de commande.
"""

import re
import sqlite3
import time

try:
    import requests
except ImportError:  # dependance listee, mais on reste importable sans elle
    requests = None

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"

#: Sans cle API, NVD tolere ~5 requetes par 30 s. On s'impose une pause large
#: pour ne jamais se faire limiter pendant un scan.
_DELAY_NO_KEY = 6.5
_DELAY_WITH_KEY = 0.8

#: Duree de validite d'une correlation en cache (jours). Au-dela, on reinterroge.
DEFAULT_MAX_AGE_DAYS = 7


def severity_from_score(score):
    """Niveau CVSS v3 standard a partir d'un score numerique.

    Barreme officiel du FIRST : 9.0-10 critique, 7.0-8.9 eleve,
    4.0-6.9 moyen, 0.1-3.9 faible, 0 informatif.
    """
    if score is None:
        return "INCONNU"
    if score >= 9.0:
        return "CRITIQUE"
    if score >= 7.0:
        return "ÉLEVÉ"
    if score >= 4.0:
        return "MOYEN"
    if score > 0.0:
        return "FAIBLE"
    return "INFO"


def _clean_version(version):
    """Reduit une version nmap bruyante a son coeur numerique.

    "8.2p1 Ubuntu 4ubuntu0.5" -> "8.2". Une version trop specifique fait
    rater la correspondance ; le couple produit + version courte est le
    meilleur compromis precision / rappel pour la recherche par mot-cle.
    """
    if not version:
        return ""
    match = re.search(r"\d+(?:\.\d+){0,2}", version)
    return match.group(0) if match else ""


class CVEDatabase:
    """Cache SQLite local de CVE, alimente a la demande depuis NVD."""

    def __init__(self, db_path="cve_cache.db", api_key=None, log=None,
                 session=None):
        self.db_path = db_path
        self.api_key = api_key or None
        self._log = log or (lambda *a, **k: None)
        self._session = session  # injectable pour les tests (evite le reseau)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    # -- schema -------------------------------------------------------------
    def _init_schema(self):
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS cve (
                cve_id      TEXT PRIMARY KEY,
                score       REAL,
                severity    TEXT,
                summary     TEXT,
                published   TEXT,
                url         TEXT
            );
            CREATE TABLE IF NOT EXISTS cve_match (
                product     TEXT NOT NULL,
                version     TEXT NOT NULL,
                cve_id      TEXT NOT NULL,
                PRIMARY KEY (product, version, cve_id)
            );
            CREATE TABLE IF NOT EXISTS cve_query (
                product     TEXT NOT NULL,
                version     TEXT NOT NULL,
                fetched_at  REAL NOT NULL,
                PRIMARY KEY (product, version)
            );
            """
        )
        self.conn.commit()

    # -- interrogation NVD --------------------------------------------------
    def _get(self, params):
        """Un appel NVD, avec cle API si disponible."""
        if self._session is not None:
            return self._session(params)
        if requests is None:
            raise RuntimeError("Le module 'requests' est indisponible.")
        headers = {"apiKey": self.api_key} if self.api_key else {}
        response = requests.get(NVD_ENDPOINT, params=params, headers=headers,
                                timeout=30)
        response.raise_for_status()
        return response.json()

    @staticmethod
    def _parse_cve(entry):
        """Extrait les champs utiles d'un enregistrement NVD 2.0."""
        cve = entry.get("cve", entry)
        cve_id = cve.get("id")
        descriptions = cve.get("descriptions", [])
        summary = next((d["value"] for d in descriptions if d.get("lang") == "en"),
                       descriptions[0]["value"] if descriptions else "")

        score = None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                score = metrics[key][0].get("cvssData", {}).get("baseScore")
                break

        return {
            "cve_id": cve_id,
            "score": score,
            "severity": severity_from_score(score),
            "summary": summary,
            "published": cve.get("published", ""),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else "",
        }

    def _fetch(self, product, version):
        """Interroge NVD pour un produit/version et renvoie une liste de CVE."""
        short = _clean_version(version)
        keyword = f"{product} {short}".strip() if short else product.strip()
        if not keyword:
            return []

        data = self._get({"keywordSearch": keyword, "resultsPerPage": 20})
        found = [self._parse_cve(item) for item in data.get("vulnerabilities", [])]

        # Version trop precise (0 resultat) : on retente sur le produit seul,
        # puis on filtre les CVE qui citent la version courte.
        if not found and short:
            data = self._get({"keywordSearch": product.strip(),
                              "resultsPerPage": 20})
            for item in data.get("vulnerabilities", []):
                parsed = self._parse_cve(item)
                if short in (parsed["summary"] or ""):
                    found.append(parsed)

        return [c for c in found if c["cve_id"]]

    # -- cache --------------------------------------------------------------
    def _store(self, product, version, cves):
        with self.conn:
            for cve in cves:
                self.conn.execute(
                    "INSERT OR REPLACE INTO cve "
                    "(cve_id, score, severity, summary, published, url) "
                    "VALUES (?,?,?,?,?,?)",
                    (cve["cve_id"], cve["score"], cve["severity"],
                     cve["summary"], cve["published"], cve["url"]))
                self.conn.execute(
                    "INSERT OR IGNORE INTO cve_match (product, version, cve_id) "
                    "VALUES (?,?,?)", (product, version, cve["cve_id"]))
            self.conn.execute(
                "INSERT OR REPLACE INTO cve_query (product, version, fetched_at) "
                "VALUES (?,?,?)", (product, version, time.time()))

    def _cached(self, product, version, max_age_days):
        row = self.conn.execute(
            "SELECT fetched_at FROM cve_query WHERE product=? AND version=?",
            (product, version)).fetchone()
        if not row:
            return None
        if max_age_days is not None and (
                time.time() - row["fetched_at"]) > max_age_days * 86400:
            return None
        rows = self.conn.execute(
            "SELECT c.* FROM cve c JOIN cve_match m ON c.cve_id = m.cve_id "
            "WHERE m.product=? AND m.version=? ORDER BY c.score DESC",
            (product, version)).fetchall()
        return [dict(r) for r in rows]

    # -- API publique -------------------------------------------------------
    def correlate(self, product, version, max_age_days=DEFAULT_MAX_AGE_DAYS,
                  now_timestamp=None):
        """CVE connues pour ce produit/version, du plus grave au moins grave.

        Renvoie une liste de dict {cve_id, score, severity, summary, url,...}.
        Utilise le cache local si frais ; sinon interroge NVD et met en cache,
        de sorte qu'un second scan (ou un usage hors ligne) reponde
        instantanement.
        """
        product = (product or "").strip()
        version = (version or "").strip()
        if not product:
            return []

        cached = self._cached(product, version, max_age_days)
        if cached is not None:
            return cached

        try:
            cves = self._fetch(product, version)
        except Exception as exc:
            self._log(f"[CVE] Interrogation NVD impossible pour "
                      f"{product} {version} : {exc}", tag="warn")
            # On se rabat sur d'anciennes donnees en cache si elles existent.
            stale = self._cached(product, version, max_age_days=None)
            return stale or []

        self._store(product, version, cves)
        delay = _DELAY_WITH_KEY if self.api_key else _DELAY_NO_KEY
        time.sleep(delay)
        return sorted(cves, key=lambda c: c["score"] or 0, reverse=True)

    def stats(self):
        """Nombre de CVE et de produits en base."""
        cve_count = self.conn.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
        product_count = self.conn.execute(
            "SELECT COUNT(DISTINCT product) FROM cve_query").fetchone()[0]
        return {"cve": cve_count, "produits": product_count}

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass

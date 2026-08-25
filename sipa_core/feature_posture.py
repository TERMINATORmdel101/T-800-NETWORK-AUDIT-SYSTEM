"""Audit de posture de securite du poste local (mixin).

Le volet defensif : plutot que d'executer des techniques d'attaque, SIPA
verifie sur SA propre machine des faiblesses de configuration concretes et
factuelles. Chaque controle lit une source reelle (registre Windows, systeme
de fichiers) et rend un statut sans ambiguite :

    FAIBLE   — la faiblesse est presente, prouvee par la valeur lue.
    OK       — controle, rien a signaler (avec la valeur qui le prouve).
    INCONNU  — pas pu verifier, et on dit pourquoi (droits, cle absente,
               systeme non Windows).

Regle du projet : jamais de verdict global « machine saine ». On ne conclut
que sur ce qu'on a reellement pu lire ; le reste est explicitement INCONNU.

C'est aussi l'inverse honnete du volet offensif refuse : on ne dumpe pas
LSASS, on SIGNALE qu'un dump de LSASS traine sur le disque ; on ne desactive
pas la protection des identifiants, on VERIFIE qu'elle est active.

Piege mixin (cf. CLAUDE.md) : ce module resout ses noms globaux chez lui.
Tous les imports systeme sont donc locaux au module.
"""

import os
import platform
import threading

try:
    import winreg
except ImportError:  # hors Windows : les controles registre renvoient INCONNU
    winreg = None


#: Statuts possibles d'un controle de posture.
FAIBLE = "FAIBLE"
OK = "OK"
INCONNU = "INCONNU"


def _lire_registre(ruche, chemin, valeur):
    """Lit une valeur de registre. Renvoie (present, valeur) sans jamais lever.

    present=False signifie « cle ou valeur absente », a distinguer d'une
    lecture impossible (droits) qui leve et retombe aussi sur (False, None) :
    dans les deux cas l'appelant reste prudent et ne conclut pas a tort.
    """
    if winreg is None:
        return (False, None)
    try:
        with winreg.OpenKey(ruche, chemin) as cle:
            donnee, _type = winreg.QueryValueEx(cle, valeur)
            return (True, donnee)
    except FileNotFoundError:
        return (False, None)
    except OSError:
        return (False, None)


class PostureMixin:
    """Controles factuels de durcissement du poste local."""

    def audit_posture(self):
        """Lance tous les controles de posture et renvoie leurs resultats.

        Chaque resultat : {nom, statut, detail, reco}. Aucun effet de bord sur
        l'interface : testable et reutilisable (mode console compris).
        """
        if platform.system() != "Windows":
            return [{
                "nom": "Audit de posture",
                "statut": INCONNU,
                "detail": "Ces controles lisent le registre Windows ; "
                          f"systeme detecte : {platform.system() or 'inconnu'}.",
                "reco": "Lancer SIPA sur le poste Windows a auditer.",
            }]
        return [
            self._posture_smb1(),
            self._posture_wdigest(),
            self._posture_rdp(),
            self._posture_dump_lsass(),
        ]

    # -- controles individuels ------------------------------------------------

    def _posture_smb1(self):
        """SMBv1 : protocole obsolete, vecteur de WannaCry/EternalBlue."""
        present, valeur = _lire_registre(
            winreg.HKEY_LOCAL_MACHINE if winreg else None,
            r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "SMB1")
        if not present:
            return {"nom": "SMBv1 (serveur)", "statut": INCONNU,
                    "detail": "Valeur SMB1 absente du registre : sur Windows "
                              "recent le composant est souvent desinstalle, "
                              "mais on ne peut pas l'affirmer d'ici.",
                    "reco": "Verifier via « Fonctionnalites Windows » que "
                            "« Prise en charge du partage SMB 1.0 » est decoche."}
        if valeur == 0:
            return {"nom": "SMBv1 (serveur)", "statut": OK,
                    "detail": "SMB1=0 : le serveur SMBv1 est desactive.",
                    "reco": ""}
        return {"nom": "SMBv1 (serveur)", "statut": FAIBLE,
                "detail": f"SMB1={valeur} : le serveur SMBv1 est actif. C'est le "
                          "protocole exploite par EternalBlue (WannaCry, NotPetya).",
                "reco": "Desactiver SMBv1 : Set-SmbServerConfiguration "
                        "-EnableSMB1Protocol $false"}

    def _posture_wdigest(self):
        """WDigest : s'il cache les identifiants en clair, LSASS les livre."""
        present, valeur = _lire_registre(
            winreg.HKEY_LOCAL_MACHINE if winreg else None,
            r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
            "UseLogonCredential")
        if not present:
            return {"nom": "Cache d'identifiants WDigest", "statut": OK,
                    "detail": "UseLogonCredential absent : Windows 8.1 / 2012 R2 "
                              "et plus recents appliquent 0 (pas de mot de passe "
                              "en clair en memoire) par defaut.",
                    "reco": ""}
        if valeur == 1:
            return {"nom": "Cache d'identifiants WDigest", "statut": FAIBLE,
                    "detail": "UseLogonCredential=1 : les mots de passe sont "
                              "gardes en clair dans LSASS, ou n'importe quel "
                              "dump les rendrait lisibles.",
                    "reco": "Passer la valeur a 0 (REG_DWORD) puis se "
                            "reconnecter."}
        return {"nom": "Cache d'identifiants WDigest", "statut": OK,
                "detail": f"UseLogonCredential={valeur} : pas de mot de passe en "
                          "clair conserve en memoire.",
                "reco": ""}

    def _posture_rdp(self):
        """RDP : s'il est ouvert, l'authentification NLA doit etre exigee."""
        present, deny = _lire_registre(
            winreg.HKEY_LOCAL_MACHINE if winreg else None,
            r"SYSTEM\CurrentControlSet\Control\Terminal Server",
            "fDenyTSConnections")
        if not present or deny == 1:
            return {"nom": "Bureau a distance (RDP)", "statut": OK,
                    "detail": "RDP desactive (fDenyTSConnections=1 ou par defaut).",
                    "reco": ""}
        # RDP est actif : NLA est-il exige ?
        nla_present, nla = _lire_registre(
            winreg.HKEY_LOCAL_MACHINE if winreg else None,
            r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
            "UserAuthentication")
        if nla_present and nla == 1:
            return {"nom": "Bureau a distance (RDP)", "statut": OK,
                    "detail": "RDP actif, mais l'authentification NLA est exigee "
                              "avant l'ouverture de session.",
                    "reco": "Verifier que le port 3389 n'est pas expose hors du "
                            "reseau local."}
        return {"nom": "Bureau a distance (RDP)", "statut": FAIBLE,
                "detail": "RDP actif SANS authentification NLA : la session "
                          "s'ouvre avant identification, ce qui expose au "
                          "detournement et au force brute.",
                "reco": "Activer « N'autoriser que les connexions avec "
                        "authentification au niveau du reseau »."}

    def _posture_dump_lsass(self):
        """Cherche un dump memoire de LSASS oublie : artefact de vol d'identifiants."""
        candidats = []
        dossiers = [os.environ.get("TEMP", ""),
                    os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Temp"),
                    os.path.join(os.path.expanduser("~"), "Downloads")]
        vus = set()
        for dossier in dossiers:
            if not dossier or dossier in vus or not os.path.isdir(dossier):
                continue
            vus.add(dossier)
            try:
                for nom in os.listdir(dossier):
                    bas = nom.lower()
                    if bas.endswith(".dmp") and ("lsass" in bas or "lsa" == bas[:3]):
                        candidats.append(os.path.join(dossier, nom))
            except OSError:
                continue
        if candidats:
            liste = ", ".join(candidats[:5])
            return {"nom": "Dump memoire de LSASS", "statut": FAIBLE,
                    "detail": f"Fichier(s) de dump de LSASS trouve(s) : {liste}. "
                              "Un tel fichier contient de quoi extraire des "
                              "identifiants hors ligne.",
                    "reco": "Supprimer ces fichiers et rechercher comment ils "
                            "ont ete crees (comsvcs.dll, procdump, Task Manager)."}
        return {"nom": "Dump memoire de LSASS", "statut": OK,
                "detail": "Aucun dump de LSASS dans les emplacements courants "
                          "(TEMP, Windows\\Temp, Downloads). Recherche limitee a "
                          "ces dossiers : une absence ici n'est pas une preuve "
                          "d'absence totale sur le disque.",
                "reco": ""}

    # -- restitution ----------------------------------------------------------

    def lancer_audit_posture(self):
        """Point d'entree du bouton : lance l'audit sans figer l'interface."""
        try:
            self.start_loading()
        except Exception:
            pass

        def _run():
            try:
                self.afficher_posture()
            except Exception as exc:
                self.log(f"[POSTURE] Audit interrompu : {exc}", tag="error")
            finally:
                try:
                    self.root.after(0, self.stop_loading)
                except Exception:
                    pass

        threading.Thread(target=_run, daemon=True).start()

    def afficher_posture(self):
        """Journalise l'audit de posture et alimente les constats.

        Les faiblesses averees (FAIBLE) rejoignent problems_found pour figurer
        dans le bilan et les rapports ; INCONNU et OK restent informatifs.
        """
        resultats = self.audit_posture()

        self.log("", tag="info")
        self.log("AUDIT DE POSTURE — DURCISSEMENT DU POSTE LOCAL", tag="title")

        tags = {FAIBLE: "warn", OK: "ok", INCONNU: "info"}
        faibles = inconnus = 0
        for r in resultats:
            self.log(f"   [{r['statut']}] {r['nom']}", tag=tags.get(r["statut"], "info"))
            self.log(f"      {r['detail']}", tag="info")
            if r["statut"] == FAIBLE:
                faibles += 1
                if r["reco"]:
                    self.log(f"      -> {r['reco']}", tag="accent")
                self.problems_found.append({
                    "type": "POSTURE", "host": "LOCAL", "port": "",
                    "service": r["nom"],
                    "details": r["detail"],
                    "action": r["reco"] or "Corriger la configuration signalee.",
                    "risk": "ÉLEVÉ",
                })
            elif r["statut"] == INCONNU:
                inconnus += 1

        self.log("", tag="info")
        self.log(f"   {faibles} faiblesse(s) averee(s), "
                 f"{inconnus} controle(s) non concluant(s).", tag="info")
        if inconnus:
            self.log("   « Non concluant » ne veut pas dire « sain » : voir le "
                     "detail de chaque ligne INCONNU.", tag="warn")
        return resultats

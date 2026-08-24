"""Ce qu'on attend — ou non — d'un appareil, selon sa nature.

Le contrôle du bon sens : SIPA sait déjà reconnaître qu'une machine est une
imprimante (registre OUI des fabricants, annonces mDNS, ports ouverts). Il sait
aussi quels ports elle expose. Ce module relie les deux moitiés, pour dire
« cette imprimante accepte des connexions d'administration à distance, ce qui
n'est pas attendu pour une imprimante » plutôt que « port 22 ouvert ».

**Trois règles de conception, et elles ne sont pas négociables.**

1. *Le silence par défaut.* On ne signale PAS « tout ce qui n'est pas attendu ».
   Un NAS a légitimement quinze ports ouverts selon ce que son propriétaire y a
   installé. Chaque profil porte donc une liste blanche courte ET une liste
   noire courte : entre les deux, aucun constat.

2. *« Inattendu » ne veut pas dire « dangereux ».* Le constat dit « je ne
   m'attendais pas à ça, confirmez que c'est voulu ». Il ne fait pas monter la
   gravité tout seul : un NAS avec SSH ouvert est parfaitement normal chez un
   technicien.

3. *Cette table encode des opinions.* Elle sera fausse sur certains réseaux.
   Elle est donc un fichier de données lisible et modifiable, chaque port
   portant sa justification en français, et le rapport cite toujours la règle
   qui a déclenché le constat. Une heuristique cachée qui rend un verdict n'est
   qu'un score opaque déguisé.
"""

#: Types d'appareils pour lesquels on assume de n'avoir aucun profil.
#: Y figurer est un choix explicite : le test échoue si un type reconnu par
#: `KnowledgeBase.classify` n'est ni ici, ni dans PROFILS.
SANS_PROFIL = {
    # Un ordinateur, un téléphone ou un serveur expose ce que son propriétaire
    # y a installé : aucune attente stable ne peut en être tirée. Émettre un
    # constat ici produirait du bruit, pas de l'information.
    "Inconnu",
    "Ordinateur", "Ordinateur portable", "Ordinateur Dell", "Ordinateur Lenovo",
    "Poste Windows", "Mac", "Machine Unix/Linux", "Machine virtuelle",
    "Serveur", "Serveur multimédia", "Raspberry Pi",
    "Téléphone Android", "iPhone", "iPad",
    "Appareil Apple", "Appareil Google", "Appareil Amazon", "Appareil Samsung",
    "Appareil Microsoft", "Appareil Huawei", "Appareil Xiaomi",
    # Types trop vagues : ils décrivent comment l'appareil a été découvert,
    # pas ce qu'il est.
    "Appareil UPnP", "Appareil mDNS", "Interface web", "Équipement réseau",
    "Carte réseau Intel", "Carte réseau Realtek",
}

#: Pour chaque type : ce qu'on attend, ce qui surprend, et pourquoi.
#: `attendus` sert à expliquer ce qui est normal ; `inattendus` seul déclenche
#: un constat. Tout port absent des deux listes reste silencieux.
PROFILS = {
    "Imprimante": {
        "resume": "Une imprimante réseau imprime et se laisse configurer depuis "
                  "un navigateur. Elle n'a aucune raison d'offrir un accès "
                  "d'administration à distance ni du partage de fichiers.",
        "attendus": {
            9100: "port d'impression brute (JetDirect)",
            631:  "protocole d'impression Internet (IPP)",
            515:  "ancien protocole d'impression (LPD)",
            80:   "interface de configuration web",
            443:  "interface de configuration web chiffrée",
            161:  "supervision SNMP (niveaux d'encre, compteurs)",
        },
        "inattendus": {
            22:   "accès d'administration à distance (SSH)",
            23:   "accès d'administration en clair (Telnet)",
            21:   "transfert de fichiers (FTP), souvent sans mot de passe",
            445:  "partage de fichiers Windows (SMB)",
            3389: "prise de contrôle du bureau à distance (RDP)",
        },
    },
    "Caméra de surveillance": {
        "resume": "Une caméra diffuse un flux vidéo et s'administre depuis un "
                  "navigateur. Un accès shell ou un partage de fichiers sur une "
                  "caméra est le signe classique d'un modèle bas de gamme mal "
                  "verrouillé.",
        "attendus": {
            80:   "interface de visualisation web",
            443:  "interface de visualisation web chiffrée",
            554:  "flux vidéo temps réel (RTSP)",
            8000: "interface constructeur",
            8080: "interface constructeur",
        },
        "inattendus": {
            22:   "accès shell à distance (SSH)",
            23:   "accès shell en clair (Telnet), très courant sur les caméras d'entrée de gamme",
            21:   "transfert de fichiers (FTP)",
            445:  "partage de fichiers Windows (SMB)",
            3389: "prise de contrôle du bureau à distance (RDP)",
        },
    },
    "Routeur / box": {
        "resume": "Une box s'administre depuis le réseau local. Ce qui compte "
                  "surtout, c'est qu'elle n'expose pas son administration en "
                  "clair, ni des services qui n'ont rien à y faire.",
        "attendus": {
            80:   "interface d'administration web",
            443:  "interface d'administration web chiffrée",
            53:   "service DNS pour le réseau local",
            67:   "attribution d'adresses (DHCP)",
        },
        "inattendus": {
            23:   "administration en clair (Telnet) : identifiants lisibles sur le réseau",
            21:   "transfert de fichiers (FTP)",
            3389: "prise de contrôle du bureau à distance (RDP)",
            445:  "partage de fichiers Windows (SMB)",
            1900: "UPnP exposé, souvent utilisé pour ouvrir des ports sans contrôle",
        },
    },
    "NAS": {
        "resume": "Un stockage réseau partage des fichiers, et son propriétaire "
                  "y installe souvent d'autres services. On ne s'étonne donc "
                  "que du strictement anormal.",
        "attendus": {
            445:  "partage de fichiers Windows (SMB)",
            139:  "partage de fichiers Windows (NetBIOS)",
            2049: "partage de fichiers Unix (NFS)",
            80:   "interface d'administration web",
            443:  "interface d'administration web chiffrée",
            5000: "interface constructeur",
            5001: "interface constructeur chiffrée",
            548:  "partage de fichiers Apple (AFP)",
        },
        "inattendus": {
            23:   "administration en clair (Telnet)",
            21:   "transfert de fichiers en clair (FTP)",
            3389: "prise de contrôle du bureau à distance (RDP)",
        },
    },
    "Téléviseur / multimédia": {
        "resume": "Un téléviseur connecté reçoit des flux et se laisse piloter "
                  "depuis un téléphone. Il n'a aucune raison d'offrir un accès "
                  "d'administration.",
        "attendus": {
            8008: "pilotage à distance (Cast)",
            8009: "pilotage à distance chiffré (Cast)",
            1900: "découverte UPnP, normale pour un lecteur multimédia",
            7000: "réception AirPlay",
            8080: "interface constructeur",
        },
        "inattendus": {
            22:   "accès shell à distance (SSH)",
            23:   "accès shell en clair (Telnet)",
            445:  "partage de fichiers Windows (SMB)",
            3389: "prise de contrôle du bureau à distance (RDP)",
        },
    },
    "Chromecast": {
        "resume": "Un Chromecast reçoit un flux depuis un appareil du réseau "
                  "local. Sa surface d'exposition est minuscule.",
        "attendus": {
            8008: "pilotage à distance (Cast)",
            8009: "pilotage à distance chiffré (Cast)",
            1900: "découverte UPnP",
        },
        "inattendus": {
            22:   "accès shell à distance (SSH)",
            23:   "accès shell en clair (Telnet)",
            445:  "partage de fichiers Windows (SMB)",
        },
    },
    "Imprimante multifonction": {
        "resume": "Comme une imprimante, avec la numérisation en plus.",
        "attendus": {
            9100: "port d'impression brute (JetDirect)",
            631:  "protocole d'impression Internet (IPP)",
            515:  "ancien protocole d'impression (LPD)",
            80:   "interface de configuration web",
            443:  "interface de configuration web chiffrée",
            161:  "supervision SNMP",
        },
        "inattendus": {
            22:   "accès d'administration à distance (SSH)",
            23:   "accès d'administration en clair (Telnet)",
            21:   "transfert de fichiers (FTP)",
            445:  "partage de fichiers Windows (SMB)",
            3389: "prise de contrôle du bureau à distance (RDP)",
        },
    },
    "Point d'accès Wi-Fi": {
        "resume": "Un point d'accès relaie le Wi-Fi et s'administre depuis le "
                  "réseau local. Son administration ne doit jamais passer en clair.",
        "attendus": {
            80:   "interface d'administration web",
            443:  "interface d'administration web chiffrée",
            22:   "administration en ligne de commande (fréquent sur le matériel professionnel)",
        },
        "inattendus": {
            23:   "administration en clair (Telnet) : identifiants lisibles sur le réseau",
            21:   "transfert de fichiers en clair (FTP)",
            445:  "partage de fichiers Windows (SMB)",
            3389: "prise de contrôle du bureau à distance (RDP)",
        },
    },
    "Enceinte connectée": {
        "resume": "Une enceinte reçoit de l'audio et se pilote depuis un "
                  "téléphone. Elle n'a rien à administrer à distance.",
        "attendus": {
            1900: "découverte UPnP",
            8008: "pilotage à distance (Cast)",
            8009: "pilotage à distance chiffré (Cast)",
            7000: "réception AirPlay",
            80:   "interface constructeur",
        },
        "inattendus": {
            22:   "accès shell à distance (SSH)",
            23:   "accès shell en clair (Telnet)",
            445:  "partage de fichiers Windows (SMB)",
            3389: "prise de contrôle du bureau à distance (RDP)",
        },
    },
    "Objet connecté": {
        "resume": "Un objet connecté fait une chose et une seule. Toute "
                  "interface d'administration à distance sur ce type de "
                  "matériel mérite une vérification : c'est la porte d'entrée "
                  "la plus courante des réseaux domestiques.",
        "attendus": {
            80:   "interface de configuration web",
            443:  "interface de configuration web chiffrée",
            1883: "messagerie MQTT (domotique)",
            8883: "messagerie MQTT chiffrée",
            5683: "protocole CoAP (objets contraints)",
        },
        "inattendus": {
            22:   "accès shell à distance (SSH)",
            23:   "accès shell en clair (Telnet) : très courant et très exposé",
            21:   "transfert de fichiers (FTP)",
            445:  "partage de fichiers Windows (SMB)",
            3389: "prise de contrôle du bureau à distance (RDP)",
        },
    },
    "Console de jeu": {
        "resume": "Une console joue en ligne. Elle n'expose normalement aucun "
                  "service d'administration.",
        "attendus": {
            80:   "services en ligne",
            443:  "services en ligne chiffrés",
            1900: "découverte UPnP (partage multimédia)",
            9295: "lecture à distance (PlayStation)",
            9296: "lecture à distance (PlayStation)",
        },
        "inattendus": {
            22:   "accès shell à distance (SSH)",
            23:   "accès shell en clair (Telnet)",
            445:  "partage de fichiers Windows (SMB)",
            3389: "prise de contrôle du bureau à distance (RDP)",
        },
    },
}


#: Synonymes : plusieurs indices produisent le meme type sous des noms voisins.
ALIAS = {
    "Box opérateur": "Routeur / box",
    "Serveur DNS / box": "Routeur / box",
    "Serveur DHCP / box": "Routeur / box",
    "Ordinateur / routeur ASUS": "Routeur / box",
    "Imprimante / serveur": "Imprimante",
    "NAS / stockage": "NAS",
    "Téléviseur": "Téléviseur / multimédia",
    "Boîtier TV": "Téléviseur / multimédia",
    "Console / TV": "Téléviseur / multimédia",
    "Objet connecté (ESP)": "Objet connecté",
    "Objet connecté (MQTT)": "Objet connecté",
}


def resoudre(type_appareil):
    """Ramène un synonyme au type canonique qui porte le profil."""
    return ALIAS.get(type_appareil, type_appareil)


def profil(type_appareil):
    """Profil d'un type d'appareil, ou None si aucun n'est défini."""
    return PROFILS.get(resoudre(type_appareil))


def controler(type_appareil, ports_ouverts):
    """Confronte les ports ouverts à ce qu'on attend de ce type d'appareil.

    Renvoie la liste des ports inattendus, chacun avec la raison écrite dans
    la table. Une liste vide signifie soit que tout est cohérent, soit qu'on
    n'a pas d'avis sur ce type — les deux se distinguent par `profil()`.
    """
    canonique = resoudre(type_appareil)
    regles = PROFILS.get(canonique)
    if not regles:
        return []

    surprises = []
    for port in sorted(set(ports_ouverts or ())):
        raison = regles["inattendus"].get(port)
        if raison:
            surprises.append({
                "port": port,
                "raison": raison,
                "type_appareil": type_appareil,
                "regle": f"{canonique} : port {port} listé comme inattendu",
            })
    return surprises


def expliquer_attendus(type_appareil, ports_ouverts):
    """Ports ouverts qui sont normaux pour ce type, avec leur justification.

    Sert à montrer à l'utilisateur ce que SIPA a jugé cohérent, et pas
    seulement ce qui l'a surpris : un contrôle qui ne dit rien de ce qu'il a
    validé se lit comme un contrôle qui n'a rien regardé.
    """
    regles = PROFILS.get(resoudre(type_appareil))
    if not regles:
        return []
    return [{"port": port, "raison": regles["attendus"][port]}
            for port in sorted(set(ports_ouverts or ()))
            if port in regles["attendus"]]

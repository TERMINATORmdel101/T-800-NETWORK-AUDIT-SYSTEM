# SIPA — contexte pour Claude

Outil d'audit réseau et sécurité (Python/Tkinter, Windows). Projet personnel.
Les commentaires, l'interface et les échanges se font **en français**.

## Lancer et vérifier

```bash
python sipa.py                                  # interface graphique
python sipa.py --cible 127.0.0.1 --scan rapide  # mode console
python tests/run_all.py                         # toutes les vérifications (hors ligne)
python tests/run_all.py --live                  # + appels réseau réels
```

**Lance toujours `tests/run_all.py` après une modification.** C'est le filet
principal ; il a attrapé plusieurs régressions.

## Structure

- `sipa.py` — point d'entrée + classe `AuditIA_Ultimate` (~7 700 lignes)
- `sipa_core/` — modules extraits, assemblés dans la classe par **mixins**
  (héritage multiple) : `theme`, `widgets`, `locales`, `services`, `secrets`,
  `cve`, `knowledge`, `cli`, `gui_*`, `feature_*`
- `tests/` — `test_structure.py` (intégrité), `test_fixes.py` (non-régression),
  `test_live.py` (réseau réel)

Le paquet s'appelle `sipa_core` et non `sipa/` pour ne pas entrer en collision
avec `sipa.py`.

## Nature du projet

SIPA est un projet personnel, fait par plaisir, pour combler une niche : un
outil d'audit réseau en français sur Windows. Il est développé **avec
l'assistance d'une IA** — l'auteur conçoit les fonctionnalités et décide de ce
qui entre dans le logiciel ; l'IA apporte les compétences de développement.
Ce n'est une prise de position ni pour ni contre l'IA : c'est le moyen qui
permet de passer de l'idée au logiciel.

C'est aussi la raison pour laquelle la règle d'honnêteté ci-dessous n'est pas
négociable : un code écrit vite doit être vérifiable lentement.

## Le principe directeur : l'honnêteté

Ce projet a été assaini d'une longue série de fonctionnalités qui
**prétendaient agir sans rien faire**. Exemples réels corrigés : les modes démo
injectaient de fausses menaces dans les rapports PDF ; `_generic_api_sync`
collectait une vraie clé API Tenable pour pinger `google.com` et annoncer
« connexion établie » ; `requests` valait `None` donc 8 fonctions réseau
échouaient en silence ; `ConfigManager.set()` ne sauvegardait jamais ; la
« chaîne SSL » affichait un certificat valide sans ouvrir de socket ; le scan
broadcast inventait des hôtes `192.168.1.x`.

**Règle : ne jamais simuler un résultat.** Si une fonctionnalité n'est pas
implémentée, elle doit le dire via `self._not_implemented(nom, raison)`. Un test
échoue si un fichier de documentation inexistant est cité.

Non implémentés et assumés : Tenable, Qualys, Defender, Rapid7, mode agent,
proxy, sandbox, heatmap, timeline. Nécessitent une clé API : SHODAN, VirusTotal.

## Pièges connus

- **Tkinter n'est pas thread-safe.** Depuis un thread, passer par `self.log()`
  (file `msg_queue`) ou `self.root.after`. Jamais `root.after` avant que la
  boucle principale ait démarré — ça lève `main thread is not in main loop`.
- **Un mixin ne voit pas les globales de `sipa.py`.** Une méthode définie dans
  `sipa_core/feature_*.py` résout ses noms globaux dans SON module. Trois
  `NameError` sont nés de là (`requests`, `scapy`, `SCAPY_AVAILABLE`,
  `random`), tous avalés par des `except` larges. `python -m pyflakes` les
  détecte : le lancer après toute extraction de code vers un mixin.
- **Sortie console Windows en cp850**, pas UTF-8. `sipa.py` force `stdout` et
  `stderr` en UTF-8 dès l'import (lignes 34-38) ; un script qui importe
  `sipa_core` sans passer par `sipa.py` n'a pas cette protection.
- **Mode headless** : `getattr(self, "headless", False)` doit court-circuiter
  toute boîte de dialogue et toute ouverture de navigateur, sinon le mode
  console et les tests se bloquent.
- **Le bootstrap ne doit jamais bloquer.** `AutoInstaller.run_check_sequence()`
  appelait `input()` puis `sys.exit(1)` sans droits admin : `SystemExit` hérite
  de `BaseException` et n'était donc pas rattrapé. Ne jamais réintroduire
  `input()` ni `sys.exit()` dans le chemin de démarrage.
- **Drapeaux `*_AVAILABLE`** : `PLOTLY_AVAILABLE` ne devient vrai qu'après
  appel de `_load_plotly()`. Toujours charger avant de tester.
- **Les couleurs de bouton désignent le texte, pas le fond.** Un test vérifie
  le contraste WCAG de chaque bouton sur les **deux** palettes.
- La cible se lit via `self.get_target()`, jamais `entry_ip.get()` (texte
  d'aide à écarter). Un test l'impose — d'où le drapeau
  `self._placeholder_visible` plutôt qu'une lecture directe du champ.
- **Nom d'import ≠ nom PyPI** : `python-nmap` → `nmap`, `Pillow` → `PIL`,
  `scikit-learn` → `sklearn`. Une vérification par `find_spec` sur le nom PyPI
  échoue toujours.

## Thème et langue

`sipa_core/theme.py` définit deux palettes (`sombre`, `clair`) dans `PALETTES`.
`THEME` est un dictionnaire **vivant** : `apply_palette()` le met à jour **en
place**, jamais par réassignation, pour que les `from ... import THEME`
existants voient le changement. Un test le vérifie.

Tkinter fige les couleurs à la création du widget : changer de palette ou de
langue passe donc par `rebuild_interface()`, qui détruit et reconstruit les
panneaux en préservant le journal.

Les libellés sont traduits **au rendu** par `self.tr()`, appelée depuis
`make_button()` et les quelques sites d'onglets/catégories. Les libellés
français restent les clés canoniques dans `build_controls` — ne pas les
remplacer par des appels de fonction, un test inspecte l'AST pour vérifier le
contraste de chaque bouton. Les traductions vivent dans `UI_LABELS`
(`sipa_core/locales.py`) ; un test échoue si un bouton n'y figure pas.

## Conventions

- Commentaires et interface en français ; messages de commit en anglais.
- Version unique dans `sipa_core/__init__.py` (`APP_NAME`, `APP_VERSION`).
- Fichiers générés (rapports, `config.json`, bases, aide exportée) : dans
  `.gitignore`. Ne jamais versionner une sortie de scan — elle contient les
  ports ouverts et les vulnérabilités d'une machine réelle.
- Les patchs complexes passent par un script Python écrit dans le scratchpad,
  car les heredocs bash mangent les échappements `\n` et les apostrophes.
  Pour cibler une méthode, préférer l'AST aux ancres textuelles : plusieurs
  lignes du projet portent des espaces en fin de ligne.

## Reste à faire

- Validation terrain : les scans nmap n'ont tourné que sur localhost et sur un
  réseau local restreint, jamais sur un parc étendu.
- La classe `AuditIA_Ultimate` reste grosse ; d'autres extractions en mixins
  sont possibles (attention au piège des globales ci-dessus).
- Les messages du journal ne sont pas traduits, seulement les libellés.
- Aucune intégration continue : la règle « toujours lancer `run_all.py` »
  n'est appliquée par rien d'automatique.

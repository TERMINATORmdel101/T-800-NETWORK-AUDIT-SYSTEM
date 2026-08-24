"""Lance les trois suites de tests de SIPA.

    python tests/run_all.py            # tests hors ligne uniquement
    python tests/run_all.py --live     # ajoute les tests reseau reels

  * test_structure.py : integrite de la refonte modulaire
  * test_fixes.py     : non-regression des correctifs
  * test_live.py      : appels reseau reels (option --live)
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

SUITES = ["test_structure.py", "test_fixes.py"]
if "--live" in sys.argv:
    SUITES.append("test_live.py")

failures = []
for suite in SUITES:
    print(f"\n{'#' * 70}\n# {suite}\n{'#' * 70}")
    code = subprocess.call([sys.executable, os.path.join(HERE, suite)], cwd=ROOT)
    if code != 0:
        failures.append(suite)

print(f"\n{'=' * 70}")
if failures:
    print(f"ECHEC : {', '.join(failures)}")
else:
    print(f"OK : {len(SUITES)} suite(s) reussie(s)")
print("=" * 70)
sys.exit(1 if failures else 0)

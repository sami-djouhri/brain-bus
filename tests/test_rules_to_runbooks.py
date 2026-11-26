"""rules_to_runbooks: ein zweiter Lauf am Folgetag schreibt keine Datei neu."""
import datetime
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest

HIER = os.path.dirname(os.path.abspath(__file__))
SKRIPT = os.path.join(HIER, "..", "scripts", "rules_to_runbooks.py")
REGELN = os.path.join(HIER, "..", "config", "rules.yaml")

spec = importlib.util.spec_from_file_location("rules_to_runbooks", SKRIPT)
gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)


class ZweiterLauf(unittest.TestCase):
    def test_folgetag_ohne_regelaenderung_ist_same(self):
        with tempfile.TemporaryDirectory() as vault:
            erster = subprocess.run([sys.executable, SKRIPT, "--rules", REGELN, "--vault", vault],
                                    capture_output=True, text=True, check=True).stdout
            self.assertIn("WROTE", erster)
            # Tagesstempel in allen Dateien auf gestern zuruecksetzen
            heute = datetime.date.today().isoformat()
            gestern = (datetime.date.today() - datetime.timedelta(days=1)).isoformat()
            for wurzel, _, dateien in os.walk(vault):
                for name in dateien:
                    p = os.path.join(wurzel, name)
                    with open(p, encoding="utf-8") as fh:
                        t = fh.read()
                    with open(p, "w", encoding="utf-8") as fh:
                        fh.write(t.replace(heute, gestern))
            zweiter = subprocess.run([sys.executable, SKRIPT, "--rules", REGELN, "--vault", vault],
                                     capture_output=True, text=True, check=True).stdout
            self.assertNotIn("WROTE", zweiter)
            self.assertIn("SAME", zweiter)

    def test_inhaltsaenderung_wird_geschrieben(self):
        alt = "---\nupdated: 2026-11-20\ngenerated: true\n---\nA\n"
        with tempfile.TemporaryDirectory() as vault:
            p = os.path.join(vault, "x", "r.md")
            gen.write(p, alt, False)
            self.assertTrue(gen.write(p, alt.replace("A", "B").replace("20", "21"), False).startswith("WROTE"))


if __name__ == "__main__":
    unittest.main()

"""Verlauf aus der Chronik fuer kritische Alarme (ZIELBILD 67 Stufe 4)."""
import unittest
from datetime import date

from app import verlauf

HEUTE = date(2026, 11, 4)


def notiz(alarme: str, gebaut: str = "") -> str:
    return (f"# Chronik\n\n1 Commits in 1 Repos.\n\n## Gebaut\n\n{gebaut}\n## Ereignisse\n\n"
            f"### Alarme\n\n{alarme}\n\n### Ausfälle (Blackbox)\n\nKeine.\n")


JF = "- 17:43 bis 18:12 (30 min): JellyfinWillNachDraussen (node1) [critical]"


class VerlaufTests(unittest.TestCase):
    def test_nur_kritische(self):
        self.assertTrue(verlauf.ist_kritisch({"severity": "critical"}))
        self.assertTrue(verlauf.ist_kritisch({"labels": {"severity": "critical"}}))
        self.assertFalse(verlauf.ist_kritisch({"severity": "warning"}))

    def test_alarmname_aus_topic_oder_payload(self):
        self.assertEqual(verlauf.alarmname("homelab/alerts/BackupFailed/fired", {}), "BackupFailed")
        self.assertEqual(verlauf.alarmname("homelab/kalender/service/unhealthy", {"alertname": "ServiceDown"}), "ServiceDown")

    def test_erster_fall(self):
        n = {date(2026, 11, 3): notiz("- 01:00 bis 01:05 (6 min): HostHighCpu (node2) [warning]")}
        self.assertEqual(verlauf.verlauf_text("BackupFailed", n, HEUTE),
                         "Verlauf (Chronik): kein früherer Fall von BackupFailed in 1 Tagen mit Chronik.")

    def test_letzter_fall_regelmaessig_und_commit_mit_suchwort(self):
        gebaut = ("### host/homelab-work (2)\n- 17:00 `aaaaaaa` jellyfin vorher, zaehlt nicht\n"
                  "- 17:51 `f114847` monitoring: Jellyfin-Alarmtexte richtig\n")
        n = {date(2026, 11, 1): notiz(JF), date(2026, 11, 2): notiz(JF.replace("17:43", "17:40")),
             date(2026, 11, 3): notiz(JF.replace("17:43", "17:42"), gebaut)}
        satz = verlauf.verlauf_text("JellyfinWillNachDraussen", n, HEUTE, {"host": "node1"})
        self.assertTrue(satz.startswith("Verlauf (Chronik): zuletzt am 3. November 17:42 bis 18:12 (30 min, node1), an 3 von 3 Tagen mit Chronik."), satz)
        self.assertIn("Kommt regelmäßig gegen 17:42 (3 von 3 Fällen).", satz)
        self.assertIn("mit „Jellyfin“ im Text: homelab-work f114847", satz)
        self.assertNotIn("aaaaaaa", satz)

    def test_ueber_mitternacht_mit_ende_und_fremder_host(self):
        n = {date(2026, 10, 27): notiz("- 04:04, über Mitternacht hinaus: BackupFailed (host) [critical]"),
             date(2026, 10, 28): notiz("- seit dem Vortag bis 04:03: BackupFailed (host) [critical]")}
        satz = verlauf.verlauf_text("BackupFailed", n, HEUTE, {"host": "node2"})
        self.assertIn("zuletzt am 27. Oktober 04:04 bis 28. Oktober 04:03 (host), an 1 von 2 Tagen", satz)
        self.assertIn("Auf node2 bisher nicht.", satz)
        self.assertIn("Danach kein Commit", satz)

    def test_laufende_phase_heute_zaehlt_nicht(self):
        n = {HEUTE: notiz("- 09:00, über Mitternacht hinaus: BackupFailed (host) [critical]")}
        self.assertIn("kein früherer Fall", verlauf.verlauf_text("BackupFailed", n, HEUTE))

    def test_allgemeiner_namensteil_ordnet_nicht_zu(self):
        gebaut = "### host/homelab-work (1)\n- 05:00 `bbbbbbb` Host-Liste aufgeraeumt\n"
        n = {date(2026, 11, 3): notiz("- 04:00 bis 04:30 (31 min): HostDiskAlmostFull (node1) [critical]", gebaut)}
        self.assertIn("Danach kein Commit", verlauf.verlauf_text("HostDiskAlmostFull", n, HEUTE, {"host": "node1"}))


if __name__ == "__main__":
    unittest.main()

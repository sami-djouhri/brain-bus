"""Freigaben ohne host-junior: die Warteschlange ist die Wahrheit.

Bis 2026-11-20 schickte `confirmations.request` die Anfrage als Discord-Knopf
über host-junior und setzte sie auf `notify_failed`, sobald der Bot nicht
antwortete, obwohl Tardis sie weiter hätte entscheiden können. Jetzt bleibt
sie `pending`, und ntfy gibt nur einen Hinweis mit Link auf Tardis.
"""

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from app import confirmations, db
from app.config import settings


class _FakeNtfy:
    aufrufe: list = []

    def __init__(self, *a, **k):
        pass

    async def publish(self, **kwargs):
        type(self).aufrufe.append(kwargs)


class _KaputtNtfy(_FakeNtfy):
    async def publish(self, **kwargs):
        # Der echte Client ist fail-silent; hier zaehlt nur, dass request()
        # den Status nicht vom Versand abhaengig macht.
        return None


def _anfragen():
    return asyncio.run(confirmations.request(
        rule_id="backup-job-failed", fingerprint="fp1", tool_name="backup.retry_service",
        args={"service_id": "gitea"}, risk="medium", reasoning_text="Lauf scheiterte."))


class FreigabeWarteschlange(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        db.init(Path(self.tmp.name) / "brain.db")
        _FakeNtfy.aufrufe = []
        self._url = settings.ntfy_url
        settings.ntfy_url = "http://ntfy"

    def tearDown(self):
        settings.ntfy_url = self._url
        self.tmp.cleanup()

    def test_anfrage_bleibt_offen_und_meldet_auf_ntfy(self):
        with mock.patch.object(confirmations, "NtfyClient", _FakeNtfy):
            ergebnis = _anfragen()
        self.assertEqual(ergebnis["result"], "queued")
        zeile = db.get_confirmation(ergebnis["callback_id"])
        self.assertEqual(zeile["status"], "pending")
        self.assertEqual(len(_FakeNtfy.aufrufe), 1)
        hinweis = _FakeNtfy.aufrufe[0]
        self.assertEqual(hinweis["topic"], "host-warn")
        self.assertIn("Tardis", hinweis["message"])
        self.assertEqual(hinweis["click"], confirmations.TARDIS_FREIGABE_URL)

    def test_versandfehler_aendert_den_status_nicht(self):
        with mock.patch.object(confirmations, "NtfyClient", _KaputtNtfy):
            ergebnis = _anfragen()
        self.assertEqual(db.get_confirmation(ergebnis["callback_id"])["status"], "pending")

    def test_doppelte_anfrage(self):
        with mock.patch.object(confirmations, "NtfyClient", _FakeNtfy):
            _anfragen()
            self.assertEqual(_anfragen()["result"], "duplicate")
        self.assertEqual(len(_FakeNtfy.aufrufe), 1)

    def test_ohne_ntfy_trotzdem_in_der_warteschlange(self):
        settings.ntfy_url = None
        with mock.patch.object(confirmations, "NtfyClient", _FakeNtfy):
            ergebnis = _anfragen()
        self.assertEqual(ergebnis["result"], "queued")
        self.assertEqual(_FakeNtfy.aufrufe, [])


if __name__ == "__main__":
    unittest.main()

"""Schreibende HTTP-Wege des brain-bus (leitstand #17).

brain-bus haengt in cc-core und cc-apps, jeder Container dort erreicht ihn direkt.
Die Freigabe darf deshalb nur mit dem geteilten Geheimnis aus Tardis wirken, und
einen Lernlauf per HTTP gibt es nicht (Ausloeser ist allein der Host-Cron).
"""
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from app import confirmations
from app.main import app


class FreigabeGeheimnisTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.url = "/api/confirmations/gibt-es-nicht/resolve"

    def test_ohne_geheimnis_401(self):
        with mock.patch.object(confirmations, "_shared_secret", return_value="richtig"):
            r = self.client.post(self.url, json={"decision": "approved", "user": "probe"})
        self.assertEqual(r.status_code, 401)

    def test_falsches_geheimnis_401(self):
        with mock.patch.object(confirmations, "_shared_secret", return_value="richtig"):
            r = self.client.post(self.url, json={"decision": "approved", "secret": "falsch"})
        self.assertEqual(r.status_code, 401)

    def test_ohne_server_geheimnis_503_statt_durchlassen(self):
        with mock.patch.object(confirmations, "_shared_secret", return_value=None):
            r = self.client.post(self.url, json={"decision": "approved", "secret": ""})
        self.assertEqual(r.status_code, 503)

    def test_richtiges_geheimnis_kommt_bis_zur_suche(self):
        with mock.patch.object(confirmations, "_shared_secret", return_value="richtig"), \
                mock.patch.object(confirmations.db, "get_confirmation", return_value=None):
            r = self.client.post(self.url, json={"decision": "approved", "secret": "richtig"})
        self.assertEqual(r.status_code, 404)


class LernlaufNurPerCronTests(unittest.TestCase):
    def test_kein_post_run(self):
        r = TestClient(app).post("/api/learner/run")
        self.assertIn(r.status_code, (404, 405))

    def test_keine_schreibende_learner_route(self):
        schreibend = [
            (r.path, sorted(r.methods))
            for r in app.routes
            if getattr(r, "path", "").startswith("/api/learner")
            and set(getattr(r, "methods", set())) - {"GET", "HEAD", "OPTIONS"}
        ]
        self.assertEqual(schreibend, [])


if __name__ == "__main__":
    unittest.main()

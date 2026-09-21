import json
import tempfile
import unittest

from app.config import settings
from app.registry import load_registry, reload_registry
from fastapi.testclient import TestClient

from app import health
from app.main import app


class HealthTests(unittest.TestCase):
    def test_health_ok(self):
        client = TestClient(app)
        r = client.get("/health")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["status"], "ok")
        self.assertIn("service", data)

    def test_registry_summary_and_service_endpoint(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            registry_path = f"{tmpdir}/platform-registry.json"
            with open(registry_path, "w", encoding="utf-8") as f:
                f.write(
                    json.dumps(
                        {
                            "updated_at": "2026-05-05T08:00:00+00:00",
                            "hosts": [{"id": "host"}],
                            "services": [
                                {
                                    "id": "homeassistant",
                                    "title": "Home Assistant",
                                    "group": "home",
                                    "current_host": "host",
                                    "target_host": "host",
                                    "state": "active",
                                    "criticality": "high",
                                    "capabilities": ["automation"],
                                    "value": ["core"],
                                    "next_stage": "operate",
                                }
                            ],
                        }
                    )
                )
            original_registry_path = settings.registry_path
            settings.registry_path = registry_path
            reload_registry()
            try:
                client = TestClient(app)
                summary = client.get("/api/registry/summary")
                self.assertEqual(summary.status_code, 200)
                summary_data = summary.json()
                self.assertEqual(summary_data["service_count"], 1)
                self.assertEqual(summary_data["critical_services"], 1)

                service = client.get("/api/registry/services/homeassistant")
                self.assertEqual(service.status_code, 200)
                service_data = service.json()
                self.assertEqual(service_data["id"], "homeassistant")
                self.assertEqual(service_data["criticality"], "high")
            finally:
                settings.registry_path = original_registry_path
                load_registry.cache_clear()


# --- Readiness-Checks (R1: /health gibt 503 statt still "ok") ---

def setup_function() -> None:
    health.clear_checks()


def teardown_function() -> None:
    health.clear_checks()


def test_health_ok_without_checks():
    client = TestClient(app)
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert "checks" not in r.json()


def test_health_ok_with_passing_check():
    health.register_check("db", lambda: None)
    client = TestClient(app)
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["checks"]["db"] == "ok"


def test_health_degraded_on_failing_check():
    def boom() -> None:
        raise RuntimeError("db unreachable")

    health.register_check("db", boom)
    client = TestClient(app)
    r = client.get("/health")
    assert r.status_code == 503
    data = r.json()
    assert data["status"] == "degraded"
    assert "db unreachable" in data["checks"]["db"]

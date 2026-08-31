import json
import tempfile
import unittest

from app.config import settings
from app.registry import extract_service_ids, get_service, load_registry, reload_registry


class RegistryTests(unittest.TestCase):
    def test_registry_service_lookup(self):
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
                service = get_service("homeassistant")
                self.assertIsNotNone(service)
                self.assertEqual(service.current_host, "host")
                self.assertEqual(service.criticality, "high")
            finally:
                settings.registry_path = original_registry_path
                load_registry.cache_clear()

    def test_extract_service_ids_from_topic_and_payload(self):
        payload = {
            "service": "lernen",
            "affected_services": ["homeassistant", "lernen"],
        }
        service_ids = extract_service_ids("homelab/homeassistant/service/unhealthy", payload)
        self.assertEqual(service_ids, ["homeassistant", "lernen"])

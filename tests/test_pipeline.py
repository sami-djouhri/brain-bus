import asyncio
import json
import tempfile
import unittest

from app import actions, tool_runner
from app.config import settings
from app.pipeline import _build_suggestion
from app.registry import load_registry, reload_registry
from app.rules import Event, Rule


class PipelineTests(unittest.TestCase):
    def test_build_suggestion_enriches_impacted_services_and_priority(self):
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
                rule = Rule(
                    id="service-unhealthy",
                    topic_pattern="homelab/+/service/unhealthy",
                    min_events=1,
                    window_seconds=60,
                    triage={"hint": "Service unhealthy", "memory_tags": ["service"]},
                    ntfy={"priority": "medium", "topic": "host-ops"},
                    suggest_topic="homelab/brain/suggestion/incident",
                )
                rule.events.append(
                    Event(
                        topic="homelab/homeassistant/service/unhealthy",
                        payload={"status": "down"},
                        received_at=1713980000.0,
                    )
                )

                suggestion = _build_suggestion(rule)

                self.assertEqual(suggestion["impacted_services"][0]["id"], "homeassistant")
                self.assertEqual(suggestion["ntfy"]["priority"], "critical")
            finally:
                settings.registry_path = original_registry_path
                load_registry.cache_clear()

    def test_action_when_skips_remote_container_restart(self):
        original_get = tool_runner.get
        tool_runner.get = lambda name: tool_runner.ToolSpec(
            name=name,
            description="restart",
            risk="medium",
            endpoint="http://docker-api/restart/{name}",
            method="POST",
            args_schema={"name": {"type": "string", "required": True, "in": "path"}},
            auth=None,
        )
        try:
            result = asyncio.run(
                actions.dispatch(
                    rule_id="container-restart-loop",
                    fingerprint="abc",
                    action_spec={
                        "tool": "docker.restart_container",
                        "args": {"name": "{{ event.payload.labels.name }}"},
                        "risk": "medium",
                        "when": {"event.payload.labels.host": "host"},
                    },
                    event_payload={"labels": {"host": "node1", "name": "cadvisor"}},
                    decision=None,
                )
            )
        finally:
            tool_runner.get = original_get

        self.assertEqual(result["result"], actions.DispatchResult.SKIPPED_CONDITION)

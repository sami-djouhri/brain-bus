"""V1 „Gläserne Autonomie": jede autonome Aktion bekommt eine persistente,
abfragbare Warum-Spur (decision_confidence/decision_reasoning/decision_source)
in der actions-Zeile. Testet Migration (idempotent) + Auto-Pfad (mit/ohne
LLM-Entscheidung)."""

import asyncio
import tempfile
import unittest
from pathlib import Path

from app import actions, audit, db, tool_runner


class DecisionTraceTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._db_path = Path(self._tmp.name) / "brain.db"
        db.init(self._db_path)

        # Seiteneffekte stubben (kein MQTT/HTTP/Memory in Unit-Tests).
        self._orig = {
            "get": tool_runner.get,
            "run": tool_runner.run,
            "mqtt": audit.publish_mqtt,
            "mem": audit.write_memory,
        }
        tool_runner.get = lambda name: tool_runner.ToolSpec(
            name=name, description="noop", risk="low",
            endpoint="http://noop/{name}", method="POST",
            args_schema={}, auth=None,
        )

        async def _fake_run(spec, args):
            return {"status": "success", "http_status": 200,
                    "response_excerpt": "ok", "elapsed_ms": 3}

        async def _fake_mem(record):
            return None

        tool_runner.run = _fake_run
        audit.publish_mqtt = lambda record: None
        audit.write_memory = _fake_mem

    def tearDown(self):
        tool_runner.get = self._orig["get"]
        tool_runner.run = self._orig["run"]
        audit.publish_mqtt = self._orig["mqtt"]
        audit.write_memory = self._orig["mem"]
        self._tmp.cleanup()

    def _cols(self):
        with db.connect() as conn:
            return {r["name"] for r in conn.execute("PRAGMA table_info(actions)")}

    def test_migration_adds_decision_columns(self):
        cols = self._cols()
        self.assertIn("decision_confidence", cols)
        self.assertIn("decision_reasoning", cols)
        self.assertIn("decision_source", cols)

    def test_init_is_idempotent(self):
        # Zweiter init darf nicht an "duplicate column" scheitern (ALTER guarded).
        db.init(self._db_path)
        self.assertIn("decision_reasoning", self._cols())

    def test_auto_action_persists_decision_trace(self):
        decision = {
            "summary": "Dienst ist hart down",
            "recommend_action": True,
            "confidence": 82,
            "reason_for_decision": "Restart ist die dokumentierte Standard-Reaktion",
            "llm_source": "gemma-node2",
        }
        result = asyncio.run(actions.dispatch(
            rule_id="unit-decision-rule", fingerprint="fp-trace-1",
            action_spec={"tool": "test.noop", "args": {}, "risk": "low"},
            event_payload={}, decision=decision,
        ))
        self.assertEqual(result["result"], actions.DispatchResult.EXECUTED_AUTO)
        row = db.list_actions(limit=5)[0]
        self.assertEqual(row["decision_confidence"], 82)
        self.assertIn("Restart", row["decision_reasoning"])
        self.assertIn("hart down", row["decision_reasoning"])
        self.assertEqual(row["decision_source"], "gemma-node2")
        self.assertEqual(row["status"], "success")

    def test_auto_action_without_decision_leaves_trace_null(self):
        # risk:low ohne rule.diagnose → kein decide.judge() → Spur bleibt ehrlich leer.
        result = asyncio.run(actions.dispatch(
            rule_id="unit-decision-rule-2", fingerprint="fp-trace-2",
            action_spec={"tool": "test.noop", "args": {}, "risk": "low"},
            event_payload={}, decision=None,
        ))
        self.assertEqual(result["result"], actions.DispatchResult.EXECUTED_AUTO)
        row = db.list_actions(limit=5)[0]
        self.assertIsNone(row["decision_confidence"])
        self.assertIsNone(row["decision_reasoning"])
        self.assertIsNone(row["decision_source"])

    def test_confirm_action_persists_reasoning_from_confirmation(self):
        # Confirm-Pfad läuft NICHT durch _execute(): confirmations.resolve() baut
        # die actions-Zeile inline. decision_reasoning stammt aus der beim request()
        # persistierten reasoning_text, decision_source markiert die Owner-Freigabe.
        from app import confirmations, secrets_store
        orig_secret = secrets_store.get
        secrets_store.get = lambda key: "unit-secret" if key == "brain_callback_secret" else None
        try:
            cid = "conf-unit-1"
            db.insert_confirmation({
                "id": cid, "created_at": audit.now_iso(),
                "expires_at": "2999-01-01T00:00:00+00:00",
                "rule_id": "disk-pressure", "fingerprint": "fp-conf-1",
                "tool_name": "test.noop", "args_json": "{}", "risk": "medium",
                "reasoning_text": "Alte Images entfernen; Platte bei 92%",
                "status": "pending", "resolved_by": None, "resolved_at": None,
                "discord_message_id": None,
            })
            res = asyncio.run(confirmations.resolve(
                cid, decision="approved", user="sami", secret="unit-secret"))
            self.assertTrue(res["ok"])
            self.assertTrue(res["executed"])
            row = db.list_actions(limit=5)[0]
            self.assertEqual(row["source"], "confirm")
            self.assertIn("Alte Images", row["decision_reasoning"])
            self.assertEqual(row["decision_source"], "confirm:sami")
            self.assertIsNone(row["decision_confidence"])
        finally:
            secrets_store.get = orig_secret


class MemoryWarumSpurTests(unittest.TestCase):
    """V1: die Per-Action-Memory-Note (was `memory.recall` liefert) trägt die
    Warum-Spur, sonst weiß der Assistent WAS geschah, aber nicht WARUM."""

    def test_llm_decision_note_carries_reasoning(self):
        rec = {
            "tool_name": "service.restart", "rule_id": "svc-down",
            "source": "auto", "status": "success", "http_status": 200,
            "args_json": '{"service_id": "foo"}', "response_excerpt": "ok",
            "decision_confidence": 82, "decision_source": "gemma-node2",
            "decision_reasoning": "Dienst hart down\n\nRestart ist Standard-Reaktion",
        }
        content, tags = audit._build_memory_note(rec)
        self.assertIn("Confidence: 82/100", content)
        self.assertIn("Entschieden von: gemma-node2", content)
        self.assertIn("Restart ist Standard-Reaktion", content)
        self.assertIn("warum-spur", tags)
        self.assertNotIn("low-confidence", tags)

    def test_low_confidence_is_flagged(self):
        rec = {
            "tool_name": "x.y", "rule_id": "r", "source": "auto",
            "status": "success", "decision_confidence": 31,
            "decision_reasoning": "unsicher", "decision_source": "gemma-node2",
        }
        _, tags = audit._build_memory_note(rec)
        self.assertIn("low-confidence", tags)

    def test_auto_without_decision_gets_deterministic_warum(self):
        rec = {
            "tool_name": "backup.retry_service", "rule_id": "backup-failed",
            "source": "auto", "status": "success",
        }
        content, tags = audit._build_memory_note(rec)
        self.assertIn("Warum: automatisch ausgeführt", content)
        self.assertIn("backup-failed", content)
        self.assertIn("warum-spur", tags)
        self.assertNotIn("low-confidence", tags)

    def test_reasoning_is_redacted(self):
        rec = {
            "tool_name": "x.y", "rule_id": "r", "source": "auto",
            "status": "success", "decision_confidence": 90,
            "decision_reasoning": "token=supersecret123 also Restart",
            "decision_source": "gemma-node2",
        }
        content, _ = audit._build_memory_note(rec)
        self.assertNotIn("supersecret123", content)
        self.assertIn("Restart", content)


class DecisionsAgainstActingTests(unittest.TestCase):
    """V1 „Gläserne Autonomie" (2. Schritt): das System persistiert auch
    Entscheidungen GEGEN Handeln (recommend_action=False / unter Confidence-
    Schwelle) — in die separate decisions-Tabelle, damit „warum hat es NICHT
    eingegriffen?" beantwortbar wird. Ohne UNIQUE(rule_id,fingerprint)-Kollision
    mit einer späteren echten actions-Ausführung."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._db_path = Path(self._tmp.name) / "brain.db"
        db.init(self._db_path)

        self._orig = {"get": tool_runner.get, "run": tool_runner.run,
                      "mqtt": audit.publish_mqtt, "mem": audit.write_memory}
        tool_runner.get = lambda name: tool_runner.ToolSpec(
            name=name, description="noop", risk="low",
            endpoint="http://noop/{name}", method="POST", args_schema={}, auth=None)

        async def _fake_run(spec, args):
            return {"status": "success", "http_status": 200,
                    "response_excerpt": "ok", "elapsed_ms": 3}

        async def _fake_mem(record):
            return None

        tool_runner.run = _fake_run
        audit.publish_mqtt = lambda record: None
        audit.write_memory = _fake_mem

    def tearDown(self):
        tool_runner.get = self._orig["get"]
        tool_runner.run = self._orig["run"]
        audit.publish_mqtt = self._orig["mqtt"]
        audit.write_memory = self._orig["mem"]
        self._tmp.cleanup()

    def test_decisions_table_exists(self):
        with db.connect() as conn:
            names = {r["name"] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn("decisions", names)

    def test_not_recommended_persists_decision(self):
        decision = {
            "summary": "Dienst wackelt nur kurz",
            "recommend_action": False,
            "confidence": 70,
            "reason_for_decision": "Flapping, kein harter Ausfall — Restart waere voreilig",
            "llm_source": "gemma-node2",
        }
        result = asyncio.run(actions.dispatch(
            rule_id="svc-flapping", fingerprint="fp-na-1",
            action_spec={"tool": "service.restart", "args": {"service_id": "foo"},
                         "risk": "medium"},
            event_payload={}, decision=decision,
        ))
        self.assertEqual(result["result"], actions.DispatchResult.SKIPPED_NOT_RECOMMENDED)
        rows = db.list_decisions(limit=5)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["outcome"], "not_recommended")
        self.assertEqual(rows[0]["rule_id"], "svc-flapping")
        self.assertEqual(rows[0]["confidence"], 70)
        self.assertIn("voreilig", rows[0]["reasoning"])
        self.assertEqual(rows[0]["llm_source"], "gemma-node2")
        # separat von actions: keine actions-Zeile fuer die Nicht-Aktion
        self.assertEqual(db.list_actions(limit=5), [])

    def test_below_threshold_persists_decision(self):
        decision = {
            "summary": "Koennte helfen",
            "recommend_action": True,
            "confidence": 40,
            "reason_for_decision": "Unsicher, ob die Ursache wirklich behoben wird",
            "llm_source": "gemma-node2",
        }
        result = asyncio.run(actions.dispatch(
            rule_id="disk-pressure", fingerprint="fp-bt-1",
            action_spec={"tool": "cleanup.images", "args": {}, "risk": "low",
                         "confidence_threshold": 60},
            event_payload={}, decision=decision,
        ))
        self.assertEqual(result["result"], actions.DispatchResult.SKIPPED_NOT_RECOMMENDED)
        rows = db.list_decisions(limit=5)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["outcome"], "below_threshold")
        self.assertEqual(rows[0]["threshold"], 60)
        self.assertEqual(rows[0]["confidence"], 40)

    def test_executed_action_does_not_persist_decision(self):
        # Wird gehandelt (recommend_action=True, keine Schwelle) → kein decisions-Row,
        # die Warum-Spur lebt in der actions-Zeile.
        decision = {"summary": "down", "recommend_action": True, "confidence": 90,
                    "reason_for_decision": "klarer Ausfall", "llm_source": "gemma-node2"}
        result = asyncio.run(actions.dispatch(
            rule_id="svc-down", fingerprint="fp-ex-1",
            action_spec={"tool": "service.restart", "args": {}, "risk": "low"},
            event_payload={}, decision=decision,
        ))
        self.assertEqual(result["result"], actions.DispatchResult.EXECUTED_AUTO)
        self.assertEqual(db.list_decisions(limit=5), [])
        self.assertEqual(len(db.list_actions(limit=5)), 1)

    def test_reasoning_is_redacted(self):
        decision = {"summary": "geheim", "recommend_action": False, "confidence": 55,
                    "reason_for_decision": "token=supersecret123 also nichts tun",
                    "llm_source": "gemma-node2"}
        asyncio.run(actions.dispatch(
            rule_id="r", fingerprint="fp-red-1",
            action_spec={"tool": "t.noop", "args": {}, "risk": "low",
                         "confidence_threshold": 0}, event_payload={}, decision=decision,
        ))
        rows = db.list_decisions(limit=5)
        self.assertEqual(len(rows), 1)
        self.assertNotIn("supersecret123", rows[0]["reasoning"])

    def test_prune_removes_old_decisions(self):
        db.insert_decision({"id": "old", "created_at": "2000-01-01T00:00:00+00:00",
                            "rule_id": "r", "outcome": "not_recommended"})
        db.insert_decision({"id": "new", "created_at": "2999-01-01T00:00:00+00:00",
                            "rule_id": "r", "outcome": "not_recommended"})
        removed = db.prune_decisions("2500-01-01T00:00:00+00:00")
        self.assertEqual(removed, 1)
        ids = {r["id"] for r in db.list_decisions(limit=10)}
        self.assertEqual(ids, {"new"})


if __name__ == "__main__":
    unittest.main()

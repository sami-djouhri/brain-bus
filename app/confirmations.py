"""
Confirmation-Flow:
1. brain-bus actions.dispatch() für risk:medium → request()
   → INSERT confirmations row (die Warteschlange ist die Wahrheit) + ntfy-Hinweis
2. Owner gibt in Tardis (Ops, Freigaben) frei oder lehnt ab
   → Tardis POST /api/confirmations/{id}/resolve
3. brain-bus validiert shared-secret, UPDATE confirmation, executes tool, audits.

Bis 2026-11-20 lief Schritt 2 über Discord-Knöpfe von host-junior, und ein
nicht erreichbarer Bot setzte die Anfrage auf `notify_failed`, obwohl sie in
Tardis weiter hätte entschieden werden können.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import os

from app import audit, db, secrets_store, tool_runner
from app.config import settings
from app.logging_config import get_logger
from app.notify import NtfyClient

log = get_logger(__name__)


CONFIRM_TTL_SECONDS = 86400  # 24h, Backup-Alerts will man auch morgens noch quittieren
TARDIS_FREIGABE_URL = os.environ.get("TARDIS_FREIGABE_URL", "https://192.0.2.10/#ops")


def _shared_secret() -> str | None:
    return secrets_store.get("brain_callback_secret")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _expires_iso(ttl_s: int = CONFIRM_TTL_SECONDS) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=ttl_s)).isoformat()


async def request(
    *,
    rule_id: str,
    fingerprint: str,
    tool_name: str,
    args: dict[str, Any],
    risk: str,
    reasoning_text: str,
    ttl_s: int = CONFIRM_TTL_SECONDS,
) -> dict[str, Any]:
    """Erzeugt die SQLite-Row und schickt einen ntfy-Hinweis.
    Returns {result: queued|duplicate, callback_id?}.
    """
    callback_id = uuid.uuid4().hex
    row = {
        "id": callback_id,
        "created_at": _now_iso(),
        "expires_at": _expires_iso(ttl_s),
        "rule_id": rule_id,
        "fingerprint": fingerprint,
        "tool_name": tool_name,
        "args_json": json.dumps(args, default=str),
        "risk": risk,
        "reasoning_text": reasoning_text,
        "status": "pending",
        "resolved_by": None,
        "resolved_at": None,
        "discord_message_id": None,
    }
    inserted = db.insert_confirmation(row)
    if not inserted:
        log.info(
            "confirmation.duplicate",
            rule_id=rule_id,
            fingerprint=fingerprint,
            tool=tool_name,
        )
        return {"result": "duplicate"}

    # Der Hinweis ist nur ein Anstoß, die Anfrage steht schon in der
    # Warteschlange und ist in Tardis entscheidbar. Ein gescheiterter Push
    # ändert deshalb nichts am Status (fail-silent wie jeder ntfy-Versand).
    log.info("confirmation.requested", callback_id=callback_id, rule_id=rule_id, tool=tool_name)
    if settings.ntfy_url:
        ttl_h = max(1, ttl_s // 3600)
        await NtfyClient(settings.ntfy_url, token_file=settings.ntfy_token_file).publish(
            title=f"Freigabe noetig: {tool_name}",
            message=(
                f"Regel {rule_id}, Risiko {risk}. Entscheiden in der Tardis-App unter Freigaben "
                f"(Hausbus fragt) oder in Tardis-Web > Ops "
                f"(verfaellt nach {ttl_h} h).\n\n{reasoning_text[:1500]}"
            ),
            topic="host-warn",
            priority="high",
            click=TARDIS_FREIGABE_URL,
        )

    return {"result": "queued", "callback_id": callback_id}


async def resolve(
    callback_id: str,
    *,
    decision: str,
    user: str,
    secret: str | None,
) -> dict[str, Any]:
    """Wird von Tardis aufgerufen, wenn der Owner freigibt oder ablehnt.

    Auth: shared-secret per `secret` arg (constant-time compare).
    Fail-closed: wenn Server-Secret nicht geladen, 503 (kein silent bypass).
    TTL: vor jeder Aktion expires_at prüfen, race gegen expire_loop schließen.
    """
    expected = _shared_secret()
    if not expected:
        log.error("confirmation.resolve.no_server_secret")
        return {"ok": False, "error": "server secret unconfigured", "http": 503}
    if not secret or not hmac.compare_digest(
        secret.encode("utf-8"), expected.encode("utf-8")
    ):
        return {"ok": False, "error": "secret mismatch", "http": 401}

    decision = (decision or "").lower()
    if decision not in ("approved", "denied", "expired"):
        return {"ok": False, "error": "invalid decision", "http": 400}

    row = db.get_confirmation(callback_id)
    if not row:
        return {"ok": False, "error": "not found", "http": 404}

    # Ein echter User-Klick gewinnt immer: eine bereits abgelaufene (vom
    # expire_loop auf "expired" gesetzte) oder pending-aber-TTL-ueberschrittene
    # Confirmation wird bei "approved" wiederbelebt statt in eine Sackgasse zu
    # laufen (Button reagiert sonst gefuehlt "nicht"). Final entschiedene
    # (approved/denied/executed/failed) bleiben gesperrt.
    if row["status"] not in ("pending", "expired"):
        return {
            "ok": False,
            "error": f"already {row['status']}",
            "http": 409,
            "current_status": row["status"],
        }

    try:
        expires = datetime.fromisoformat(row["expires_at"])
    except (TypeError, ValueError):
        expires = None
    ttl_passed = expires is not None and datetime.now(timezone.utc) >= expires

    if row["status"] == "expired" or ttl_passed:
        if decision != "approved":
            db.update_confirmation(
                callback_id,
                {"status": "expired", "resolved_by": user or "system",
                 "resolved_at": _now_iso()},
            )
            return {
                "ok": True,
                "executed": False,
                "decision": "expired",
                "note": "confirmation expired",
            }
        log.info("confirmation.revived_on_approve", callback_id=callback_id, user=user)

    db.update_confirmation(
        callback_id,
        {
            "status": decision,
            "resolved_by": user,
            "resolved_at": _now_iso(),
        },
    )
    log.info(
        "confirmation.resolved",
        callback_id=callback_id,
        decision=decision,
        user=user,
        tool=row["tool_name"],
    )

    if decision != "approved":
        return {"ok": True, "executed": False, "decision": decision}

    # Execute the tool now.
    spec = tool_runner.get(row["tool_name"])
    if spec is None:
        log.warning("confirmation.unknown_tool_at_execute", tool=row["tool_name"])
        db.update_confirmation(callback_id, {"status": "failed"})
        return {"ok": False, "error": "tool unknown", "http": 500}

    try:
        args = json.loads(row["args_json"])
    except Exception:
        args = {}

    # Re-validate (tool spec may have changed)
    try:
        validated = tool_runner.validate_and_coerce(spec, args)
    except tool_runner.ArgError as e:
        db.update_confirmation(callback_id, {"status": "failed"})
        return {"ok": False, "error": f"args: {e}", "http": 400}

    # Insert action row with confirmation_id link
    action_id = uuid.uuid4().hex
    action_row = {
        "id": action_id,
        "created_at": _now_iso(),
        "rule_id": row["rule_id"],
        "fingerprint": row["fingerprint"],
        "tool_name": spec.name,
        "args_json": row["args_json"],
        "source": "confirm",
        "confirmation_id": callback_id,
        "status": "running",
        "http_status": None,
        "response_excerpt": None,
        "elapsed_ms": None,
        "decision_confidence": None,
        "decision_reasoning": (row.get("reasoning_text") or "").strip() or None,
        "decision_source": f"confirm:{user}" if user else "confirm",
    }
    inserted = db.insert_action(action_row)
    if not inserted:
        # Duplicate (rule_id+fingerprint already executed). Unusual aber sicher.
        log.info("confirmation.action_duplicate", callback_id=callback_id)
        db.update_confirmation(callback_id, {"status": "executed"})
        return {"ok": True, "executed": False, "duplicate": True}

    result = await tool_runner.run(spec, validated)
    db.update_action(action_id, {
        "status": result["status"],
        "http_status": result["http_status"],
        "response_excerpt": result["response_excerpt"],
        "elapsed_ms": result["elapsed_ms"],
    })
    db.update_confirmation(
        callback_id,
        {"status": "executed" if result["status"] == "success" else "failed"},
    )

    audit_record = {**action_row, "decision_by": user, "status": result["status"],
                    "http_status": result["http_status"],
                    "response_excerpt": result["response_excerpt"],
                    "elapsed_ms": result["elapsed_ms"]}
    audit.publish_mqtt(audit_record)
    asyncio.create_task(audit.write_memory(audit_record))

    log.info(
        "confirmation.action_executed",
        callback_id=callback_id,
        action_id=action_id,
        tool=spec.name,
        status=result["status"],
        elapsed_ms=result["elapsed_ms"],
    )
    return {
        "ok": True,
        "executed": True,
        "action_id": action_id,
        "outcome": result["status"],
        "http_status": result["http_status"],
        "response_excerpt": result["response_excerpt"][:200],
    }


async def expire_loop(interval_s: float = 900.0) -> None:
    """Background-Task: cleant pending confirms, deren TTL abgelaufen ist."""
    while True:
        try:
            await asyncio.sleep(interval_s)
            n = db.expire_pending(_now_iso())
            if n:
                log.info("confirmation.expired_swept", count=n)
        except asyncio.CancelledError:
            return
        except Exception as exc:
            log.warning("confirmation.expire_loop_error", error=str(exc))

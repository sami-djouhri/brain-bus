"""Event-Producer für den kanonischen Event Spine in life-ops-api.

Spec: ~/homelab-work/HOMELAB_EVENT_SPINE_SPEC_2026-05-13.md
Sink: life-ops-api POST /api/events
"""
import hashlib
import json
from datetime import datetime, timezone

import httpx

from app.config import settings
from app.logging_config import get_logger

log = get_logger(__name__)

SOURCE = "brain-bus"


def _canonical_hash(event_type: str, source: str, external_id: str, occurred_at: str, payload: dict, entity_ref: str | None) -> str:
    blob = json.dumps(
        {
            "event_type": event_type,
            "source": source,
            "external_id": external_id,
            "occurred_at": occurred_at,
            "payload": payload,
            "entity_ref": entity_ref,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(blob.encode()).hexdigest()


async def emit(
    event_type: str,
    summary: str,
    *,
    external_id: str,
    severity: str = "info",
    entity_ref: str | None = None,
    payload: dict | None = None,
) -> bool:
    """Publiziert ein Event an life-ops-api. Best-effort, blockiert nie den Aufrufer."""
    if not settings.life_ops_api_url:
        return False
    occurred_at = datetime.now(timezone.utc).isoformat()
    payload = payload or {}
    event = {
        "event_type": event_type,
        "source": SOURCE,
        "external_id": external_id,
        "occurred_at": occurred_at,
        "summary": summary[:400],
        "severity": severity,
        "entity_ref": entity_ref,
        "payload": payload,
        "hash": _canonical_hash(event_type, SOURCE, external_id, occurred_at, payload, entity_ref),
    }
    url = settings.life_ops_api_url.rstrip("/") + "/api/events"
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            r = await client.post(url, json=event)
            if r.status_code >= 400:
                log.warning("event.emit_failed", status=r.status_code, body=r.text[:200])
                return False
        return True
    except Exception as exc:
        log.warning("event.emit_exception", error=str(exc))
        return False

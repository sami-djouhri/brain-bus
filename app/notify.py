"""
Notify-Client für brain-bus → host-junior Discord-Bot.

POST http://host-junior:8765/notify
    {"title": "...", "message": "...", "urgent": bool}

Wird gerufen wenn Rule.ntfy.priority == "high".
Fail-silent — Notification-Fehler blockieren nichts.
"""

from __future__ import annotations

import os
from pathlib import Path

import httpx

from app.logging_config import get_logger

log = get_logger(__name__)


def _brain_secret() -> str:
    """Liest das geteilte brain_callback_secret (JJ1: /notify ist jetzt auth-pflichtig)."""
    path = Path(os.environ.get("BRAIN_CALLBACK_SECRET_FILE", "/run/secrets/brain_callback_secret"))
    try:
        return path.read_text(encoding="utf-8").strip()
    except Exception:
        return ""


class NotifyClient:
    def __init__(self, base_url: str, enabled: bool = True) -> None:
        self.base_url = base_url.rstrip("/")
        self.enabled = enabled

    async def notify(self, *, title: str, message: str, urgent: bool = False) -> None:
        if not self.enabled:
            return
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(5.0, connect=2.0)) as c:
                resp = await c.post(
                    f"{self.base_url}/notify",
                    json={"title": title, "message": message, "urgent": urgent},
                    headers={"X-Brain-Secret": _brain_secret()},
                )
                log.info(
                    "notify.sent",
                    status=resp.status_code,
                    title=title[:60],
                    urgent=urgent,
                )
        except Exception as exc:
            log.warning("notify.failed", error=str(exc), title=title[:60])

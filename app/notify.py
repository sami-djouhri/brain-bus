"""
Notify-Client für brain-bus → host-junior Discord-Bot.

POST http://host-junior:8765/notify
    {"title": "...", "message": "...", "urgent": bool}

Wird gerufen wenn Rule.ntfy.priority == "high".
Fail-silent, Notification-Fehler blockieren nichts.
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
                # Ein abgelehnter POST ist kein Versand. Bis 2026-08-23 hiess die
                # Zeile auch bei 401/403 "notify.sent" — eine kaputte Zustellung
                # war im Log von einer geglueckten nicht zu unterscheiden.
                if resp.is_success:
                    log.info(
                        "notify.sent", status=resp.status_code, title=title[:60], urgent=urgent
                    )
                else:
                    log.warning(
                        "notify.rejected", status=resp.status_code, title=title[:60], urgent=urgent
                    )
        except Exception as exc:
            log.warning("notify.failed", error=str(exc), title=title[:60])


class NtfyClient:
    """Parallel-Kanal an den host-ntfy (notify-net): macht high/critical-Alarme
    Discord-unabhaengig aufs Handy zustellbar. Fail-silent wie NotifyClient —
    ein ntfy-Fehler darf den Discord-Pfad nie blockieren (und umgekehrt)."""

    # Vollstaendige Abbildung auf die ntfy-Stufen (5=max ... 1=min). Bis 2026-08-23
    # kannte die Tabelle nur high/critical; alles darunter ging ohne X-Priority raus
    # bzw. wurde vom Aufrufer gar nicht erst zugestellt. Damit die drei Kanaele
    # (critical/warn/info) am Handy unterschiedlich klingen, muss jede Stufe gesetzt sein.
    _PRIORITY_MAP = {
        "critical": "5",
        "crit": "5",
        "high": "4",
        "normal": "3",
        "medium": "3",
        "med": "3",
        "low": "2",
    }

    def __init__(
        self,
        base_url: str,
        token_file: str | None = None,
        default_topic: str = "host-critical",
        enabled: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token_file = token_file or "/run/secrets/ntfy_token"
        self.default_topic = default_topic
        self.enabled = enabled and bool(self.base_url)

    def _token(self) -> str:
        try:
            return Path(self.token_file).read_text(encoding="utf-8").strip()
        except Exception:
            return ""

    async def publish(
        self, *, title: str, message: str, topic: str | None = None, priority: str = ""
    ) -> None:
        if not self.enabled:
            return
        target = topic or self.default_topic
        try:
            # Header muessen latin-1-sicher sein; Umlaute im Titel ersetzen statt crashen.
            headers = {"X-Title": title[:200].encode("ascii", "replace").decode()}
            token = self._token()
            if token:
                headers["Authorization"] = f"Bearer {token}"
            prio = self._PRIORITY_MAP.get(priority)
            if prio:
                headers["X-Priority"] = prio
            async with httpx.AsyncClient(timeout=httpx.Timeout(5.0, connect=2.0)) as c:
                resp = await c.post(
                    f"{self.base_url}/{target}",
                    content=message.encode("utf-8"),
                    headers=headers,
                )
                # Wie oben: ohne diese Unterscheidung sieht ein fehlendes
                # Topic-Recht (403) im Log genauso aus wie eine zugestellte
                # Meldung — und der Kanal traegt still nie etwas.
                if resp.is_success:
                    log.info(
                        "ntfy.sent", status=resp.status_code, topic=target, title=title[:60]
                    )
                else:
                    log.warning(
                        "ntfy.rejected", status=resp.status_code, topic=target, title=title[:60]
                    )
        except Exception as exc:
            log.warning("ntfy.failed", error=str(exc), topic=target, title=title[:60])


class IrcClient:
    """Dritter Weg neben Discord und ntfy: der interne IRC-Server auf node1.

    Der Unterschied zu den beiden anderen ist Absicht: Discord und ntfy bekommen
    eine Auswahl (Discord ab high, ntfy je nach Kanal), IRC bekommt **alles** — auch
    das, was fuer einen Push zu leise waere. Ein Chatkanal draengelt nicht, also darf
    er vollstaendig sein; genau das macht ihn zum Ort, an dem man spaeter nachliest
    ("wann fing das an?"). Die ~84 taeglichen Pushes bleiben davon unberuehrt.

    Fail-silent wie die anderen: ein IRC-Fehler darf weder Discord noch ntfy
    blockieren. Welchen Kanal eine Meldung nimmt, entscheidet irc-posten anhand der
    Dringlichkeit — brain-bus muss den Kanalschnitt des Hauses nicht kennen.
    """

    def __init__(
        self,
        base_url: str,
        token_file: str | None = None,
        enabled: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token_file = token_file or "/run/secrets/irc_posten_token"
        self.enabled = enabled and bool(self.base_url)

    def _token(self) -> str:
        try:
            return Path(self.token_file).read_text(encoding="utf-8").strip()
        except Exception:
            return ""

    async def melde(self, *, text: str, dringlichkeit: str = "info") -> None:
        if not self.enabled:
            return
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(5.0, connect=2.0)) as c:
                resp = await c.post(
                    f"{self.base_url}/nachricht",
                    json={
                        "text": text,
                        "dringlichkeit": dringlichkeit or "info",
                        "quelle": "brain-bus",
                    },
                    headers={"Authorization": f"Bearer {self._token()}"},
                )
                # Erfolg und Ablehnung getrennt protokollieren — dieselbe Lehre wie
                # oben bei ntfy: ein 401 sieht sonst im Log aus wie eine Zustellung.
                if resp.is_success:
                    log.info("irc.sent", status=resp.status_code, text=text[:60])
                else:
                    log.warning("irc.rejected", status=resp.status_code, text=text[:60])
        except Exception as exc:
            log.warning("irc.failed", error=str(exc), text=text[:60])

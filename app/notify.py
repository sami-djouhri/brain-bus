"""
Push-Clients für brain-bus.

ntfy ist seit 2026-11-20 der einzige Push-Weg. Der frühere NotifyClient
(POST an host-junior /notify, Discord) ist mit der Ablösung von Junior
entfallen. Alle Clients sind fail-silent, ein Versandfehler blockiert nichts.
"""

from __future__ import annotations

from pathlib import Path

import httpx

from app.logging_config import get_logger

log = get_logger(__name__)


class NtfyClient:
    """Push an den host-ntfy (notify-net), drei Kanaele nach Dringlichkeit.
    Fail-silent: ein ntfy-Fehler darf die Pipeline nie blockieren."""

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
        self, *, title: str, message: str, topic: str | None = None, priority: str = "",
        click: str = "",
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
            if click:
                # Antippen der Meldung oeffnet diese Adresse (ntfy `Click`).
                headers["X-Click"] = click
            async with httpx.AsyncClient(timeout=httpx.Timeout(5.0, connect=2.0)) as c:
                resp = await c.post(
                    f"{self.base_url}/{target}",
                    content=message.encode("utf-8"),
                    headers=headers,
                )
                # Wie oben: ohne diese Unterscheidung sieht ein fehlendes
                # Topic-Recht (403) im Log genauso aus wie eine zugestellte
                # Meldung, und der Kanal traegt still nie etwas.
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
    """Zweiter Weg neben ntfy: der interne IRC-Server auf node1 (seit 2026-11-04 auf Eis).

    Der Unterschied ist Absicht: ntfy bekommt eine Auswahl je Kanal, IRC bekommt
    **alles**, auch das, was fuer einen Push zu leise waere. Ein Chatkanal
    draengelt nicht, also darf er vollstaendig sein; genau das macht ihn zum Ort,
    an dem man spaeter nachliest ("wann fing das an?").

    Fail-silent: ein IRC-Fehler darf ntfy nicht blockieren. Welchen Kanal eine
    Meldung nimmt, entscheidet irc-posten anhand der
    Dringlichkeit: brain-bus muss den Kanalschnitt des Hauses nicht kennen.
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
                # Erfolg und Ablehnung getrennt protokollieren: dieselbe Lehre wie
                # oben bei ntfy: ein 401 sieht sonst im Log aus wie eine Zustellung.
                if resp.is_success:
                    log.info("irc.sent", status=resp.status_code, text=text[:60])
                else:
                    log.warning("irc.rejected", status=resp.status_code, text=text[:60])
        except Exception as exc:
            log.warning("irc.failed", error=str(exc), text=text[:60])

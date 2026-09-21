"""Health-/Readiness-Checks fuer den /health-Endpoint.

Das Template liefert nur die Mechanik: Dienste registrieren optionale
Readiness-Checks (z. B. eine DB-Probe), und `/health` gibt **503** statt 200,
sobald einer fehlschlaegt. Ohne registrierte Checks bleibt `/health` ein reiner
Liveness-Ping (200) -- also voll rueckwaertskompatibel zum alten Verhalten.

Secure-by-default fuer neue Dienste: `HEALTH_DB_PATH` in der env setzen, dann
verdrahtet `main.py` automatisch eine SQLite-Probe -- ohne eine Zeile Code. Der
Container-HEALTHCHECK (`curl -fsS .../health`) wird damit aussagekraeftig: ein
DB-blinder Dienst faellt auf `unhealthy` statt still "ok" zu melden.
"""

from __future__ import annotations

import asyncio
import inspect
import sqlite3
from collections.abc import Awaitable, Callable

from starlette.concurrency import run_in_threadpool

# Ein Check signalisiert Fehler durch eine Exception; der Rueckgabewert wird
# ignoriert. Sync- und async-Callables sind erlaubt.
HealthCheck = Callable[[], Awaitable[None] | None]

_checks: dict[str, HealthCheck] = {}


def register_check(name: str, fn: HealthCheck) -> None:
    """Registriert einen benannten Readiness-Check (idempotent pro Name)."""
    _checks[name] = fn


def clear_checks() -> None:
    """Leert die Registry (v. a. fuer Tests)."""
    _checks.clear()


def registered_checks() -> tuple[str, ...]:
    """Namen der aktuell registrierten Checks."""
    return tuple(_checks)


async def _invoke(fn: HealthCheck) -> None:
    if inspect.iscoroutinefunction(fn):
        await fn()
    else:
        # Sync-Check (z. B. blockierendes SQLite) im Threadpool ausfuehren,
        # damit ein haengender Check den Event-Loop nicht blockiert.
        await run_in_threadpool(fn)


async def run_checks(timeout: float = 5.0) -> tuple[bool, dict[str, str]]:
    """Fuehrt alle registrierten Checks aus.

    Returns ``(healthy, {name: "ok" | "error: ..."})``. Ohne Checks: ``(True, {})``.
    Ein Check, der wirft oder das Timeout reisst, macht das Ergebnis ``degraded`` --
    nie eine 500 (der Endpoint selbst darf nicht am Check sterben).
    """
    results: dict[str, str] = {}
    healthy = True
    for name, fn in _checks.items():
        try:
            await asyncio.wait_for(_invoke(fn), timeout=timeout)
            results[name] = "ok"
        except Exception as exc:  # noqa: BLE001 - jeder Check-Fehler = degraded
            healthy = False
            detail = str(exc) or exc.__class__.__name__
            results[name] = f"error: {detail[:200]}"
    return healthy, results


def sqlite_check(path: str, *, connect_timeout: float = 2.0) -> HealthCheck:
    """Baut einen Readiness-Check, der die SQLite-DB oeffnet und ``SELECT 1`` ausfuehrt.

    Faengt genau das ab, was der llm-gateway-Ausfall 2026-07 gezeigt hat: ein
    Dienst meldet "ok", obwohl seine DB unerreichbar ist. Ein kaputter Pfad,
    eine gesperrte oder korrupte Datei laesst den Check werfen -> 503.
    """

    def _check() -> None:
        conn = sqlite3.connect(path, timeout=connect_timeout)
        try:
            conn.execute("SELECT 1").fetchone()
        finally:
            conn.close()

    return _check

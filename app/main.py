"""brain-bus, MQTT → Rule-Engine → Suggestions + LLM-Reasoning."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Response

from app import confirmations, db, secrets_store, tool_runner
from app.config import settings
from app.llm_client import LLMClient, build_default_client
from app import events, health
from app.logging_config import configure_logging, get_logger
from app.mqtt import publisher
from app.mqtt_subscriber import subscriber
from app.notify import IrcClient, NotifyClient, NtfyClient
from app.pipeline import publish_suggestion, run_reasoning
from app.registry import get_service, load_registry
from app.rules import RuleEngine, load_rules

configure_logging()
log = get_logger(__name__)

RULES_PATH = Path("/app/config/rules.yaml")
TOOLS_PATH = Path("/app/config/tools.yaml")
DB_PATH = Path("/data/brain.db")
SECRETS_DIR = Path("/run/secrets")

_engine: RuleEngine | None = None
_llm: LLMClient | None = None
_notify: NotifyClient | None = None
_ntfy: NtfyClient | None = None
_irc: IrcClient | None = None
_reasoning_tasks: set[asyncio.Task[None]] = set()
_expire_task: asyncio.Task[None] | None = None


def get_engine() -> RuleEngine:
    if _engine is None:
        raise RuntimeError("rule engine not initialized")
    return _engine


def _spawn_reasoning(rule, fingerprint: str, trigger_event=None) -> None:
    if not settings.llm_enabled or _llm is None:
        return
    task = asyncio.create_task(
        run_reasoning(rule, fingerprint, _llm, _notify, _ntfy, _irc, trigger_event),
        name=f"reasoning-{rule.id}-{fingerprint}",
    )
    _reasoning_tasks.add(task)
    task.add_done_callback(_reasoning_tasks.discard)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _engine, _llm, _notify, _ntfy, _irc
    log.info("brain-bus.startup", version=settings.service_version)

    # Stufe 8a: DB + Secrets + Tool-Registry vor allem anderen.
    db.init(DB_PATH)
    secrets_store.init(SECRETS_DIR)
    tool_runner.load(TOOLS_PATH)

    rules = load_rules(RULES_PATH)
    _engine = RuleEngine(rules)

    if settings.llm_enabled:
        _llm = build_default_client(settings)
        log.info(
            "llm.configured",
            primary=settings.llm_gateway_url,
            fallback=settings.llm_fallback_url,
            wake=settings.llm_wake_url,
        )

    if settings.notify_enabled:
        _notify = NotifyClient(settings.notify_url, enabled=True)
        log.info("notify.configured", url=settings.notify_url)

    if settings.ntfy_url:
        _ntfy = NtfyClient(
            settings.ntfy_url,
            token_file=settings.ntfy_token_file,
            default_topic=settings.ntfy_default_topic,
        )
        log.info("ntfy.configured", url=settings.ntfy_url, default_topic=settings.ntfy_default_topic)

    if settings.irc_posten_url:
        _irc = IrcClient(
            settings.irc_posten_url,
            token_file=settings.irc_posten_token_file,
        )
        log.info("irc.configured", url=settings.irc_posten_url)

    async def handle_event(topic: str, payload: dict[str, Any], meta: dict[str, Any]) -> None:
        assert _engine is not None
        triggered = _engine.on_event(topic, payload, meta.get("retained", False))
        for rule in triggered:
            fingerprint = rule.fingerprint()
            log.info("rule.triggered", rule_id=rule.id, topic=topic, fingerprint=fingerprint)
            publish_suggestion(rule)
            # Das ausloesende Ereignis wandert als Wert mit in die Async-Task.
            # rule.trigger_event steht hier noch fest (die Schleife laeuft synchron
            # bis zum ersten await); in der Task waere es laengst ueberschrieben.
            _spawn_reasoning(rule, fingerprint, rule.trigger_event)
            asyncio.create_task(events.emit(
                event_type="alert.created",
                summary=f"{rule.id} on {topic}",
                external_id=f"brain-bus:{rule.id}:{fingerprint}",
                severity=getattr(rule, "severity", "info") or "info",
                entity_ref=topic,
                payload={"rule_id": rule.id, "topic": topic, "fingerprint": fingerprint, "event": payload},
            ))

    subscriber.on("homelab/#", include_retained=True)(handle_event)

    loop = asyncio.get_running_loop()
    try:
        publisher.connect()
    except Exception as exc:
        log.warning("publisher.connect_failed", error=str(exc))
    await subscriber.start(loop)

    # Stufe 8c: Background-Sweeper für expired confirmations.
    global _expire_task
    _expire_task = loop.create_task(
        confirmations.expire_loop(), name="confirmation-expire"
    )

    yield

    # Wait briefly for in-flight reasoning (best-effort).
    if _reasoning_tasks:
        await asyncio.wait(list(_reasoning_tasks), timeout=5)
    if _expire_task:
        _expire_task.cancel()
        try:
            await _expire_task
        except (asyncio.CancelledError, Exception):
            pass
    await subscriber.stop()
    publisher.disconnect()
    log.info("brain-bus.shutdown")


app = FastAPI(
    title="brain-bus",
    version=settings.service_version,
    openapi_url="/api/openapi.json",
    docs_url="/api/docs",
    redoc_url=None,
    lifespan=lifespan,
)


# Readiness-Check aus der env verdrahten: HEALTH_DB_PATH gesetzt -> DB-Probe.
if settings.health_db_path:
    health.register_check("db", health.sqlite_check(settings.health_db_path))


@app.get("/health")
async def health_endpoint(response: Response) -> dict:
    healthy, checks = await health.run_checks(timeout=settings.health_check_timeout)
    body = {
        "status": "ok" if healthy else "degraded",
        "service": "brain-bus",
        "version": settings.service_version,
        "time": datetime.now(timezone.utc).isoformat(),
        "llm_enabled": settings.llm_enabled,
        "reasoning_tasks": len(_reasoning_tasks),
    }
    if checks:
        body["checks"] = checks
    if not healthy:
        response.status_code = 503
    return body


@app.get("/api/rules")
async def list_rules() -> dict:
    engine = get_engine()
    return {"rules": engine.introspect()}


@app.get("/api/tools")
async def list_tools() -> dict:
    """Tool-Registry (Single-Source-of-Truth). HA-Component darf cachen."""
    import yaml as _yaml
    if not TOOLS_PATH.exists():
        return {"version": 0, "tools": []}
    data = _yaml.safe_load(TOOLS_PATH.read_text(encoding="utf-8")) or {}
    return {
        "version": data.get("version", 1),
        "tools": data.get("tools", []),
    }


# Backwards-kompatibler Alias auf /tools (für einfachere HTTP-Clients).
@app.get("/tools")
async def list_tools_alias() -> dict:
    return await list_tools()


@app.get("/api/registry/summary")
async def registry_summary() -> dict:
    registry = load_registry()
    return registry.summary()


@app.get("/api/registry/services/{service_id}")
async def registry_service(service_id: str) -> dict:
    service = get_service(service_id)
    if service is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="service not found")
    return service.as_dict()


@app.get("/api/actions")
async def list_actions(limit: int = 50) -> dict:
    """Audit-Trail: letzte N ausgeführte Actions."""
    return {"actions": db.list_actions(limit=min(max(limit, 1), 200))}


@app.get("/api/confirmations")
async def list_confirmations(status: str | None = None, limit: int = 50) -> dict:
    """Pending/historical Confirmation-Records."""
    return {"confirmations": db.list_confirmations(status=status, limit=min(max(limit, 1), 200))}


@app.post("/api/confirmations/{callback_id}/resolve")
async def resolve_confirmation(callback_id: str, body: dict) -> dict:
    """Wird vom host-junior Cog aufgerufen wenn User Approve/Deny klickt."""
    decision = str(body.get("decision", ""))
    user = str(body.get("user", "?"))
    secret = body.get("secret")
    result = await confirmations.resolve(
        callback_id, decision=decision, user=user, secret=secret
    )
    if not result.get("ok"):
        from fastapi import HTTPException
        raise HTTPException(
            status_code=int(result.get("http", 400)),
            detail=result.get("error", "resolve failed"),
        )
    return result


# Learner-Router (brain-bus Lernschleife)
from app.routes_learner import router as learner_router  # noqa: E402
app.include_router(learner_router)

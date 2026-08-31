"""
MQTT-Subscriber als Pendant zu mqtt.py (Publisher).

Benutzung:

    from app.mqtt_subscriber import subscriber

    @subscriber.on("homelab/+/+/failed")
    async def on_failure(topic: str, payload: dict, meta: dict) -> None:
        log.info("failure", topic=topic, payload=payload)

    # in lifespan:
    await subscriber.start(asyncio.get_running_loop())
    ...
    await subscriber.stop()

Konventionen:
- payload wird JSON-dekodiert; bei Parse-Fehler kommt raw bytes als
  {"_raw": <bytes>} ins Handler-Dict.
- retain=True Messages werden per Default gedroppt (Discovery-Flut).
  Pro Subscription mit include_retained=True überschreibbar.
- Handler sind async. Ausnahmen werden geloggt, schlucken den Event.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

import paho.mqtt.client as mqtt

from app.config import settings
from app.logging_config import get_logger

log = get_logger(__name__)

Handler = Callable[[str, dict[str, Any], dict[str, Any]], Awaitable[None]]


@dataclass(slots=True)
class _Subscription:
    pattern: str
    handler: Handler
    qos: int
    include_retained: bool


class MqttSubscriber:
    def __init__(self) -> None:
        self._client: mqtt.Client | None = None
        self._subs: list[_Subscription] = []
        self._queue: asyncio.Queue[tuple[str, bytes, bool]] | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._worker: asyncio.Task[None] | None = None

    def on(
        self,
        pattern: str,
        *,
        qos: int = 0,
        include_retained: bool = False,
    ) -> Callable[[Handler], Handler]:
        """Decorator: registriert async-Handler für MQTT-Pattern."""

        def decorator(handler: Handler) -> Handler:
            self._subs.append(
                _Subscription(
                    pattern=pattern,
                    handler=handler,
                    qos=qos,
                    include_retained=include_retained,
                )
            )
            return handler

        return decorator

    async def start(self, loop: asyncio.AbstractEventLoop) -> None:
        if self._client is not None:
            return
        self._loop = loop
        self._queue = asyncio.Queue(maxsize=1000)
        self._worker = loop.create_task(self._run_worker(), name="mqtt-subscriber")

        client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id=f"{settings.service_name}-subscriber",
        )
        if settings.mqtt_username:
            client.username_pw_set(settings.mqtt_username, settings.mqtt_password)

        client.on_connect = self._on_connect
        client.on_message = self._on_message
        client.on_disconnect = self._on_disconnect

        client.reconnect_delay_set(min_delay=1, max_delay=60)
        client.connect_async(settings.mqtt_host, settings.mqtt_port, keepalive=60)
        client.loop_start()
        self._client = client
        log.info(
            "mqtt.subscriber.started",
            host=settings.mqtt_host,
            port=settings.mqtt_port,
            subscriptions=len(self._subs),
        )

    async def stop(self) -> None:
        if self._client is not None:
            self._client.loop_stop()
            self._client.disconnect()
            self._client = None
        if self._worker is not None:
            self._worker.cancel()
            try:
                await self._worker
            except (asyncio.CancelledError, Exception):
                pass
            self._worker = None
        log.info("mqtt.subscriber.stopped")

    # paho callbacks (thread context; must be thread-safe) ------------

    def _on_connect(
        self, client: mqtt.Client, userdata: Any, flags: Any, reason_code: Any, properties: Any = None
    ) -> None:
        if reason_code != 0:
            log.warning("mqtt.subscriber.connect_failed", rc=str(reason_code))
            return
        seen: set[tuple[str, int]] = set()
        for sub in self._subs:
            key = (sub.pattern, sub.qos)
            if key in seen:
                continue
            seen.add(key)
            client.subscribe(sub.pattern, qos=sub.qos)
        log.info("mqtt.subscriber.subscribed", count=len(seen))

    def _on_disconnect(
        self, client: mqtt.Client, userdata: Any, *args: Any, **kwargs: Any
    ) -> None:
        log.info("mqtt.subscriber.disconnected")

    def _on_message(self, client: mqtt.Client, userdata: Any, msg: mqtt.MQTTMessage) -> None:
        if self._loop is None or self._queue is None:
            return
        try:
            self._loop.call_soon_threadsafe(
                self._enqueue, msg.topic, msg.payload, bool(msg.retain)
            )
        except RuntimeError:
            pass

    def _enqueue(self, topic: str, payload: bytes, retained: bool) -> None:
        assert self._queue is not None
        try:
            self._queue.put_nowait((topic, payload, retained))
        except asyncio.QueueFull:
            log.warning("mqtt.subscriber.queue_full", topic=topic)

    # async worker ---------------------------------------------------

    async def _run_worker(self) -> None:
        assert self._queue is not None
        while True:
            topic, payload_raw, retained = await self._queue.get()
            try:
                await self._dispatch(topic, payload_raw, retained)
            except Exception as exc:  # pragma: no cover
                log.exception("mqtt.subscriber.dispatch_error", error=str(exc))

    async def _dispatch(self, topic: str, payload_raw: bytes, retained: bool) -> None:
        payload: dict[str, Any]
        try:
            decoded = payload_raw.decode("utf-8")
            parsed = json.loads(decoded) if decoded else {}
            payload = parsed if isinstance(parsed, dict) else {"_value": parsed}
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = {"_raw": payload_raw}

        meta = {"retained": retained}
        for sub in self._subs:
            if retained and not sub.include_retained:
                continue
            if not mqtt.topic_matches_sub(sub.pattern, topic):
                continue
            try:
                await sub.handler(topic, payload, meta)
            except Exception as exc:
                log.exception(
                    "mqtt.subscriber.handler_error",
                    pattern=sub.pattern,
                    topic=topic,
                    error=str(exc),
                )


subscriber = MqttSubscriber()

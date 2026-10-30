import json
from contextlib import contextmanager
from typing import Any

import paho.mqtt.client as mqtt

from app.config import settings
from app.logging_config import get_logger

log = get_logger(__name__)


TOPIC_PREFIX = "homelab"


def topic(entity: str, action: str) -> str:
    """
    Einheitliches Topic-Schema:

        homelab/{service}/{entity}/{action}

    Beispiele:
        homelab/lager/item/added
        homelab/fitness/workout/completed
        homelab/mealprep/plan/generated
    """
    return f"{TOPIC_PREFIX}/{settings.service_name}/{entity}/{action}"


class MqttPublisher:
    def __init__(self) -> None:
        self._client: mqtt.Client | None = None

    def connect(self) -> None:
        if self._client is not None:
            return
        client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id=f"{settings.service_name}-publisher",
        )
        if settings.mqtt_username:
            client.username_pw_set(settings.mqtt_username, settings.mqtt_password)
        client.connect(settings.mqtt_host, settings.mqtt_port, keepalive=60)
        client.loop_start()
        self._client = client
        log.info("mqtt.connected", host=settings.mqtt_host, port=settings.mqtt_port)

    def disconnect(self) -> None:
        if self._client is None:
            return
        self._client.loop_stop()
        self._client.disconnect()
        self._client = None

    def publish(
        self,
        entity: str,
        action: str,
        payload: dict[str, Any],
        *,
        retain: bool = False,
        qos: int = 0,
    ) -> None:
        if self._client is None:
            self.connect()
        assert self._client is not None
        t = topic(entity, action)
        body = json.dumps(payload, default=str)
        result = self._client.publish(t, body, qos=qos, retain=retain)
        log.debug("mqtt.publish", topic=t, rc=result.rc, retain=retain)


publisher = MqttPublisher()


@contextmanager
def mqtt_lifespan():
    publisher.connect()
    try:
        yield publisher
    finally:
        publisher.disconnect()

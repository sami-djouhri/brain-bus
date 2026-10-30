from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    service_name: str = "brain-bus"
    service_version: str = "0.1.0"
    env: str = "dev"

    mqtt_host: str = "mosquitto"
    mqtt_port: int = 1883
    mqtt_username: str | None = None
    mqtt_password: str | None = None
    mqtt_password_file: str | None = None

    auth_required: bool = False
    auth_header_user: str = "Remote-User"
    auth_header_groups: str = "Remote-Groups"
    auth_trusted_proxies: list[str] = ["127.0.0.1", "10.210.0.0/16", "172.16.0.0/12"]

    ha_discovery_prefix: str = "homeassistant"
    log_level: str = "INFO"

    # Optionaler Readiness-Check: ist HEALTH_DB_PATH gesetzt, prueft /health per
    # SQLite-Probe (SELECT 1), ob die DB erreichbar ist, sonst 503. Leer = Liveness.
    health_db_path: str | None = None
    health_check_timeout: float = 5.0

    # LLM-Enrichment (Stufe 5)
    llm_enabled: bool = True
    llm_gateway_url: str = "http://192.0.2.10:8081/v1"
    llm_gateway_model: str = "qwen-2.5-7b"
    llm_gateway_token: str | None = None
    llm_gateway_token_file: str | None = None
    llm_direct_url: str | None = "http://192.0.2.10:8080/v1"
    llm_direct_model: str | None = "qwen-2.5-7b"
    llm_fallback_url: str | None = "http://192.0.2.10:8081/v1"
    llm_fallback_model: str | None = "gemma-3-4b"
    llm_wake_url: str | None = "http://192.0.2.10:9090/wake"

    # Notifications (Stufe 7)
    notify_enabled: bool = True
    notify_url: str = "http://host-junior:8765"
    # ntfy-Parallel-Kanal: high/critical geht zusaetzlich an ntfy (Discord bleibt
    # der Hauptweg, keiner blockiert den anderen). Leerer ntfy_url = deaktiviert.
    ntfy_url: str | None = None
    ntfy_token_file: str | None = "/run/secrets/ntfy_token"
    ntfy_default_topic: str = "host-critical"

    # Dritter Weg: der interne IRC-Server (irc-posten auf node1). Leere URL =
    # abgeschaltet. Bekommt bewusst ALLE Meldungen, nicht nur die lauten.
    irc_posten_url: str | None = None
    irc_posten_token_file: str | None = "/run/secrets/irc_posten_token"
    registry_path: str = "/app/shared/platform-registry.json"

    # Event Spine (life-ops-api). Leer = Event-Producer deaktiviert.
    life_ops_api_url: str | None = None

    def model_post_init(self, __context) -> None:
        if not self.mqtt_password and self.mqtt_password_file:
            path = Path(self.mqtt_password_file)
            if path.exists():
                self.mqtt_password = path.read_text(encoding="utf-8").strip()


settings = Settings()

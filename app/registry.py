"""Registry helpers for service and host context enrichment."""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.config import settings


@dataclass(slots=True)
class ServiceContext:
    id: str
    title: str
    group: str
    current_host: str
    target_host: str
    state: str
    criticality: str
    capabilities: list[str]
    value: list[str]
    next_stage: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ServiceContext":
        return cls(
            id=str(data.get("id", "")),
            title=str(data.get("title", "")),
            group=str(data.get("group", "unknown")),
            current_host=str(data.get("current_host", "unknown")),
            target_host=str(data.get("target_host", "unknown")),
            state=str(data.get("state", "unknown")),
            criticality=str(data.get("criticality", "unknown")),
            capabilities=[str(item) for item in data.get("capabilities", [])],
            value=[str(item) for item in data.get("value", [])],
            next_stage=str(data.get("next_stage", "")),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "group": self.group,
            "current_host": self.current_host,
            "target_host": self.target_host,
            "state": self.state,
            "criticality": self.criticality,
            "capabilities": self.capabilities,
            "value": self.value,
            "next_stage": self.next_stage,
        }


@dataclass(slots=True)
class RegistryData:
    updated_at: str
    hosts: list[dict[str, Any]]
    services: list[ServiceContext]

    def summary(self) -> dict[str, Any]:
        return {
            "updated_at": self.updated_at,
            "host_count": len(self.hosts),
            "service_count": len(self.services),
            "critical_services": sum(1 for service in self.services if service.criticality == "high"),
        }


@lru_cache(maxsize=1)
def load_registry() -> RegistryData:
    path = Path(settings.registry_path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    return RegistryData(
        updated_at=str(raw.get("updated_at", "")),
        hosts=list(raw.get("hosts", [])),
        services=[ServiceContext.from_dict(service) for service in raw.get("services", [])],
    )


def reload_registry() -> RegistryData:
    load_registry.cache_clear()
    return load_registry()


def get_service(service_id: str) -> ServiceContext | None:
    service_id = service_id.strip()
    if not service_id:
        return None
    registry = load_registry()
    for service in registry.services:
        if service.id == service_id:
            return service
    return None


def extract_service_ids(topic: str, payload: dict[str, Any]) -> list[str]:
    candidates: list[str] = []
    parts = topic.split("/")
    if len(parts) >= 2 and parts[0] == "homelab":
        candidates.append(parts[1])

    for key in ("service", "service_id", "service_name"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            candidates.append(value)

    affected = payload.get("affected_services")
    if isinstance(affected, list):
        for item in affected:
            if isinstance(item, str) and item:
                candidates.append(item)

    seen: set[str] = set()
    deduped: list[str] = []
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        deduped.append(candidate)
    return deduped


def resolve_services(topic: str, payload: dict[str, Any]) -> list[ServiceContext]:
    contexts: list[ServiceContext] = []
    for service_id in extract_service_ids(topic, payload):
        service = get_service(service_id)
        if service is not None:
            contexts.append(service)
    return contexts

"""
Tool-Runner: lädt Tool-Definition aus tools.yaml, validiert+coercet args,
templatet `{{ event.payload.X }}` Werte, ruft HTTP-Endpoint mit optionalem
Bearer-Token. Plain stdlib + httpx.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import yaml

from app import secrets_store
from app.logging_config import get_logger

log = get_logger(__name__)


_PATH_FORBIDDEN_CHARS = frozenset("/\\\x00\r\n\t ")
_PATH_MAX_LEN = 128


_PLACEHOLDER_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_.\[\]]+)\s*\}\}")


@dataclass(slots=True)
class ToolSpec:
    name: str
    description: str
    risk: str
    endpoint: str
    method: str
    args_schema: dict[str, dict[str, Any]]
    auth: dict[str, Any] | None  # {type: "bearer", secret: "ha_token"}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ToolSpec":
        return cls(
            name=d["name"],
            description=d.get("description", ""),
            risk=str(d.get("risk", "low")).lower(),
            endpoint=d["endpoint"],
            method=str(d.get("method", "GET")).upper(),
            args_schema=d.get("args") or {},
            auth=d.get("auth"),
        )


_tools: dict[str, ToolSpec] = {}


def load(path: Path) -> None:
    """Lädt tools.yaml in Memory. Aufruf einmalig beim startup."""
    global _tools
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    out: dict[str, ToolSpec] = {}
    for raw in data.get("tools", []) or []:
        spec = ToolSpec.from_dict(raw)
        out[spec.name] = spec
    _tools = out
    log.info("tools.loaded", count=len(_tools), names=list(_tools.keys()))


def get(name: str) -> ToolSpec | None:
    return _tools.get(name)


def all_tools() -> dict[str, ToolSpec]:
    return dict(_tools)


# --- Templating ---

def _resolve_path(context: dict[str, Any], dotted: str) -> Any:
    """`event.payload.service_id` → walk dict via dot-path. Returns None on miss."""
    cur: Any = context
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _render(value: Any, context: dict[str, Any]) -> Any:
    """Ersetzt {{ path.to.value }} in Strings; non-string passthrough."""
    if not isinstance(value, str):
        return value
    if "{{" not in value:
        return value
    def replace(m: re.Match[str]) -> str:
        resolved = _resolve_path(context, m.group(1))
        return "" if resolved is None else str(resolved)
    return _PLACEHOLDER_RE.sub(replace, value)


def render_args(args: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    return {k: _render(v, context) for k, v in args.items()}


# --- Validation + Coercion ---

class ArgError(Exception):
    pass


def _validate_path_value(name: str, value: Any) -> str:
    """Strikt für `in: path` args — keine traversal, keine schräge Whitespace,
    keine null-bytes. Returns URL-encoded string ready für Pfad-Replace.
    """
    s = "" if value is None else str(value)
    if not s:
        raise ArgError(f"path arg {name!r}: empty")
    if len(s) > _PATH_MAX_LEN:
        raise ArgError(f"path arg {name!r}: too long ({len(s)} > {_PATH_MAX_LEN})")
    if ".." in s:
        raise ArgError(f"path arg {name!r}: contains '..'")
    bad = [c for c in s if c in _PATH_FORBIDDEN_CHARS]
    if bad:
        raise ArgError(f"path arg {name!r}: forbidden chars {bad!r}")
    return urllib.parse.quote(s, safe="")


def _coerce(value: Any, expected: str) -> Any:
    if value is None:
        return None
    if expected == "string":
        return str(value)
    if expected == "integer":
        return int(value)
    if expected == "boolean":
        if isinstance(value, bool):
            return value
        return str(value).lower() in {"1", "true", "yes", "on"}
    if expected == "datetime":
        return str(value)  # passthrough — ISO assumed
    return value


def validate_and_coerce(spec: ToolSpec, args: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, schema in spec.args_schema.items():
        required = bool(schema.get("required", False))
        if name not in args or args.get(name) in (None, ""):
            if required and "default" not in schema:
                raise ArgError(f"missing required arg: {name}")
            if "default" in schema:
                out[name] = schema["default"]
            continue
        try:
            out[name] = _coerce(args[name], str(schema.get("type", "string")))
        except (ValueError, TypeError) as e:
            raise ArgError(f"arg {name}: type-coerce failed ({schema.get('type')}): {e}")
    return out


# --- Execution ---

def _split_args(spec: ToolSpec, args: dict[str, Any]) -> tuple[str, dict[str, Any], dict[str, Any], Any]:
    """Returns (rendered_url, query_params, body_dict, headers_extra).

    Argument-Placement-Konvention: schema entry 'in' ∈ {path, query, body}.
    Default: path-Tokens werden ersetzt, Rest geht in body (für POST) oder query (für GET).
    """
    url = spec.endpoint
    query: dict[str, Any] = {}
    body: dict[str, Any] = {}
    for name, value in args.items():
        in_loc = (spec.args_schema.get(name) or {}).get("in")
        token = "{" + name + "}"
        if in_loc == "path" or token in url:
            safe = _validate_path_value(name, value)
            url = url.replace(token, safe)
            continue
        if in_loc == "body":
            body[name] = value
            continue
        if in_loc == "query":
            query[name] = value
            continue
        # Fallback: GET → query, POST/PUT → body
        if spec.method == "GET":
            query[name] = value
        else:
            body[name] = value
    return url, query, body, {}


async def run(
    spec: ToolSpec,
    args: dict[str, Any],
    *,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Führt Tool-Call aus. Returns {status, http_status, response_excerpt, elapsed_ms, body}."""
    import time as _time

    headers: dict[str, str] = {"Accept": "application/json"}
    if spec.auth and spec.auth.get("type") == "bearer":
        secret_name = spec.auth.get("secret")
        token = secrets_store.get(secret_name) if secret_name else None
        if token:
            headers["Authorization"] = f"Bearer {token}"
    if spec.auth and spec.auth.get("type") == "apikey":
        secret_name = spec.auth.get("secret")
        key = secrets_store.get(secret_name) if secret_name else None
        header_name = spec.auth.get("header", "X-API-Key")
        if key:
            headers[header_name] = key

    url, query, body, _ = _split_args(spec, args)

    t0 = _time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout, connect=5.0)) as client:
            if spec.method == "GET":
                resp = await client.get(url, params=query, headers=headers)
            else:
                resp = await client.request(
                    spec.method, url, params=query, json=body or None, headers=headers
                )
        elapsed_ms = int((_time.perf_counter() - t0) * 1000)
        text_excerpt = (resp.text or "")[:500]
        try:
            body_parsed: Any = resp.json()
        except Exception:
            body_parsed = None
        status = "success" if 200 <= resp.status_code < 300 else "failure"
        log.info(
            "tool.executed",
            tool=spec.name,
            status=status,
            http_status=resp.status_code,
            elapsed_ms=elapsed_ms,
        )
        return {
            "status": status,
            "http_status": resp.status_code,
            "response_excerpt": text_excerpt,
            "elapsed_ms": elapsed_ms,
            "body": body_parsed,
        }
    except httpx.TimeoutException:
        elapsed_ms = int((_time.perf_counter() - t0) * 1000)
        log.warning("tool.timeout", tool=spec.name, elapsed_ms=elapsed_ms)
        return {
            "status": "timeout",
            "http_status": None,
            "response_excerpt": "",
            "elapsed_ms": elapsed_ms,
            "body": None,
        }
    except Exception as exc:
        elapsed_ms = int((_time.perf_counter() - t0) * 1000)
        log.warning("tool.error", tool=spec.name, error=str(exc), elapsed_ms=elapsed_ms)
        return {
            "status": "failure",
            "http_status": None,
            "response_excerpt": str(exc)[:500],
            "elapsed_ms": elapsed_ms,
            "body": None,
        }

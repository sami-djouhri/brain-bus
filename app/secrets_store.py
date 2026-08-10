"""Lädt benannte Secret-Files aus /run/secrets/ — typisiert."""

from __future__ import annotations

from pathlib import Path

from app.logging_config import get_logger

log = get_logger(__name__)


_secrets: dict[str, str] = {}
_default_dir = Path("/run/secrets")


def init(dir_path: Path | None = None) -> None:
    """Lädt alle Files aus dem Secrets-Dir in den In-Memory-Cache."""
    global _secrets
    base = dir_path or _default_dir
    if not base.exists():
        log.warning("secrets.dir_missing", path=str(base))
        return
    loaded: dict[str, str] = {}
    for f in base.iterdir():
        if f.is_file() and not f.name.startswith("."):
            try:
                loaded[f.name] = f.read_text(encoding="utf-8").strip()
            except Exception as exc:
                log.warning("secrets.read_failed", file=f.name, error=str(exc))
    _secrets = loaded
    log.info("secrets.loaded", count=len(_secrets), names=list(_secrets.keys()))


def get(name: str) -> str | None:
    return _secrets.get(name)


def require(name: str) -> str:
    val = _secrets.get(name)
    if not val:
        raise RuntimeError(f"required secret not found: {name}")
    return val

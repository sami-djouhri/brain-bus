"""
LLM-Client für brain-bus.

Reasoning-Pfad:
  primary gateway → direct remote LLM → local fallback.

Gateway-Call kann lange dauern (Qwen ~0.5 tok/s), daher großzügige Timeouts.
Nur im Async-Background verwendet, blockiert keinen Voice-Pfad.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

from app.logging_config import get_logger

log = get_logger(__name__)


class LLMClient:
    def __init__(
        self,
        *,
        primary_url: str,
        primary_token: str | None,
        primary_model: str,
        direct_url: str | None,
        direct_model: str | None,
        fallback_url: str | None,
        fallback_model: str | None,
        wake_url: str | None = None,
    ) -> None:
        self.primary_url = primary_url.rstrip("/")
        self.primary_token = primary_token
        self.primary_model = primary_model
        self.direct_url = direct_url.rstrip("/") if direct_url else None
        self.direct_model = direct_model
        self.fallback_url = fallback_url.rstrip("/") if fallback_url else None
        self.fallback_model = fallback_model
        self.wake_url = wake_url

    async def reason(
        self,
        system: str,
        user: str,
        *,
        max_tokens: int = 220,
        primary_timeout: float = 20.0,
        direct_timeout: float = 20.0,
        fallback_timeout: float = 40.0,
    ) -> dict[str, Any]:
        """Try the configured primary reasoning node first.

        The local model is a resilience fallback; using it first hides remote
        AI-node failures and makes the dedicated inference host irrelevant.
        """
        result = await self._try_primary(system, user, max_tokens, primary_timeout)
        if result is not None:
            return result

        result = await self._try_direct(system, user, max_tokens, direct_timeout) if self.direct_url else None
        if result is not None:
            return result

        if self.wake_url:
            await self._try_wake()
            result = await self._try_primary(system, user, max_tokens, primary_timeout)
            if result is not None:
                return result

        if self.fallback_url:
            result = await self._try_fallback(system, user, max_tokens, fallback_timeout)
            if result.get("text"):
                return result

        return {"text": None, "source": "none", "elapsed_ms": 0}

    async def _try_primary(
        self, system: str, user: str, max_tokens: int, timeout: float
    ) -> dict[str, Any] | None:
        try:
            return await self._call(
                f"{self.primary_url}/chat/completions",
                system,
                user,
                max_tokens,
                timeout,
                model=self.primary_model,
                token=self.primary_token,
                source="gateway",
            )
        except Exception as exc:
            log.warning("llm.primary_failed", url=self.primary_url, error=str(exc))
            return None

    async def _try_direct(
        self, system: str, user: str, max_tokens: int, timeout: float
    ) -> dict[str, Any] | None:
        assert self.direct_url is not None
        try:
            return await self._call(
                f"{self.direct_url}/chat/completions",
                system,
                user,
                max_tokens,
                timeout,
                model=self.direct_model or self.primary_model,
                token=None,
                source="direct",
            )
        except Exception as exc:
            log.warning("llm.direct_failed", url=self.direct_url, error=str(exc))
            return None

    async def _try_fallback(
        self, system: str, user: str, max_tokens: int, timeout: float
    ) -> dict[str, Any]:
        assert self.fallback_url is not None
        try:
            return await self._call(
                f"{self.fallback_url}/chat/completions",
                system,
                user,
                max_tokens,
                timeout,
                model=self.fallback_model or self.primary_model,
                token=None,
                source="fallback",
            )
        except Exception as exc:
            log.warning("llm.fallback_failed", url=self.fallback_url, error=str(exc))
            return {"text": None, "source": "fallback-error", "elapsed_ms": 0}

    async def _try_wake(self) -> None:
        assert self.wake_url is not None
        import asyncio as _asyncio
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(5.0, connect=2.0)) as c:
                resp = await c.get(self.wake_url)
                log.info("llm.wake", url=self.wake_url, status=resp.status_code)
        except Exception as exc:
            log.info("llm.wake_failed", url=self.wake_url, error=str(exc))
            return
        # Unpause ist instant, aber llama.cpp braucht ein paar Sekunden
        # bis es wieder zuverlässig Requests annimmt. Kurzer Warmup-Sleep.
        await _asyncio.sleep(4)

    async def _call(
        self,
        url: str,
        system: str,
        user: str,
        max_tokens: int,
        timeout: float,
        *,
        model: str,
        token: str | None,
        source: str,
    ) -> dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        body = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": max_tokens,
            "temperature": 0.2,
            "stream": False,
        }
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout + 5, connect=5.0, read=timeout)
        ) as client:
            import time as _time

            t0 = _time.perf_counter()
            resp = await client.post(url, headers=headers, json=body)
            elapsed_ms = int((_time.perf_counter() - t0) * 1000)
            resp.raise_for_status()
            data = resp.json()

        text = (
            data.get("choices", [{}])[0].get("message", {}).get("content") or ""
        ).strip()
        log.info("llm.answered", source=source, elapsed_ms=elapsed_ms, chars=len(text))
        return {"text": text, "source": source, "elapsed_ms": elapsed_ms}


def _read_secret(path: str | None) -> str | None:
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        return None
    return p.read_text(encoding="utf-8").strip()


def build_default_client(settings: Any) -> LLMClient:
    token = settings.llm_gateway_token or _read_secret(settings.llm_gateway_token_file)
    return LLMClient(
        primary_url=settings.llm_gateway_url,
        primary_token=token,
        primary_model=settings.llm_gateway_model,
        direct_url=settings.llm_direct_url,
        direct_model=settings.llm_direct_model,
        fallback_url=settings.llm_fallback_url,
        fallback_model=settings.llm_fallback_model,
        wake_url=settings.llm_wake_url,
    )

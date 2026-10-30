import asyncio
import unittest

from app.llm_client import LLMClient


class LLMClientTests(unittest.TestCase):
    def test_reason_prefers_primary_before_fallback(self):
        calls = []

        async def fake_call(self, url, system, user, max_tokens, timeout, *, model, token, source):
            calls.append(source)
            return {"text": f"{source}-ok", "source": source, "elapsed_ms": 1}

        original_call = LLMClient._call
        LLMClient._call = fake_call
        try:
            client = LLMClient(
                primary_url="http://primary/v1",
                primary_token=None,
                primary_model="primary-model",
                direct_url="http://direct/v1",
                direct_model="direct-model",
                fallback_url="http://fallback/v1",
                fallback_model="fallback-model",
            )

            result = asyncio.run(client.reason("system", "user"))
        finally:
            LLMClient._call = original_call

        self.assertEqual(result["source"], "gateway")
        self.assertEqual(calls, ["gateway"])

    def test_reason_uses_fallback_after_primary_and_direct_fail(self):
        calls = []

        async def fake_call(self, url, system, user, max_tokens, timeout, *, model, token, source):
            calls.append(source)
            if source in {"gateway", "direct"}:
                raise RuntimeError(f"{source} unavailable")
            return {"text": "fallback-ok", "source": source, "elapsed_ms": 1}

        original_call = LLMClient._call
        LLMClient._call = fake_call
        try:
            client = LLMClient(
                primary_url="http://primary/v1",
                primary_token=None,
                primary_model="primary-model",
                direct_url="http://direct/v1",
                direct_model="direct-model",
                fallback_url="http://fallback/v1",
                fallback_model="fallback-model",
            )

            result = asyncio.run(client.reason("system", "user"))
        finally:
            LLMClient._call = original_call

        self.assertEqual(result["source"], "fallback")
        self.assertEqual(calls, ["gateway", "direct", "fallback"])

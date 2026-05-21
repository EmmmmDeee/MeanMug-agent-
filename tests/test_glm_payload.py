from __future__ import annotations

import asyncio
import os

os.environ.setdefault("DISCORD_TOKEN", "x")
os.environ.setdefault("GLM_API_KEY", "x")

from meanmug.core.config import Config
from meanmug.services.glm import GlmClient


class _FakeResponse:
    status = 200

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    async def json(self):
        return {
            "choices": [
                {"message": {"content": "ok", "reasoning_content": "thought trace"}}
            ]
        }

    async def text(self):
        return ""


class _FakeSession:
    def __init__(self):
        self.last_url = None
        self.last_payload = None
        self.last_headers = None

    def post(self, url, json, headers, timeout):
        self.last_url = url
        self.last_payload = json
        self.last_headers = headers
        return _FakeResponse()


def test_payload_shape_with_enrichment():
    cfg = Config.from_env()
    fake = _FakeSession()
    client = GlmClient(fake, cfg.glm)
    enrichment = {"ips": {"8.8.8.8": {"geo": {"asn": "AS15169"}}}}
    asyncio.run(
        client.analyze_osint(
            "check 8.8.8.8",
            {"ips": ["8.8.8.8"], "domains": [], "emails": [], "handles": ["alice"]},
            enrichment=enrichment,
        )
    )
    assert fake.last_url.endswith("/chat/completions")
    assert fake.last_payload["model"] == cfg.glm.model
    if cfg.glm.thinking:
        assert fake.last_payload["thinking"] == {"type": "enabled"}
    user_block = fake.last_payload["messages"][1]["content"]
    assert "Pre-extracted indicators" in user_block
    assert "Handles: alice" in user_block
    assert "Live enrichment" in user_block
    assert "AS15169" in user_block
    assert fake.last_headers["Authorization"].startswith("Bearer ")


def test_pivot_prepends_focus():
    cfg = Config.from_env()
    fake = _FakeSession()
    client = GlmClient(fake, cfg.glm)
    asyncio.run(
        client.analyze_pivot(
            "evil.io",
            {"ips": [], "domains": ["evil.io"], "emails": [], "handles": []},
        )
    )
    user_block = fake.last_payload["messages"][1]["content"]
    assert user_block.startswith("PIVOT FOCUS")
    assert "`evil.io`" in user_block

from __future__ import annotations

import asyncio
import os

os.environ.setdefault("DISCORD_TOKEN", "x")
os.environ.setdefault("GLM_API_KEY", "x")

import pytest

from meanmug.config import Config
from meanmug.glm import GlmClient, GlmError


class _Resp:
    def __init__(self, status: int, body: str = "", json_data=None):
        self.status = status
        self._body = body
        self._json = json_data

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    async def text(self):
        return self._body

    async def json(self):
        return self._json


class _Session:
    def __init__(self, resp):
        self._resp = resp

    def post(self, *a, **kw):
        return self._resp


def _client(resp):
    cfg = Config.from_env()
    return GlmClient(_Session(resp), cfg.glm)


def test_http_4xx_raises_glm_error():
    client = _client(_Resp(401, body="invalid api key"))
    with pytest.raises(GlmError, match="HTTP 401"):
        asyncio.run(
            client.analyze_osint(
                "hi", {"ips": [], "domains": [], "emails": [], "handles": []}
            )
        )


def test_malformed_response_raises_glm_error():
    client = _client(_Resp(200, json_data={"unexpected": "shape"}))
    with pytest.raises(GlmError, match="malformed"):
        asyncio.run(
            client.analyze_osint(
                "hi", {"ips": [], "domains": [], "emails": [], "handles": []}
            )
        )


def test_empty_content_raises_glm_error():
    client = _client(
        _Resp(200, json_data={"choices": [{"message": {"content": "   "}}]})
    )
    with pytest.raises(GlmError, match="empty"):
        asyncio.run(
            client.analyze_osint(
                "hi", {"ips": [], "domains": [], "emails": [], "handles": []}
            )
        )

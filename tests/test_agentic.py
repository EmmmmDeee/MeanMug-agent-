"""Tests for the GLM-5.1 agentic loop."""
from __future__ import annotations

import asyncio
import json
import os

os.environ.setdefault("DISCORD_TOKEN", "x")
os.environ.setdefault("GLM_API_KEY", "x")

import pytest

from meanmug.core.config import Config
from meanmug.services.glm import AgenticResult, GlmClient, GlmError
from meanmug.services.tools import DISPATCH, TOOL_SCHEMAS, execute_tool_call


# ----------------------------- fake aiohttp + scripted GLM ---------------


class _Resp:
    def __init__(self, payload: dict, status: int = 200):
        self._payload = payload
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    async def json(self):
        return self._payload

    async def text(self):
        return json.dumps(self._payload)


class _ScriptedSession:
    """Returns canned GLM responses in order; records each POST payload."""

    def __init__(self, scripted: list[dict]):
        self._scripted = list(scripted)
        self.requests: list[dict] = []

    def post(self, url, json=None, headers=None, timeout=None):
        self.requests.append(json or {})
        if not self._scripted:
            raise AssertionError("scripted GLM exhausted; bot called GLM more than expected")
        return _Resp(self._scripted.pop(0))


def _assistant_tool_call(name: str, args: dict, call_id: str = "c1") -> dict:
    return {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": call_id,
                            "type": "function",
                            "function": {"name": name, "arguments": json.dumps(args)},
                        }
                    ],
                }
            }
        ]
    }


def _assistant_final(content: str) -> dict:
    return {"choices": [{"message": {"role": "assistant", "content": content}}]}


# ----------------------------- tool catalog ------------------------------


def test_tool_schemas_have_required_shape():
    for schema in TOOL_SCHEMAS:
        assert schema["type"] == "function"
        fn = schema["function"]
        assert fn["name"] in DISPATCH, f"schema for {fn['name']} has no dispatcher"
        assert "parameters" in fn
        assert fn["parameters"]["type"] == "object"


def test_every_dispatcher_has_a_schema():
    schema_names = {s["function"]["name"] for s in TOOL_SCHEMAS}
    assert schema_names == set(DISPATCH.keys())


def test_execute_unknown_tool_returns_error():
    async def go():
        return await execute_tool_call(None, "no_such_tool", "{}")
    out = asyncio.run(go())
    assert "error" in out and "unknown tool" in out["error"]


def test_execute_invalid_json_args_returns_error():
    async def go():
        return await execute_tool_call(None, "dns_lookup", "{not json")
    out = asyncio.run(go())
    assert "error" in out and "not valid JSON" in out["error"]


# ----------------------------- agentic loop ------------------------------


def test_agentic_loop_executes_one_tool_then_finalizes():
    """GLM asks for github_user, we execute, GLM emits the final report."""
    cfg = Config.from_env()

    # First GLM turn: tool_call for github_user(alice)
    turn1 = _assistant_tool_call("github_user", {"username": "alice"})
    # Second GLM turn: final answer
    turn2 = _assistant_final("**Classification** — Handle\n**Threat Level** — LOW")
    session = _ScriptedSession([turn1, turn2])
    client = GlmClient(session, cfg.glm)

    # Patch the tool dispatcher to avoid hitting the network.
    async def fake_github(session, username):
        return {"login": username, "name": "Alice"}

    from meanmug.services import tools
    original = tools.DISPATCH["github_user"]
    tools.DISPATCH["github_user"] = fake_github
    try:
        result = asyncio.run(client.chat_with_tools("Investigate @alice"))
    finally:
        tools.DISPATCH["github_user"] = original

    assert isinstance(result, AgenticResult)
    assert result.turns == 2
    assert len(result.tool_calls) == 1
    tc = result.tool_calls[0]
    assert tc.name == "github_user"
    assert tc.arguments == {"username": "alice"}
    assert tc.result["login"] == "alice"
    assert "Classification" in result.content
    assert result.hit_turn_cap is False

    # The second request must include the tool result in the message history.
    second_req = session.requests[1]
    role_sequence = [m["role"] for m in second_req["messages"]]
    assert role_sequence == ["system", "user", "assistant", "tool"]


def test_agentic_loop_hits_turn_cap_and_forces_final():
    cfg = Config.from_env()
    # GLM keeps asking for tool calls forever
    forever_tool = _assistant_tool_call("github_user", {"username": "alice"})
    final = _assistant_final("**Classification** — Forced")
    scripted = [dict(forever_tool) for _ in range(3)] + [final]
    session = _ScriptedSession(scripted)
    client = GlmClient(session, cfg.glm)

    async def fake_github(session, username):
        return {"login": username}

    from meanmug.services import tools
    original = tools.DISPATCH["github_user"]
    tools.DISPATCH["github_user"] = fake_github
    try:
        result = asyncio.run(client.chat_with_tools("loop", max_turns=3))
    finally:
        tools.DISPATCH["github_user"] = original

    assert result.hit_turn_cap is True
    assert result.turns == 4  # 3 looping turns + 1 forced final
    assert len(result.tool_calls) == 3
    # Final request must NOT include a tools array (forced no-tools turn).
    final_req = session.requests[-1]
    assert "tools" not in final_req


def test_agentic_loop_recovers_from_tool_failure():
    cfg = Config.from_env()
    turn1 = _assistant_tool_call("github_user", {"username": "alice"})
    turn2 = _assistant_final("**Classification** — Recovered")
    session = _ScriptedSession([turn1, turn2])
    client = GlmClient(session, cfg.glm)

    async def explode(session, username):
        raise RuntimeError("github is down")

    from meanmug.services import tools
    original = tools.DISPATCH["github_user"]
    tools.DISPATCH["github_user"] = explode
    try:
        result = asyncio.run(client.chat_with_tools("investigate @alice"))
    finally:
        tools.DISPATCH["github_user"] = original

    assert "Recovered" in result.content
    # Tool result should be an error dict
    assert "error" in result.tool_calls[0].result


def test_agentic_loop_empty_response_raises():
    cfg = Config.from_env()
    empty = _assistant_final("   ")  # whitespace-only
    session = _ScriptedSession([empty])
    client = GlmClient(session, cfg.glm)
    with pytest.raises(GlmError, match="no content"):
        asyncio.run(client.chat_with_tools("anything"))


def test_agentic_loop_includes_tools_in_first_request():
    cfg = Config.from_env()
    session = _ScriptedSession([_assistant_final("done")])
    client = GlmClient(session, cfg.glm)
    asyncio.run(client.chat_with_tools("just answer"))
    first = session.requests[0]
    assert first.get("tool_choice") == "auto"
    assert isinstance(first.get("tools"), list)
    assert len(first["tools"]) == len(TOOL_SCHEMAS)

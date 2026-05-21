from __future__ import annotations

import asyncio
import os

os.environ.setdefault("DISCORD_TOKEN", "x")
os.environ.setdefault("GLM_API_KEY", "x")

import pytest

from meanmug.core.config import Config
from meanmug.services.discord_io import chunk_text, color_for_analysis
from meanmug.services.glm import (
    GlmClient,
    GlmResult,
    _DIRECTIVE_BEGIN,
    _DIRECTIVE_END,
    _extract_directive,
    load_system_prompt,
)
from meanmug.services.storage import open_db, record_audit, token_usage_since


# ----------------------------- directive extraction ----------------------


def test_extract_directive_picks_marked_region():
    text = (
        "# header\n\nhuman context\n"
        f"{_DIRECTIVE_BEGIN}\nmodel-facing only\n{_DIRECTIVE_END}\n"
        "# more human context after\n"
    )
    out = _extract_directive(text)
    assert out == "model-facing only"


def test_extract_directive_falls_back_to_whole_file():
    text = "no markers here at all\n"
    assert _extract_directive(text) == "no markers here at all"


def test_real_system_prompt_uses_markers():
    """Real SYSTEM_PROMPT.md must mark its directive."""
    prompt = load_system_prompt()
    # Loaded prompt must not include human-only sections
    assert "Operational Invariants" not in prompt
    assert "Exit codes" not in prompt
    # But must include the actual directive content
    assert "MeanMug-Agent" in prompt
    assert "Report discipline" in prompt
    # Reasonable size — under 4000 chars (agentic-mode section adds tool catalog).
    assert len(prompt) < 4000, f"directive is {len(prompt)} chars; trim further"


# ----------------------------- GlmClient cache ---------------------------


class _StubSession:
    def __init__(self):
        self.calls = 0

    def post(self, *args, **kwargs):
        self.calls += 1
        return _StubResp()


class _StubResp:
    status = 200

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    async def json(self):
        return {
            "choices": [{"message": {"content": "ok"}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
        }

    async def text(self):
        return ""


def test_cache_hit_on_identical_input():
    cfg = Config.from_env()
    session = _StubSession()
    client = GlmClient(session, cfg.glm)

    r1 = asyncio.run(
        client.analyze_osint(
            "8.8.8.8", {"ips": ["8.8.8.8"], "domains": [], "emails": [], "handles": []}
        )
    )
    r2 = asyncio.run(
        client.analyze_osint(
            "8.8.8.8", {"ips": ["8.8.8.8"], "domains": [], "emails": [], "handles": []}
        )
    )
    assert session.calls == 1, "second identical call should hit cache"
    assert r1.cached is False
    assert r2.cached is True
    assert r2.content == r1.content


def test_cache_miss_on_different_input():
    cfg = Config.from_env()
    session = _StubSession()
    client = GlmClient(session, cfg.glm)
    asyncio.run(
        client.analyze_osint(
            "8.8.8.8", {"ips": ["8.8.8.8"], "domains": [], "emails": [], "handles": []}
        )
    )
    asyncio.run(
        client.analyze_osint(
            "1.1.1.1", {"ips": ["1.1.1.1"], "domains": [], "emails": [], "handles": []}
        )
    )
    assert session.calls == 2


# ----------------------------- usage parsing ----------------------------


def test_usage_parsed_from_response():
    cfg = Config.from_env()
    session = _StubSession()
    client = GlmClient(session, cfg.glm)
    result = asyncio.run(
        client.analyze_osint(
            "x", {"ips": [], "domains": [], "emails": [], "handles": []}
        )
    )
    assert result.usage == (100, 50)


def test_usage_absent_when_response_lacks_it():
    class _NoUsageResp(_StubResp):
        async def json(self):
            return {"choices": [{"message": {"content": "ok"}}]}

    class _NoUsageSession:
        def post(self, *a, **kw):
            return _NoUsageResp()

    cfg = Config.from_env()
    client = GlmClient(_NoUsageSession(), cfg.glm)
    result = asyncio.run(
        client.analyze_osint("y", {"ips": [], "domains": [], "emails": [], "handles": []})
    )
    assert result.usage is None


# ----------------------------- threat color -----------------------------


@pytest.mark.parametrize(
    "level,expected_hex",
    [
        ("CRITICAL", 0xEF4444),
        ("HIGH", 0xF59E0B),
        ("MEDIUM", 0xEAB308),
        ("LOW", 0x22C55E),
    ],
)
def test_color_for_analysis_parses_threat_level(level, expected_hex):
    text = f"**Classification** — IP\n**Threat Level** — {level} — reason"
    color = color_for_analysis(text)
    assert color.value == expected_hex


def test_color_defaults_to_green_without_threat_line():
    color = color_for_analysis("plain text with no threat marker")
    import discord
    assert color == discord.Color.green()


# ----------------------------- smarter chunker --------------------------


def test_chunker_prefers_section_boundary():
    text = (
        "**Classification** — IP\n"
        + ("x" * 200)
        + "\n**Threat Level** — LOW — public\n"
        + ("y" * 200)
        + "\n**Key Findings**\n"
        + ("z" * 100)
    )
    chunks = chunk_text(text, limit=300)
    # First chunk should end at one of the **section** boundaries
    assert chunks[0].endswith("x" * 200) or chunks[0].endswith("\n")
    # Subsequent chunk should start with a **section** marker
    assert any(c.startswith("**") for c in chunks[1:])


# ----------------------------- 24h token spend --------------------------


@pytest.mark.asyncio
async def test_token_usage_since_sums_recent_audits(tmp_path):
    db = await open_db(str(tmp_path / "x.db"))
    await record_audit(db, 1, "a", usage=(100, 50))
    await record_audit(db, 1, "b", usage=(200, 75))
    await record_audit(db, 1, "c")  # cached, no usage
    pt, ct = await token_usage_since(db, "-1 day")
    assert pt == 300
    assert ct == 125
    await db.close()


@pytest.mark.asyncio
async def test_token_usage_returns_zero_when_no_audits(tmp_path):
    db = await open_db(str(tmp_path / "x.db"))
    pt, ct = await token_usage_since(db, "-1 day")
    assert pt == 0 and ct == 0
    await db.close()


# ----------------------------- footer formatting ------------------------


def test_footer_shows_token_count_when_not_cached():
    from meanmug.cogs.osint import _footer_for
    r = GlmResult(content="x", reasoning=None, usage=(123, 45), cached=False)
    f = _footer_for(r)
    assert "123+45 tok" in f
    assert "cache hit" not in f


def test_footer_shows_cache_hit():
    from meanmug.cogs.osint import _footer_for
    r = GlmResult(content="x", reasoning=None, usage=(123, 45), cached=True)
    f = _footer_for(r)
    assert "cache hit" in f
    assert "tok" not in f


def test_footer_marks_reasoning_when_present():
    from meanmug.cogs.osint import _footer_for
    r = GlmResult(content="x", reasoning="long thought trace", usage=(10, 20), cached=False)
    f = _footer_for(r)
    assert "🧠" in f

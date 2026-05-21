"""End-to-end-ish tests: cogs are exercised through fake Interactions."""
from __future__ import annotations

import os

os.environ.setdefault("DISCORD_TOKEN", "x")
os.environ.setdefault("GLM_API_KEY", "x")

import pytest

from meanmug.cogs.cases import CasesCog
from meanmug.cogs.intel_stream import IntelStreamCog, _message_text
from meanmug.cogs.ops import OpsCog
from meanmug.cogs.osint import OSINTCog
from meanmug.cogs.people import PeopleCog, _classify
from meanmug.core.config import Config
from meanmug.services.storage import add_watch, open_db

from tests.fakes import (
    CannedGlm,
    FakeAuthor,
    FakeBot,
    FakeChannel,
    FakeEmbed,
    FakeHttpSession,
    FakeInteraction,
    FakeMessage,
)


# ----------------------------- fixtures ------------------------------------


@pytest.fixture
def cfg():
    os.environ["INTEL_CHANNEL_IDS"] = "100"
    os.environ["ENRICHMENT_ENABLED"] = "false"  # tests must not hit the network
    return Config.from_env()


@pytest.fixture
async def bot(cfg, tmp_path):
    db = await open_db(str(tmp_path / "t.db"))
    fake_bot = FakeBot(db=db, session=FakeHttpSession(), glm=CannedGlm(), config=cfg)
    fake_bot.repo_root = None  # type: ignore[attr-defined]
    yield fake_bot
    await db.close()


# ----------------------------- /osint --------------------------------------


@pytest.mark.asyncio
async def test_osint_command_persists_and_replies(bot):
    cog = OSINTCog(bot)
    interaction = FakeInteraction()
    await cog.osint.callback(cog, interaction, "scan 8.8.8.8 and evil.io", None, None)
    # GLM called once with osint method
    assert any(c[0] == "osint" for c in bot.glm.calls)
    # response: deferred + at least one followup (embed header)
    assert len(interaction.followup.messages) >= 1
    embed = interaction.followup.messages[0]["embed"]
    assert embed is not None
    # audit row written
    async with bot.db.execute("SELECT COUNT(*) FROM audits") as cur:
        n = (await cur.fetchone())[0]
    assert n == 1


@pytest.mark.asyncio
async def test_osint_rejects_empty(bot):
    cog = OSINTCog(bot)
    interaction = FakeInteraction()
    await cog.osint.callback(cog, interaction, "   ", None, None)
    assert interaction.followup.messages[0]["ephemeral"] is True
    assert "usage" in interaction.followup.messages[0]["content"]


@pytest.mark.asyncio
async def test_osint_rejects_unknown_case(bot):
    cog = OSINTCog(bot)
    interaction = FakeInteraction()
    with pytest.raises(Exception):  # AppCommandError
        await cog.osint.callback(cog, interaction, "x", None, "no-such")


# ----------------------------- /pivot --------------------------------------


@pytest.mark.asyncio
async def test_pivot_calls_pivot_variant(bot):
    cog = OSINTCog(bot)
    interaction = FakeInteraction()
    await cog.pivot.callback(cog, interaction, "evil.io", None)
    assert bot.glm.calls[-1][0] == "pivot"
    assert "evil.io" in bot.glm.calls[-1][1][0]


# ----------------------------- /history ------------------------------------


@pytest.mark.asyncio
async def test_history_empty(bot):
    cog = OSINTCog(bot)
    interaction = FakeInteraction()
    await cog.history.callback(cog, interaction, None, 10)
    assert "no history" in interaction.response.messages[0]["content"]


@pytest.mark.asyncio
async def test_history_after_osint(bot):
    cog = OSINTCog(bot)
    inter1 = FakeInteraction()
    await cog.osint.callback(cog, inter1, "8.8.8.8", None, None)
    inter2 = FakeInteraction()
    await cog.history.callback(cog, inter2, None, 5)
    assert "Your last 1 audits" in inter2.response.messages[0]["content"]


# ----------------------------- /case ---------------------------------------


@pytest.mark.asyncio
async def test_case_start_and_close(bot):
    cog = CasesCog(bot)
    i1 = FakeInteraction()
    await cog.start.callback(cog, i1, "apt-test")
    assert "opened" in i1.response.messages[0]["content"]

    i2 = FakeInteraction()
    await cog.show.callback(cog, i2, "apt-test")
    assert i2.response.messages[0]["embed"] is not None

    i3 = FakeInteraction()
    await cog.close.callback(cog, i3, "apt-test")
    assert "closed" in i3.response.messages[0]["content"]


@pytest.mark.asyncio
async def test_case_bad_name_rejected(bot):
    cog = CasesCog(bot)
    i = FakeInteraction()
    await cog.start.callback(cog, i, "Bad Name!")
    assert i.response.messages[0]["ephemeral"] is True


# ----------------------------- /watch* ------------------------------------


@pytest.mark.asyncio
async def test_watch_lifecycle(bot):
    cog = PeopleCog(bot)

    from discord.app_commands import Choice
    i1 = FakeInteraction()
    await cog.watch.callback(cog, i1, "badactor", Choice(name="handle", value="handle"), None)
    assert "watching" in i1.response.messages[0]["content"]

    i2 = FakeInteraction()
    await cog.watchlist.callback(cog, i2)
    assert "badactor" in i2.response.messages[0]["content"]

    i3 = FakeInteraction()
    await cog.unwatch.callback(cog, i3, "badactor")
    assert "removed" in i3.response.messages[0]["content"]


# ----------------------------- /investigate / /trace ----------------------


@pytest.mark.asyncio
async def test_investigate_routes_through_agentic_loop(bot):
    cog = PeopleCog(bot)
    interaction = FakeInteraction()
    await cog.investigate.callback(cog, interaction, "@alice", None)
    assert any(c[0] == "agentic" for c in bot.glm.calls)


# ----------------------------- /changelog / /backup / /health -------------


@pytest.mark.asyncio
async def test_changelog_renders(bot, tmp_path):
    bot.repo_root = tmp_path  # type: ignore[attr-defined]
    (tmp_path / "CHANGELOG.md").write_text("# x\n- `abc123` — first entry\n- `def456` — second\n")
    cog = OpsCog(bot)
    i = FakeInteraction()
    await cog.changelog.callback(cog, i)
    msg = i.response.messages[0]["content"]
    assert "abc123" in msg and "def456" in msg


@pytest.mark.asyncio
async def test_health_reports_db_ok(bot, tmp_path):
    bot.repo_root = tmp_path  # type: ignore[attr-defined]
    cog = OpsCog(bot)
    i = FakeInteraction()
    await cog.health.callback(cog, i)
    embed = i.followup.messages[0]["embed"]
    assert embed is not None


# ----------------------------- intel_stream listener ----------------------


@pytest.mark.asyncio
async def test_intel_listener_skips_self(bot):
    cog = IntelStreamCog(bot)
    msg = FakeMessage(author=bot.user, content="contains @badactor", channel=FakeChannel(id=100))
    assert cog._should_handle(msg) is False


@pytest.mark.asyncio
async def test_intel_listener_skips_dms(bot):
    cog = IntelStreamCog(bot)
    msg = FakeMessage(content="long enough content here", guild=None)
    assert cog._should_handle(msg) is False


@pytest.mark.asyncio
async def test_intel_listener_skips_unwatched_channel(bot):
    cog = IntelStreamCog(bot)
    msg = FakeMessage(content="long enough content here", channel=FakeChannel(id=99))
    assert cog._should_handle(msg) is False


@pytest.mark.asyncio
async def test_intel_listener_accepts_watched_channel(bot):
    cog = IntelStreamCog(bot)
    other_author = FakeAuthor(id=999, name="oathnet")
    msg = FakeMessage(
        content="seen indicator evil.io in feed",
        author=other_author,
        channel=FakeChannel(id=100),
    )
    assert cog._should_handle(msg) is True


@pytest.mark.asyncio
async def test_intel_listener_fires_on_watch_hit(bot):
    cog = IntelStreamCog(bot)
    await add_watch(bot.db, "evil.io", "domain", 1)
    channel = FakeChannel(id=100)
    other_author = FakeAuthor(id=999, name="oathnet")
    msg = FakeMessage(
        content="alert: new evil.io campaign observed by sensors",
        author=other_author,
        channel=channel,
    )
    await cog.on_message(msg)
    assert msg.reactions_added == ["👀"]
    # delivered to the source channel
    assert any("Watchlist hit" in s for s in channel.sent)
    # GLM was invoked
    assert any(c[0] == "person" for c in bot.glm.calls)


def test_message_text_includes_embed_content():
    embed = FakeEmbed(title="Alert", description="evil.io campaign")
    embed.fields = [type("F", (), {"name": "src", "value": "@badactor"})()]
    embed.footer = type("Footer", (), {"text": "intel-bot"})()
    msg = FakeMessage(content="see embed", embeds=[embed])
    text = _message_text(msg)
    assert "evil.io" in text
    assert "@badactor" in text
    assert "intel-bot" in text


# ----------------------------- classifier ---------------------------------


@pytest.mark.parametrize(
    "input_,kind",
    [
        ("alice@example.com", "email"),
        ("@alice", "handle"),
        ("8.8.8.8", "ip"),
        ("google.com", "domain"),
        ("Alice", "handle"),
    ],
)
def test_classify(input_, kind):
    assert _classify(input_)[0] == kind

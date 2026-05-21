"""Coverage for paths the earlier integration tests missed."""
from __future__ import annotations

import os

os.environ.setdefault("DISCORD_TOKEN", "x")
os.environ.setdefault("GLM_API_KEY", "x")
os.environ.setdefault("INTEL_CHANNEL_IDS", "100")
os.environ.setdefault("ENRICHMENT_ENABLED", "false")

import pytest
from discord.app_commands import Choice

from meanmug.bot import CasesCog
from meanmug.bot import OpsCog
from meanmug.bot import PeopleCog
from meanmug.config import Config
from meanmug.database import open_db

from tests.fakes import CannedGlm, FakeBot, FakeHttpSession, FakeInteraction


@pytest.fixture
async def bot(tmp_path):
    db = await open_db(str(tmp_path / "t.db"))
    cfg = Config.from_env()
    fake = FakeBot(db=db, session=FakeHttpSession(), glm=CannedGlm(), config=cfg)
    fake.repo_root = tmp_path  # type: ignore[attr-defined]
    yield fake
    await db.close()


# ----------------------------- /investigate fails fast on bad case ---------


@pytest.mark.asyncio
async def test_investigate_validates_case_before_glm(bot):
    cog = PeopleCog(bot)
    interaction = FakeInteraction()
    with pytest.raises(Exception):  # AppCommandError
        await cog.investigate.callback(cog, interaction, "@alice", "no-such-case")
    # CRITICAL: no GLM call must have happened
    assert all(c[0] != "agentic" for c in bot.glm.calls), (
        "investigate spent a GLM agentic loop before validating case"
    )


@pytest.mark.asyncio
async def test_investigate_caps_long_subject_in_embed_title(bot):
    cog = PeopleCog(bot)
    interaction = FakeInteraction()
    long_subject = "x" * 500
    await cog.investigate.callback(cog, interaction, long_subject, None)
    embed = interaction.followup.messages[0]["embed"]
    assert len(embed.title) <= 256


# ----------------------------- long analysis paginates --------------------


@pytest.mark.asyncio
async def test_long_analysis_paginates_to_multiple_messages(tmp_path):
    db = await open_db(str(tmp_path / "t.db"))
    cfg = Config.from_env()
    long_content = ("paragraph.\n\n" * 400).strip()  # ~4800 chars
    bot = FakeBot(db=db, session=FakeHttpSession(), glm=CannedGlm(content=long_content), config=cfg)
    bot.repo_root = tmp_path  # type: ignore[attr-defined]

    from meanmug.bot import OSINTCog
    cog = OSINTCog(bot)
    interaction = FakeInteraction()
    await cog.osint.callback(cog, interaction, "8.8.8.8", None, None)

    # First followup is the embed; subsequent ones are text chunks.
    assert len(interaction.followup.messages) >= 2, (
        f"expected paginated output, got {len(interaction.followup.messages)} message(s)"
    )
    # Each text chunk fits Discord's 2000-char limit.
    for msg in interaction.followup.messages[1:]:
        content = msg["content"] or ""
        assert len(content) <= 2000
    await db.close()


# ----------------------------- /case list with status filter --------------


@pytest.mark.asyncio
async def test_case_list_with_status_filter(bot):
    cog = CasesCog(bot)
    # open one case, close it; open another
    await cog.start.callback(cog, FakeInteraction(), "alpha")
    await cog.close.callback(cog, FakeInteraction(), "alpha")
    await cog.start.callback(cog, FakeInteraction(), "beta")

    interaction = FakeInteraction()
    await cog.list_cmd.callback(cog, interaction, Choice(name="open", value="open"))
    body = interaction.response.messages[0]["content"]
    assert "beta" in body
    assert "alpha" not in body

    interaction2 = FakeInteraction()
    await cog.list_cmd.callback(cog, interaction2, Choice(name="closed", value="closed"))
    body2 = interaction2.response.messages[0]["content"]
    assert "alpha" in body2
    assert "beta" not in body2


# ----------------------------- /backup with target -----------------------


@pytest.mark.asyncio
async def test_backup_with_target(bot, tmp_path):
    # Populate the essential set under repo_root so snapshot has files to read.
    from meanmug.ops import ESSENTIAL_FILES
    import shutil
    real_root = __import__("pathlib").Path(__file__).resolve().parents[1]
    for f in ESSENTIAL_FILES:
        src = real_root / f
        dst = tmp_path / f
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    cog = OpsCog(bot)
    interaction = FakeInteraction()
    await cog.backup.callback(
        cog, interaction, Choice(name="SYSTEM_PROMPT.md", value="SYSTEM_PROMPT.md")
    )
    msg = interaction.followup.messages[0]["content"]
    assert "✅" in msg
    assert (tmp_path / "backups").exists()


@pytest.mark.asyncio
async def test_backup_rejects_non_essential_target(bot, tmp_path):
    cog = OpsCog(bot)
    interaction = FakeInteraction()
    await cog.backup.callback(
        cog, interaction, Choice(name="README.md", value="README.md")
    )
    msg = interaction.followup.messages[0]["content"]
    assert "⚠️" in msg


# ----------------------------- watchlist edge cases -----------------------


@pytest.mark.asyncio
async def test_watch_dedupes_case_insensitively(bot):
    cog = PeopleCog(bot)
    i1 = FakeInteraction()
    await cog.watch.callback(
        cog, i1, "BadActor", Choice(name="handle", value="handle"), None
    )
    i2 = FakeInteraction()
    await cog.watch.callback(
        cog, i2, "badactor", Choice(name="handle", value="handle"), None
    )
    assert i1.response.messages[0]["ephemeral"] is False
    assert i2.response.messages[0]["ephemeral"] is True
    assert "already watching" in i2.response.messages[0]["content"]


@pytest.mark.asyncio
async def test_unwatch_unknown_identifier(bot):
    cog = PeopleCog(bot)
    interaction = FakeInteraction()
    await cog.unwatch.callback(cog, interaction, "nonexistent")
    assert interaction.response.messages[0]["ephemeral"] is True
    assert "not watching" in interaction.response.messages[0]["content"]


# ----------------------------- audit refusal flag -----------------------


@pytest.mark.asyncio
async def test_record_audit_refusal_flag(bot):
    from meanmug.database import record_audit
    await record_audit(bot.db, 1, "danger", refusal=True)
    async with bot.db.execute("SELECT refusal FROM audits") as cur:
        row = await cur.fetchone()
    assert row[0] == 1


# ----------------------------- health with closed DB ---------------------


@pytest.mark.asyncio
async def test_health_reports_db_fail_when_closed(tmp_path):
    db = await open_db(str(tmp_path / "x.db"))
    cfg = Config.from_env()
    bot = FakeBot(db=db, session=FakeHttpSession(), glm=CannedGlm(), config=cfg)
    bot.repo_root = tmp_path  # type: ignore[attr-defined]
    await db.close()

    cog = OpsCog(bot)
    interaction = FakeInteraction()
    await cog.health.callback(cog, interaction)
    embed = interaction.followup.messages[0]["embed"]
    db_field = next(f for f in embed.fields if "DB" in f.name)
    assert "FAIL" in db_field.value

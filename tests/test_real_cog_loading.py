"""Verify the cogs register correctly through real discord.py machinery.

This is the test that catches issues fakes don't: app_commands.Group binding,
slash-command tree registration, group-vs-toplevel routing, etc.
"""
from __future__ import annotations

import asyncio
import os

os.environ.setdefault("DISCORD_TOKEN", "x")
os.environ.setdefault("GLM_API_KEY", "x")
os.environ.setdefault("INTEL_CHANNEL_IDS", "100")

import discord
import pytest
from discord.ext import commands

from meanmug.cogs.cases import CasesCog
from meanmug.cogs.intel_stream import IntelStreamCog
from meanmug.cogs.ops import OpsCog
from meanmug.cogs.osint import OSINTCog
from meanmug.cogs.people import PeopleCog
from meanmug.core.config import Config
from meanmug.services.storage import open_db

from tests.fakes import CannedGlm, FakeHttpSession


@pytest.mark.asyncio
async def test_all_cogs_register_expected_commands(tmp_path):
    cfg = Config.from_env()
    intents = discord.Intents.default()
    intents.message_content = True
    bot = commands.Bot(command_prefix="!", intents=intents)
    bot.db = await open_db(str(tmp_path / "x.db"))  # type: ignore[attr-defined]
    bot.session = FakeHttpSession()  # type: ignore[attr-defined]
    bot.glm = CannedGlm()  # type: ignore[attr-defined]
    bot.config = cfg  # type: ignore[attr-defined]
    bot.repo_root = tmp_path  # type: ignore[attr-defined]

    for cls in (OSINTCog, PeopleCog, CasesCog, OpsCog, IntelStreamCog):
        await bot.add_cog(cls(bot))

    names: set[str] = set()
    for cmd in bot.tree.walk_commands():
        # walk_commands returns leaves; group subcommands surface with qualified_name.
        names.add(cmd.qualified_name)

    expected = {
        # OSINT
        "osint", "pivot", "history",
        # People
        "investigate", "trace", "watch", "unwatch", "watchlist",
        # Cases (subcommands of /case)
        "case start", "case list", "case show", "case close",
        # Ops
        "changelog", "backup", "health",
    }
    missing = expected - names
    assert not missing, f"missing commands: {missing}; got: {sorted(names)}"

    # Cleanup
    await bot.db.close()  # type: ignore[attr-defined]
    await bot.close()

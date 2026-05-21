from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import discord
from discord import app_commands
from discord.ext import commands

from meanmug.services.backup import (
    ESSENTIAL_FILES,
    latest_snapshot_name,
    snapshot,
)
from meanmug.services.storage import integrity_ok, token_usage_since

log = logging.getLogger(__name__)


def _parse_changelog(text: str) -> list[str]:
    """Return one string per bullet entry in CHANGELOG.md, top-to-bottom."""
    out: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("- ") and "`" in s:
            out.append(s[2:])
    return out


class OpsCog(commands.Cog):
    """/changelog, /backup, /health — operational invariants surface."""

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self.repo_root: Path = bot.repo_root  # type: ignore[attr-defined]
        self.changelog_path = self.repo_root / "CHANGELOG.md"

    @app_commands.command(name="changelog", description="Show the latest 10 changelog entries.")
    async def changelog(self, interaction: discord.Interaction) -> None:
        if not self.changelog_path.is_file():
            await interaction.response.send_message(
                "⚠️ `CHANGELOG.md` not found.", ephemeral=True
            )
            return
        entries = _parse_changelog(self.changelog_path.read_text(encoding="utf-8"))[:10]
        if not entries:
            await interaction.response.send_message("_no entries_", ephemeral=True)
            return
        body = "\n".join(f"- {e}" for e in entries)
        await interaction.response.send_message(
            f"**Last {len(entries)} changes**\n{body[:1900]}"
        )

    @app_commands.command(name="backup", description="Snapshot essential config files.")
    @app_commands.describe(target="Optional: a single essential file path.")
    @app_commands.choices(
        target=[app_commands.Choice(name=f, value=f) for f in ESSENTIAL_FILES]
    )
    async def backup(
        self,
        interaction: discord.Interaction,
        target: Optional[app_commands.Choice[str]] = None,
    ) -> None:
        await interaction.response.defer(ephemeral=True)
        try:
            result = snapshot(self.repo_root, target=target.value if target else None)
        except ValueError as exc:
            await interaction.followup.send(f"⚠️ {exc}", ephemeral=True)
            return
        if result["status"] == "no-op":
            await interaction.followup.send(
                f"✅ no-op — current state matches `{result['matched']}`", ephemeral=True
            )
        else:
            await interaction.followup.send(
                f"✅ snapshotted `{result['timestamp']}` "
                f"({result['files']} files, state `{result['state_hash']}`)",
                ephemeral=True,
            )

    @app_commands.command(name="health", description="Bot, DB, GLM, and backup status.")
    async def health(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)
        latency_ms = round(self.bot.latency * 1000)
        try:
            db_ok = await integrity_ok(self.bot.db)
        except Exception:
            log.exception("db integrity check failed")
            db_ok = False
        last_backup = latest_snapshot_name(self.repo_root) or "_none_"
        try:
            pt_24h, ct_24h = await token_usage_since(self.bot.db, "-1 day")
        except Exception:
            pt_24h, ct_24h = 0, 0

        glm_cfg = self.bot.config.glm  # type: ignore[attr-defined]
        cache_size = len(getattr(self.bot.glm, "_cache", {}))  # type: ignore[attr-defined]
        embed = discord.Embed(
            title="MeanMug-Agent Health",
            color=discord.Color.green() if db_ok else discord.Color.red(),
        )
        embed.add_field(name="Gateway latency", value=f"{latency_ms} ms")
        embed.add_field(name="DB integrity", value="ok" if db_ok else "**FAIL**")
        embed.add_field(name="Last backup", value=f"`{last_backup}`")
        embed.add_field(
            name="GLM",
            value=f"`{glm_cfg.base_url}`\nmodel `{glm_cfg.model}` · thinking `{glm_cfg.thinking}`",
            inline=False,
        )
        embed.add_field(
            name="Tokens (24h)",
            value=f"prompt `{pt_24h}` · completion `{ct_24h}` · total `{pt_24h + ct_24h}`",
            inline=True,
        )
        embed.add_field(name="GLM cache", value=f"`{cache_size}` entries", inline=True)
        embed.set_footer(text="MeanMug-Agent | Production Fabric")
        await interaction.followup.send(embed=embed)


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(OpsCog(bot))

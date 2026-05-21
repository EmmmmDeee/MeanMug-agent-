from __future__ import annotations

import logging
from typing import Optional

import discord
from discord import app_commands
from discord.ext import commands

from meanmug.services.discord_io import chunk_text
from meanmug.services.extract import extract_indicators
from meanmug.services.glm import GlmError
from meanmug.services.storage import record_audit

log = logging.getLogger(__name__)

FOOTER = "MeanMug-Agent | GLM-5.1 OSINT Fabric"
MAX_RAW_BYTES = 256 * 1024


class OSINTCog(commands.Cog):
    """Discord-facing OSINT command. Delegates analysis to GLM-5.1."""

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    @app_commands.command(name="osint", description="Run GLM-5.1 OSINT analysis on text or a file.")
    @app_commands.describe(
        input_data="Raw indicators, notes, or text to analyze.",
        file="Optional file (logs, dumps, emails). Read as UTF-8.",
    )
    async def osint(
        self,
        interaction: discord.Interaction,
        input_data: str,
        file: Optional[discord.Attachment] = None,
    ) -> None:
        await interaction.response.defer(thinking=True)

        raw = await self._ingest(input_data, file)
        indicators = extract_indicators(raw)

        try:
            result = await self.bot.glm.analyze_osint(raw, indicators)
        except GlmError as exc:
            log.warning("GLM analysis failed: %s", exc)
            await record_audit(self.bot.db, interaction.user.id, raw, analysis=None)
            await interaction.followup.send(
                f"⚠️ GLM analysis failed: `{exc}`",
                ephemeral=True,
            )
            return

        await record_audit(self.bot.db, interaction.user.id, raw, analysis=result.content)
        await self._dispatch(interaction, indicators, result.content)

    @staticmethod
    async def _ingest(input_data: str, file: Optional[discord.Attachment]) -> str:
        raw = input_data
        if file is not None:
            if file.size > MAX_RAW_BYTES:
                raise app_commands.AppCommandError(
                    f"Attachment exceeds {MAX_RAW_BYTES // 1024} KiB cap."
                )
            raw += "\n" + (await file.read()).decode("utf-8", "ignore")
        return raw

    async def _dispatch(
        self,
        interaction: discord.Interaction,
        indicators: dict[str, list[str]],
        analysis: str,
    ) -> None:
        chunks = chunk_text(analysis)
        embed = self._build_header_embed(indicators, chunks[0])
        await interaction.followup.send(embed=embed)
        for chunk in chunks[1:]:
            await interaction.followup.send(chunk)

    @staticmethod
    def _build_header_embed(indicators: dict[str, list[str]], analysis_head: str) -> discord.Embed:
        embed = discord.Embed(
            title="OSINT Intelligence Report",
            description=analysis_head,
            color=discord.Color.green(),
        )
        for label, key in (("IPs", "ips"), ("Domains", "domains"), ("Emails", "emails")):
            values = indicators[key]
            embed.add_field(
                name=f"{label} ({len(values)})",
                value=f"`{', '.join(values)}`" if values else "_none_",
                inline=False,
            )
        embed.set_footer(text=FOOTER)
        return embed

    @commands.Cog.listener()
    async def on_app_command_error(
        self,
        interaction: discord.Interaction,
        error: app_commands.AppCommandError,
    ) -> None:
        if isinstance(error, app_commands.CommandOnCooldown):
            message = f"⏳ Cool-down: {error.retry_after:.1f}s"
        else:
            log.exception("app command error", exc_info=error)
            message = f"⚠️ {error}" if str(error) else "⚠️ Command failed. Check logs."
        send = interaction.followup.send if interaction.response.is_done() else interaction.response.send_message
        await send(message, ephemeral=True)


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(OSINTCog(bot))

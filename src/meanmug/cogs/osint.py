from __future__ import annotations

import logging
from typing import Optional

import discord
from discord import app_commands
from discord.ext import commands

from meanmug.services.extract import extract_indicators
from meanmug.services.storage import record_audit

log = logging.getLogger(__name__)

FOOTER = "MeanMug-Agent | Production Fabric"


class OSINTCog(commands.Cog):
    """Logic layer: OSINT ingestion, extraction, persistence, display."""

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    @app_commands.command(name="osint", description="Execute structured intelligence analysis")
    @app_commands.describe(
        input_data="Raw indicators or text",
        file="Optional file attachment to include in the analysis",
    )
    async def osint(
        self,
        interaction: discord.Interaction,
        input_data: str,
        file: Optional[discord.Attachment] = None,
    ) -> None:
        await interaction.response.defer()

        raw = input_data
        if file is not None:
            raw += "\n" + (await file.read()).decode("utf-8", "ignore")

        indicators = extract_indicators(raw)
        await record_audit(self.bot.db, interaction.user.id, raw)

        embed = discord.Embed(
            title="OSINT Intelligence Report",
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

        await interaction.followup.send(embed=embed)

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
            message = "⚠️ Command failed. Check logs."
        send = interaction.followup.send if interaction.response.is_done() else interaction.response.send_message
        await send(message, ephemeral=True)


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(OSINTCog(bot))

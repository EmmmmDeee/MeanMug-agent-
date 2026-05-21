from __future__ import annotations

import logging
import re
from typing import Optional

import discord
from discord import app_commands
from discord.ext import commands

from meanmug.services.storage import (
    case_audits,
    close_case,
    create_case,
    get_case_by_name,
    list_cases,
)

log = logging.getLogger(__name__)

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,31}$")


class CasesCog(commands.Cog):
    """/case group — manage OSINT investigation cases."""

    case_group = app_commands.Group(name="case", description="Manage OSINT investigation cases.")

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    @case_group.command(name="start", description="Open a new investigation case.")
    @app_commands.describe(name="Short slug: a-z, 0-9, _ and -, 2-32 chars.")
    async def start(self, interaction: discord.Interaction, name: str) -> None:
        if not _NAME_RE.match(name):
            await interaction.response.send_message(
                "⚠️ name must match `^[a-z0-9][a-z0-9_-]{1,31}$`", ephemeral=True
            )
            return
        if await get_case_by_name(self.bot.db, name):
            await interaction.response.send_message(
                f"⚠️ case `{name}` already exists.", ephemeral=True
            )
            return
        case_id = await create_case(self.bot.db, name, interaction.user.id)
        await interaction.response.send_message(f"✅ case `{name}` opened (id `{case_id}`).")

    @case_group.command(name="list", description="List recent cases.")
    @app_commands.describe(status="Filter by status.")
    @app_commands.choices(
        status=[
            app_commands.Choice(name="open", value="open"),
            app_commands.Choice(name="closed", value="closed"),
        ]
    )
    async def list_cmd(
        self,
        interaction: discord.Interaction,
        status: Optional[app_commands.Choice[str]] = None,
    ) -> None:
        rows = await list_cases(self.bot.db, status=status.value if status else None)
        if not rows:
            await interaction.response.send_message("_no cases_", ephemeral=True)
            return
        body = "\n".join(
            f"`#{r[0]:>3}` **{r[1]}** — {r[2]} · {r[3]}" for r in rows
        )
        await interaction.response.send_message(f"**Cases**\n{body[:1900]}")

    @case_group.command(name="show", description="Show a case and its recent audits.")
    @app_commands.describe(name="The case name.")
    async def show(self, interaction: discord.Interaction, name: str) -> None:
        case = await get_case_by_name(self.bot.db, name)
        if case is None:
            await interaction.response.send_message(f"⚠️ no case `{name}`.", ephemeral=True)
            return
        audits = await case_audits(self.bot.db, case[0])
        embed = discord.Embed(title=f"Case: {case[1]}", color=discord.Color.blurple())
        embed.add_field(name="Status", value=case[3])
        embed.add_field(name="Opened by", value=f"<@{case[2]}>")
        embed.add_field(name="Opened at", value=case[4])
        if case[5]:
            embed.add_field(name="Closed at", value=case[5])
        embed.add_field(name="Audits", value=str(len(audits)), inline=False)
        if audits:
            preview = "\n".join(
                f"`{a[0]}` — {(a[1] or '').replace(chr(10), ' ')[:80]}" for a in audits[:5]
            )
            embed.add_field(name="Recent", value=preview, inline=False)
        await interaction.response.send_message(embed=embed)

    @case_group.command(name="close", description="Close a case.")
    @app_commands.describe(name="The case name.")
    async def close(self, interaction: discord.Interaction, name: str) -> None:
        case = await get_case_by_name(self.bot.db, name)
        if case is None:
            await interaction.response.send_message(f"⚠️ no case `{name}`.", ephemeral=True)
            return
        if case[3] == "closed":
            await interaction.response.send_message("_already closed_", ephemeral=True)
            return
        await close_case(self.bot.db, case[0])
        await interaction.response.send_message(f"✅ case `{name}` closed.")


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(CasesCog(bot))

from __future__ import annotations

import logging
from typing import Optional

import discord
from discord import app_commands
from discord.ext import commands

from meanmug.services.discord_io import chunk_text
from meanmug.services.extract import extract_indicators
from meanmug.services.glm import GlmError
from meanmug.services.people import enrich_person
from meanmug.services.storage import (
    add_watch,
    list_watches,
    record_audit,
    remove_watch,
)

log = logging.getLogger(__name__)

FOOTER = "MeanMug-Agent | People OSINT"
COOLDOWN_RATE = 1
COOLDOWN_PER = 20.0
_KINDS = ("handle", "email", "domain", "ip")


def _per_user(interaction: discord.Interaction) -> discord.abc.User:
    return interaction.user


def _classify(identifier: str) -> tuple[str, str]:
    """Best-effort classify an operator-supplied identifier; return (kind, normalized)."""
    s = identifier.strip()
    low = s.lower()
    if "@" in s and "." in s.split("@", 1)[1]:
        return "email", low
    if low.startswith("@"):
        return "handle", low.lstrip("@")
    if all(c.isdigit() or c == "." for c in low) and low.count(".") == 3:
        return "ip", low
    if "." in low and " " not in low:
        return "domain", low
    return "handle", low.lstrip("@")


class PeopleCog(commands.Cog):
    """People-centric OSINT — identity correlation across public surfaces."""

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    @app_commands.command(
        name="investigate",
        description="Person-centric GLM investigation across handles and emails.",
    )
    @app_commands.describe(
        subject="Handle, email, name, or free text describing the person.",
        case="Optional case name to append this audit to.",
    )
    @app_commands.checks.cooldown(COOLDOWN_RATE, COOLDOWN_PER, key=_per_user)
    async def investigate(
        self,
        interaction: discord.Interaction,
        subject: str,
        case: Optional[str] = None,
    ) -> None:
        await interaction.response.defer(thinking=True)
        if not subject.strip():
            await interaction.followup.send("usage: `/investigate <subject>`", ephemeral=True)
            return

        indicators = extract_indicators(subject)
        if not indicators["handles"] and not indicators["emails"]:
            kind, norm = _classify(subject)
            if kind == "handle":
                indicators["handles"].append(norm)
            elif kind == "email":
                indicators["emails"].append(norm)

        person_intel = await enrich_person(
            self.bot.session,
            handles=indicators["handles"],
            emails=indicators["emails"],
        ) if self.bot.config.enrichment_enabled else {}

        try:
            result = await self.bot.glm.analyze_person(
                subject, person_intel, indicators
            )
        except GlmError as exc:
            log.warning("GLM person analysis failed: %s", exc)
            await record_audit(self.bot.db, interaction.user.id, subject)
            await interaction.followup.send(f"⚠️ GLM analysis failed: `{exc}`", ephemeral=True)
            return

        case_id = await self._resolve_case_id(case)
        await record_audit(
            self.bot.db, interaction.user.id, subject, analysis=result.content, case_id=case_id
        )
        await self._dispatch(interaction, subject, person_intel, result.content, case=case)

    @app_commands.command(
        name="trace",
        description="Quick keyless trace of a handle across GitHub, GitLab, HackerNews.",
    )
    @app_commands.describe(handle="The username/alias to trace.")
    @app_commands.checks.cooldown(COOLDOWN_RATE, COOLDOWN_PER, key=_per_user)
    async def trace(self, interaction: discord.Interaction, handle: str) -> None:
        await interaction.response.defer(thinking=True)
        h = handle.strip().lstrip("@").lower()
        if not h:
            await interaction.followup.send("usage: `/trace <handle>`", ephemeral=True)
            return
        intel = await enrich_person(self.bot.session, handles=[h])
        data = intel["handles"].get(h, {})
        platforms = data.get("platforms_found", 0)
        embed = discord.Embed(
            title=f"Trace: {h}",
            color=discord.Color.green() if platforms else discord.Color.dark_gray(),
            description=f"Found on **{platforms}/3** keyless platforms.",
        )
        gh = data.get("github") or {}
        if gh:
            value = (
                f"[{gh.get('login')}]({gh.get('url')}) · "
                f"{gh.get('public_repos', 0)} repos · {gh.get('followers', 0)} followers"
            )
            if gh.get("name") or gh.get("bio"):
                value += f"\n{gh.get('name') or ''} — {gh.get('bio') or ''}"[:200]
            embed.add_field(name="GitHub", value=value[:1024], inline=False)
        gl = data.get("gitlab") or {}
        if gl:
            embed.add_field(
                name="GitLab",
                value=f"[{gl.get('username')}]({gl.get('url')}) — {gl.get('name') or ''}"[:1024],
                inline=False,
            )
        hn = data.get("hackernews") or {}
        if hn:
            embed.add_field(
                name="HackerNews",
                value=f"`{hn.get('id')}` · karma {hn.get('karma')}"[:1024],
                inline=False,
            )
        if platforms == 0:
            embed.add_field(name="—", value="No public profiles found on tested platforms.")
        embed.set_footer(text=FOOTER)
        await interaction.followup.send(embed=embed)

    @app_commands.command(name="watch", description="Add an identifier to the watchlist.")
    @app_commands.describe(
        identifier="Handle, email, domain, or IP to watch for in intel channels.",
        kind="What kind of identifier this is.",
        note="Optional note.",
    )
    @app_commands.choices(kind=[app_commands.Choice(name=k, value=k) for k in _KINDS])
    async def watch(
        self,
        interaction: discord.Interaction,
        identifier: str,
        kind: app_commands.Choice[str],
        note: Optional[str] = None,
    ) -> None:
        norm = identifier.strip().lstrip("@").lower()
        added = await add_watch(self.bot.db, norm, kind.value, interaction.user.id, note)
        if added:
            await interaction.response.send_message(
                f"✅ watching `{norm}` (`{kind.value}`)."
            )
        else:
            await interaction.response.send_message(
                f"_already watching `{norm}` (`{kind.value}`)._", ephemeral=True
            )

    @app_commands.command(name="unwatch", description="Remove an identifier from the watchlist.")
    @app_commands.describe(identifier="The identifier to stop watching.")
    async def unwatch(self, interaction: discord.Interaction, identifier: str) -> None:
        norm = identifier.strip().lstrip("@").lower()
        n = await remove_watch(self.bot.db, norm)
        if n:
            await interaction.response.send_message(f"✅ removed `{norm}` ({n} entries).")
        else:
            await interaction.response.send_message(f"_not watching `{norm}`._", ephemeral=True)

    @app_commands.command(name="watchlist", description="Show the current watchlist.")
    async def watchlist(self, interaction: discord.Interaction) -> None:
        rows = await list_watches(self.bot.db)
        if not rows:
            await interaction.response.send_message("_watchlist is empty_", ephemeral=True)
            return
        lines = [
            f"`{r[2]:>6}` `{r[1]}`" + (f" — {r[3]}" if r[3] else "") for r in rows
        ]
        body = "\n".join(lines)
        await interaction.response.send_message(
            f"**Watchlist ({len(rows)})**\n{body[:1900]}"
        )

    async def _resolve_case_id(self, case: Optional[str]) -> Optional[int]:
        if not case:
            return None
        from meanmug.services.storage import get_case_by_name

        row = await get_case_by_name(self.bot.db, case)
        if row is None:
            raise app_commands.AppCommandError(f"case `{case}` does not exist.")
        if row[3] != "open":
            raise app_commands.AppCommandError(f"case `{case}` is {row[3]}.")
        return row[0]

    async def _dispatch(
        self,
        interaction: discord.Interaction,
        subject: str,
        person_intel: dict,
        analysis: str,
        case: Optional[str] = None,
    ) -> None:
        chunks = chunk_text(analysis)
        embed = discord.Embed(
            title=f"People Intel: {subject}",
            description=chunks[0],
            color=discord.Color.green(),
        )
        for h, d in (person_intel.get("handles") or {}).items():
            found = d.get("platforms_found", 0)
            embed.add_field(name=f"@{h}", value=f"{found}/3 platforms", inline=True)
        if case:
            embed.add_field(name="Case", value=f"`{case}`", inline=False)
        embed.set_footer(text=FOOTER)
        await interaction.followup.send(embed=embed)
        for chunk in chunks[1:]:
            await interaction.followup.send(chunk)


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(PeopleCog(bot))

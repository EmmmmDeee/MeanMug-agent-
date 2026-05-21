from __future__ import annotations

import logging
from typing import Optional

import discord
from discord import app_commands
from discord.ext import commands

from meanmug.services.discord_io import chunk_text, color_for_analysis
from meanmug.services.extract import extract_indicators
from meanmug.services.glm import GlmError
from meanmug.services.people import enrich_person
from meanmug.services.storage import (
    add_watch,
    get_case_by_name,
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

        # Validate case BEFORE entering the agentic loop.
        case_id = await self._resolve_case_id(case)

        user_message = (
            f"Investigate this subject: {subject.strip()}\n\n"
            "Use the available tools to gather public OSINT on the subject, "
            "pivot on what you find, then produce the standard 5-section report."
        )

        try:
            agentic = await self.bot.glm.chat_with_tools(user_message)
        except GlmError as exc:
            log.warning("GLM agentic investigation failed: %s", exc)
            await record_audit(
                self.bot.db, interaction.user.id, subject, case_id=case_id
            )
            await interaction.followup.send(f"⚠️ GLM analysis failed: `{exc}`", ephemeral=True)
            return

        await record_audit(
            self.bot.db,
            interaction.user.id,
            subject,
            analysis=agentic.content,
            case_id=case_id,
            reasoning=agentic.reasoning,
        )
        await self._dispatch_agentic(interaction, subject, agentic, case=case)

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
        result,
        case: Optional[str] = None,
    ) -> None:
        chunks = chunk_text(result.content)
        title = f"People Intel: {subject}"
        if len(title) > 256:
            title = title[:253] + "..."
        embed = discord.Embed(
            title=title,
            description=chunks[0],
            color=color_for_analysis(chunks[0]),
        )
        for h, d in (person_intel.get("handles") or {}).items():
            found = d.get("platforms_found", 0)
            embed.add_field(name=f"@{h}", value=f"{found}/3 platforms", inline=True)
        if case:
            embed.add_field(name="Case", value=f"`{case}`", inline=False)
        embed.set_footer(text=_footer_for(result))
        await interaction.followup.send(embed=embed)
        for chunk in chunks[1:]:
            await interaction.followup.send(chunk)

    async def _dispatch_agentic(
        self,
        interaction: discord.Interaction,
        subject: str,
        agentic,
        case: Optional[str] = None,
    ) -> None:
        chunks = chunk_text(agentic.content)
        title = f"Investigation: {subject}"
        if len(title) > 256:
            title = title[:253] + "..."
        embed = discord.Embed(
            title=title,
            description=chunks[0],
            color=color_for_analysis(chunks[0]),
        )
        tool_counts: dict[str, int] = {}
        for tc in agentic.tool_calls:
            tool_counts[tc.name] = tool_counts.get(tc.name, 0) + 1
        if tool_counts:
            embed.add_field(
                name=f"Tools invoked ({len(agentic.tool_calls)})",
                value=" · ".join(
                    f"`{n}`×{c}" if c > 1 else f"`{n}`" for n, c in sorted(tool_counts.items())
                )[:1024],
                inline=False,
            )
        if case:
            embed.add_field(name="Case", value=f"`{case}`", inline=False)
        embed.set_footer(text=_agentic_footer(agentic))
        await interaction.followup.send(embed=embed)
        for chunk in chunks[1:]:
            await interaction.followup.send(chunk)


def _footer_for(result) -> str:
    parts = [FOOTER]
    if getattr(result, "cached", False):
        parts.append("cache hit")
    if getattr(result, "reasoning", None):
        parts.append(f"🧠 {len(result.reasoning)}c reasoning")
    return " · ".join(parts)


def _agentic_footer(agentic) -> str:
    tools_used = ", ".join(sorted({tc.name for tc in agentic.tool_calls})) or "no tools"
    label = (
        f"{agentic.turns} turns · {len(agentic.tool_calls)} tool calls ({tools_used})"
    )
    if agentic.hit_turn_cap:
        label += " · ⚠ turn cap"
    if agentic.reasoning:
        label += f" · 🧠 {len(agentic.reasoning)}c reasoning"
    return f"{FOOTER} | {label}"


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(PeopleCog(bot))

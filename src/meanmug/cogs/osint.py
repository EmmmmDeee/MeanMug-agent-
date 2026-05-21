from __future__ import annotations

import logging
from typing import Optional

import discord
from discord import app_commands
from discord.ext import commands

from meanmug.services.discord_io import chunk_text, color_for_analysis
from meanmug.services.enrich import enrich_indicators
from meanmug.services.extract import extract_indicators
from meanmug.services.glm import GlmError
from meanmug.services.storage import (
    get_case_by_name,
    recent_audits,
    record_audit,
)

log = logging.getLogger(__name__)

FOOTER = "MeanMug-Agent | GLM-5.1 OSINT Fabric"
MAX_RAW_BYTES = 256 * 1024
COOLDOWN_RATE = 1
COOLDOWN_PER = 20.0


def _per_user(interaction: discord.Interaction) -> Optional[discord.User]:
    return interaction.user


class OSINTCog(commands.Cog):
    """Discord-facing OSINT commands. Delegates analysis to GLM-5.1."""

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    @app_commands.command(name="osint", description="Run GLM-5.1 OSINT analysis on text or a file.")
    @app_commands.describe(
        input_data="Raw indicators, notes, or text to analyze.",
        file="Optional file (logs, dumps, emails). Read as UTF-8.",
        case="Optional case name to append this audit to.",
    )
    @app_commands.checks.cooldown(COOLDOWN_RATE, COOLDOWN_PER, key=_per_user)
    async def osint(
        self,
        interaction: discord.Interaction,
        input_data: str,
        file: Optional[discord.Attachment] = None,
        case: Optional[str] = None,
    ) -> None:
        await interaction.response.defer(thinking=True)

        if not input_data.strip() and file is None:
            await interaction.followup.send("usage: `/osint <input>`", ephemeral=True)
            return

        case_id = await self._resolve_case(case)
        raw = await self._ingest(input_data, file)
        indicators = extract_indicators(raw)
        enrichment = await self._enrich(indicators)

        try:
            result = await self.bot.glm.analyze_osint(raw, indicators, enrichment=enrichment)
        except GlmError as exc:
            log.warning("GLM osint failed: %s", exc)
            await record_audit(self.bot.db, interaction.user.id, raw, case_id=case_id)
            await interaction.followup.send(f"⚠️ GLM analysis failed: `{exc}`", ephemeral=True)
            return

        await record_audit(
            self.bot.db,
            interaction.user.id,
            raw,
            analysis=result.content,
            case_id=case_id,
            reasoning=result.reasoning,
            usage=None if result.cached else result.usage,
        )
        await self._dispatch(interaction, indicators, enrichment, result, case=case)

    @app_commands.command(name="pivot", description="Pursue every downstream lead from one indicator.")
    @app_commands.describe(
        indicator="A single indicator (IP, domain, email, alias).",
        case="Optional case name to append this audit to.",
    )
    @app_commands.checks.cooldown(COOLDOWN_RATE, COOLDOWN_PER, key=_per_user)
    async def pivot(
        self,
        interaction: discord.Interaction,
        indicator: str,
        case: Optional[str] = None,
    ) -> None:
        await interaction.response.defer(thinking=True)

        if not indicator.strip():
            await interaction.followup.send("usage: `/pivot <indicator>`", ephemeral=True)
            return

        case_id = await self._resolve_case(case)
        indicators = extract_indicators(indicator)
        enrichment = await self._enrich(indicators)

        try:
            result = await self.bot.glm.analyze_pivot(indicator, indicators, enrichment=enrichment)
        except GlmError as exc:
            log.warning("GLM pivot failed: %s", exc)
            await record_audit(self.bot.db, interaction.user.id, indicator, case_id=case_id)
            await interaction.followup.send(f"⚠️ GLM pivot failed: `{exc}`", ephemeral=True)
            return

        await record_audit(
            self.bot.db,
            interaction.user.id,
            indicator,
            analysis=result.content,
            case_id=case_id,
            reasoning=result.reasoning,
            usage=None if result.cached else result.usage,
        )
        await self._dispatch(
            interaction, indicators, enrichment, result, case=case, title="Pivot Report"
        )

    @app_commands.command(name="history", description="Show your recent audits, optionally filtered by case.")
    @app_commands.describe(
        case="Optional case name to filter by.",
        limit="Number of audits to show (1-25).",
    )
    async def history(
        self,
        interaction: discord.Interaction,
        case: Optional[str] = None,
        limit: int = 10,
    ) -> None:
        limit = max(1, min(limit, 25))
        case_id: Optional[int] = None
        if case:
            row = await get_case_by_name(self.bot.db, case)
            if row is None:
                await interaction.response.send_message(
                    f"⚠️ no case `{case}`.", ephemeral=True
                )
                return
            case_id = row[0]
        rows = await recent_audits(
            self.bot.db, interaction.user.id, limit, case_id=case_id
        )
        if not rows:
            await interaction.response.send_message("_no history_", ephemeral=True)
            return
        lines = [
            f"`#{r[0]:>4}` `{r[3]}` — {(r[1] or '').replace(chr(10), ' ')[:90]}"
            for r in rows
        ]
        header = f"**Your last {len(rows)} audits"
        header += f" in `{case}`**" if case else "**"
        body = "\n".join(lines)
        await interaction.response.send_message(
            f"{header}\n{body[:1900]}", ephemeral=True
        )

    async def _enrich(self, indicators: dict[str, list[str]]) -> dict:
        if not self.bot.config.enrichment_enabled:
            return {}
        return await enrich_indicators(self.bot.session, indicators)

    async def _resolve_case(self, case: Optional[str]) -> Optional[int]:
        if not case:
            return None
        row = await get_case_by_name(self.bot.db, case)
        if row is None:
            raise app_commands.AppCommandError(f"case `{case}` does not exist; use `/case start`.")
        if row[3] != "open":
            raise app_commands.AppCommandError(f"case `{case}` is {row[3]}; reopen with a new name.")
        return row[0]

    @staticmethod
    async def _ingest(input_data: str, file: Optional[discord.Attachment]) -> str:
        raw = input_data
        if file is not None:
            if file.size > MAX_RAW_BYTES:
                raise app_commands.AppCommandError(
                    f"attachment exceeds {MAX_RAW_BYTES // 1024} KiB cap."
                )
            raw += "\n" + (await file.read()).decode("utf-8", "ignore")
        return raw

    async def _dispatch(
        self,
        interaction: discord.Interaction,
        indicators: dict[str, list[str]],
        enrichment: dict,
        result,
        case: Optional[str] = None,
        title: str = "OSINT Intelligence Report",
    ) -> None:
        chunks = chunk_text(result.content)
        embed = self._build_header_embed(
            indicators, enrichment, chunks[0], case=case, title=title, result=result
        )
        await interaction.followup.send(embed=embed)
        for chunk in chunks[1:]:
            await interaction.followup.send(chunk)

    @staticmethod
    def _build_header_embed(
        indicators: dict[str, list[str]],
        enrichment: dict,
        analysis_head: str,
        case: Optional[str],
        title: str,
        result,
    ) -> discord.Embed:
        embed = discord.Embed(
            title=title,
            description=analysis_head,
            color=color_for_analysis(analysis_head),
        )
        for label, key in (("IPs", "ips"), ("Domains", "domains"), ("Emails", "emails")):
            values = indicators[key]
            embed.add_field(
                name=f"{label} ({len(values)})",
                value=f"`{', '.join(values)}`" if values else "_none_",
                inline=False,
            )
        flags = _enrichment_flags(enrichment)
        if flags:
            embed.add_field(name="Enrichment", value=" · ".join(flags), inline=False)
        if case:
            embed.add_field(name="Case", value=f"`{case}`", inline=False)
        embed.set_footer(text=_footer_for(result))
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
        send = (
            interaction.followup.send
            if interaction.response.is_done()
            else interaction.response.send_message
        )
        await send(message, ephemeral=True)


def _footer_for(result) -> str:
    parts = [FOOTER]
    if getattr(result, "cached", False):
        parts.append("cache hit")
    elif getattr(result, "usage", None):
        pt, ct = result.usage
        parts.append(f"{pt}+{ct} tok")
    if getattr(result, "reasoning", None):
        parts.append(f"🧠 {len(result.reasoning)}c reasoning")
    return " · ".join(parts)


def _enrichment_flags(enrichment: dict) -> list[str]:
    flags: list[str] = []
    ip_count = len(enrichment.get("ips", {}))
    dom_count = len(enrichment.get("domains", {}))
    if ip_count:
        tor_hits = sum(1 for v in enrichment["ips"].values() if v.get("tor_exit"))
        flags.append(f"{ip_count} IP" + ("s" if ip_count != 1 else ""))
        if tor_hits:
            flags.append(f"⚠ {tor_hits} Tor exit")
    if dom_count:
        flags.append(f"{dom_count} domain" + ("s" if dom_count != 1 else ""))
    return flags


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(OSINTCog(bot))

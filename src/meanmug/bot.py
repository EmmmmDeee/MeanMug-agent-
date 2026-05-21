"""Discord layer: bot subclass + all five cogs + small UI helpers.

Cogs:
- OSINTCog        /osint, /pivot, /history + app-command error handler
- PeopleCog       /investigate, /trace, /watch, /unwatch, /watchlist
- CasesCog        /case start | list | show | close
- OpsCog          /changelog, /backup, /health
- IntelStreamCog  on_message listener for autonomous watchlist hits

The bot owns shared handles (aiohttp session, aiosqlite connection, GLM
client) and exposes them to cogs via self attributes. Cogs only touch
Discord types; everything Discord-agnostic lives in config / intel / glm
/ database / ops.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional

import aiohttp
import aiosqlite
import discord
from discord import app_commands
from discord.ext import commands

from meanmug import database, intel, ops
from meanmug.config import Config
from meanmug.glm import AgenticResult, GlmClient, GlmError, GlmResult

log = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]

# UI constants used across cogs
FOOTER_OSINT = "MeanMug-Agent | GLM-5.1 OSINT Fabric"
FOOTER_PEOPLE = "MeanMug-Agent | People OSINT"
FOOTER_OPS = "MeanMug-Agent | Production Fabric"
MAX_RAW_BYTES = 256 * 1024
COOLDOWN_RATE = 1
COOLDOWN_PER = 20.0
MIN_INTEL_MSG_LEN = 16
INTEL_SEEN_CAP = 4096


# ============================== Discord helpers ============================


_THREAT_RE = re.compile(
    r"\*\*Threat Level\*\*\s*[—\-:]\s*(CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN)",
    re.IGNORECASE,
)
_THREAT_COLORS: dict[str, discord.Color] = {
    "CRITICAL": discord.Color.from_str("#ef4444"),
    "HIGH": discord.Color.from_str("#f59e0b"),
    "MEDIUM": discord.Color.from_str("#eab308"),
    "LOW": discord.Color.from_str("#22c55e"),
    "UNKNOWN": discord.Color.dark_gray(),
}


def color_for_analysis(analysis: str) -> discord.Color:
    """Pick an embed color from the analysis's **Threat Level** line."""
    match = _THREAT_RE.search(analysis or "")
    if not match:
        return discord.Color.green()
    return _THREAT_COLORS.get(match.group(1).upper(), discord.Color.green())


def chunk_text(text: str, limit: int = 1900) -> list[str]:
    """Split text into Discord-safe chunks.

    Boundary preference (each rejected if it falls before half the limit):
    Markdown section header → paragraph break → line → word → hard cut.
    """
    text = text.strip()
    if len(text) <= limit:
        return [text]
    chunks: list[str] = []
    remaining = text
    half = limit // 2
    while len(remaining) > limit:
        window = remaining[:limit]
        cut = window.rfind("\n**")
        if cut < half:
            cut = window.rfind("\n\n")
        if cut < half:
            cut = window.rfind("\n")
        if cut < half:
            cut = window.rfind(" ")
        if cut <= 0:
            cut = limit
        chunks.append(remaining[:cut].rstrip())
        remaining = remaining[cut:].lstrip()
    if remaining:
        chunks.append(remaining)
    return chunks


def _per_user(interaction: discord.Interaction) -> discord.abc.User:
    return interaction.user


def _footer_for(result: GlmResult, base: str = FOOTER_OSINT) -> str:
    parts = [base]
    if getattr(result, "cached", False):
        parts.append("cache hit")
    elif getattr(result, "usage", None):
        pt, ct = result.usage
        parts.append(f"{pt}+{ct} tok")
    if getattr(result, "reasoning", None):
        parts.append(f"🧠 {len(result.reasoning)}c reasoning")
    return " · ".join(parts)


def _agentic_footer(agentic: AgenticResult, base: str = FOOTER_PEOPLE) -> str:
    tools_used = ", ".join(sorted({tc.name for tc in agentic.tool_calls})) or "no tools"
    label = f"{agentic.turns} turns · {len(agentic.tool_calls)} tool calls ({tools_used})"
    if agentic.hit_turn_cap:
        label += " · ⚠ turn cap"
    if agentic.reasoning:
        label += f" · 🧠 {len(agentic.reasoning)}c reasoning"
    return f"{base} | {label}"


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


def _classify(identifier: str) -> tuple[str, str]:
    """Best-effort classify an operator-supplied identifier; (kind, normalized)."""
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


def _message_text(message: discord.Message) -> str:
    """Concatenate message content with all text from any rich embeds."""
    parts: list[str] = []
    if message.content:
        parts.append(message.content)
    for embed in message.embeds or []:
        if embed.title:
            parts.append(embed.title)
        if embed.description:
            parts.append(embed.description)
        for field in embed.fields or []:
            if field.name:
                parts.append(field.name)
            if field.value:
                parts.append(field.value)
        if embed.footer and embed.footer.text:
            parts.append(embed.footer.text)
    return "\n".join(parts)


# ============================== OSINT cog ==================================


class OSINTCog(commands.Cog):
    """/osint, /pivot, /history + the app-command error handler shared by all cogs."""

    def __init__(self, bot: "MeanMugBot") -> None:
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
        indicators = intel.extract_indicators(raw)
        enrichment = await self._enrich(indicators)

        try:
            result = await self.bot.glm.analyze_osint(raw, indicators, enrichment=enrichment)
        except GlmError as exc:
            log.warning("GLM osint failed: %s", exc)
            await database.record_audit(self.bot.db, interaction.user.id, raw, case_id=case_id)
            await interaction.followup.send(f"⚠️ GLM analysis failed: `{exc}`", ephemeral=True)
            return

        await database.record_audit(
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
        indicators = intel.extract_indicators(indicator)
        enrichment = await self._enrich(indicators)

        try:
            result = await self.bot.glm.analyze_pivot(indicator, indicators, enrichment=enrichment)
        except GlmError as exc:
            log.warning("GLM pivot failed: %s", exc)
            await database.record_audit(self.bot.db, interaction.user.id, indicator, case_id=case_id)
            await interaction.followup.send(f"⚠️ GLM pivot failed: `{exc}`", ephemeral=True)
            return

        await database.record_audit(
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

    @app_commands.command(
        name="history", description="Show your recent audits, optionally filtered by case."
    )
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
            row = await database.get_case_by_name(self.bot.db, case)
            if row is None:
                await interaction.response.send_message(f"⚠️ no case `{case}`.", ephemeral=True)
                return
            case_id = row[0]
        rows = await database.recent_audits(self.bot.db, interaction.user.id, limit, case_id=case_id)
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
        await interaction.response.send_message(f"{header}\n{body[:1900]}", ephemeral=True)

    # --- helpers ---

    async def _enrich(self, indicators: dict[str, list[str]]) -> dict:
        if not self.bot.config.enrichment_enabled:
            return {}
        return await intel.enrich_indicators(self.bot.session, indicators)

    async def _resolve_case(self, case: Optional[str]) -> Optional[int]:
        if not case:
            return None
        row = await database.get_case_by_name(self.bot.db, case)
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
        result: GlmResult,
        case: Optional[str] = None,
        title: str = "OSINT Intelligence Report",
    ) -> None:
        chunks = chunk_text(result.content)
        embed = discord.Embed(
            title=title,
            description=chunks[0],
            color=color_for_analysis(chunks[0]),
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
        await interaction.followup.send(embed=embed)
        for chunk in chunks[1:]:
            await interaction.followup.send(chunk)

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


# ============================== People cog =================================


_KINDS = ("handle", "email", "domain", "ip")


class PeopleCog(commands.Cog):
    """/investigate (agentic), /trace (fast), and watchlist management."""

    def __init__(self, bot: "MeanMugBot") -> None:
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
            await database.record_audit(self.bot.db, interaction.user.id, subject, case_id=case_id)
            await interaction.followup.send(f"⚠️ GLM analysis failed: `{exc}`", ephemeral=True)
            return

        await database.record_audit(
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
        person = await intel.enrich_person(self.bot.session, handles=[h])
        data = person["handles"].get(h, {})
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
        embed.set_footer(text=FOOTER_PEOPLE)
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
        added = await database.add_watch(self.bot.db, norm, kind.value, interaction.user.id, note)
        if added:
            await interaction.response.send_message(f"✅ watching `{norm}` (`{kind.value}`).")
        else:
            await interaction.response.send_message(
                f"_already watching `{norm}` (`{kind.value}`)._", ephemeral=True
            )

    @app_commands.command(name="unwatch", description="Remove an identifier from the watchlist.")
    @app_commands.describe(identifier="The identifier to stop watching.")
    async def unwatch(self, interaction: discord.Interaction, identifier: str) -> None:
        norm = identifier.strip().lstrip("@").lower()
        n = await database.remove_watch(self.bot.db, norm)
        if n:
            await interaction.response.send_message(f"✅ removed `{norm}` ({n} entries).")
        else:
            await interaction.response.send_message(f"_not watching `{norm}`._", ephemeral=True)

    @app_commands.command(name="watchlist", description="Show the current watchlist.")
    async def watchlist(self, interaction: discord.Interaction) -> None:
        rows = await database.list_watches(self.bot.db)
        if not rows:
            await interaction.response.send_message("_watchlist is empty_", ephemeral=True)
            return
        lines = [
            f"`{r[2]:>6}` `{r[1]}`" + (f" — {r[3]}" if r[3] else "") for r in rows
        ]
        body = "\n".join(lines)
        await interaction.response.send_message(f"**Watchlist ({len(rows)})**\n{body[:1900]}")

    async def _resolve_case_id(self, case: Optional[str]) -> Optional[int]:
        if not case:
            return None
        row = await database.get_case_by_name(self.bot.db, case)
        if row is None:
            raise app_commands.AppCommandError(f"case `{case}` does not exist.")
        if row[3] != "open":
            raise app_commands.AppCommandError(f"case `{case}` is {row[3]}.")
        return row[0]

    async def _dispatch_agentic(
        self,
        interaction: discord.Interaction,
        subject: str,
        agentic: AgenticResult,
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


# ============================== Cases cog ==================================


_CASE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,31}$")


class CasesCog(commands.Cog):
    """/case group — manage OSINT investigation cases."""

    case_group = app_commands.Group(name="case", description="Manage OSINT investigation cases.")

    def __init__(self, bot: "MeanMugBot") -> None:
        self.bot = bot

    @case_group.command(name="start", description="Open a new investigation case.")
    @app_commands.describe(name="Short slug: a-z, 0-9, _ and -, 2-32 chars.")
    async def start(self, interaction: discord.Interaction, name: str) -> None:
        if not _CASE_NAME_RE.match(name):
            await interaction.response.send_message(
                "⚠️ name must match `^[a-z0-9][a-z0-9_-]{1,31}$`", ephemeral=True
            )
            return
        if await database.get_case_by_name(self.bot.db, name):
            await interaction.response.send_message(
                f"⚠️ case `{name}` already exists.", ephemeral=True
            )
            return
        case_id = await database.create_case(self.bot.db, name, interaction.user.id)
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
        rows = await database.list_cases(self.bot.db, status=status.value if status else None)
        if not rows:
            await interaction.response.send_message("_no cases_", ephemeral=True)
            return
        body = "\n".join(f"`#{r[0]:>3}` **{r[1]}** — {r[2]} · {r[3]}" for r in rows)
        await interaction.response.send_message(f"**Cases**\n{body[:1900]}")

    @case_group.command(name="show", description="Show a case and its recent audits.")
    @app_commands.describe(name="The case name.")
    async def show(self, interaction: discord.Interaction, name: str) -> None:
        case = await database.get_case_by_name(self.bot.db, name)
        if case is None:
            await interaction.response.send_message(f"⚠️ no case `{name}`.", ephemeral=True)
            return
        audits = await database.case_audits(self.bot.db, case[0])
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
        case = await database.get_case_by_name(self.bot.db, name)
        if case is None:
            await interaction.response.send_message(f"⚠️ no case `{name}`.", ephemeral=True)
            return
        if case[3] == "closed":
            await interaction.response.send_message("_already closed_", ephemeral=True)
            return
        await database.close_case(self.bot.db, case[0])
        await interaction.response.send_message(f"✅ case `{name}` closed.")


# ============================== Ops cog ====================================


class OpsCog(commands.Cog):
    """/changelog, /backup, /health — operational invariants surface."""

    def __init__(self, bot: "MeanMugBot") -> None:
        self.bot = bot
        self.repo_root: Path = bot.repo_root
        self.changelog_path = self.repo_root / "CHANGELOG.md"

    @app_commands.command(name="changelog", description="Show the latest 10 changelog entries.")
    async def changelog(self, interaction: discord.Interaction) -> None:
        if not self.changelog_path.is_file():
            await interaction.response.send_message("⚠️ `CHANGELOG.md` not found.", ephemeral=True)
            return
        entries = ops.parse_changelog(self.changelog_path.read_text(encoding="utf-8"))[:10]
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
        target=[app_commands.Choice(name=f, value=f) for f in ops.ESSENTIAL_FILES]
    )
    async def backup(
        self,
        interaction: discord.Interaction,
        target: Optional[app_commands.Choice[str]] = None,
    ) -> None:
        await interaction.response.defer(ephemeral=True)
        try:
            result = ops.snapshot(self.repo_root, target=target.value if target else None)
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
            db_ok = await database.integrity_ok(self.bot.db)
        except Exception:
            log.exception("db integrity check failed")
            db_ok = False
        last_backup = ops.latest_snapshot_name(self.repo_root) or "_none_"
        try:
            audits_24h = await database.audits_count_since(self.bot.db, "-1 day")
        except Exception:
            audits_24h = 0

        glm_cfg = self.bot.config.glm
        cache_size = len(getattr(self.bot.glm, "_cache", {}))
        embed = discord.Embed(
            title="MeanMug-Agent Health",
            color=discord.Color.green() if db_ok else discord.Color.red(),
        )
        embed.add_field(name="Gateway latency", value=f"{latency_ms} ms")
        embed.add_field(name="DB integrity", value="ok" if db_ok else "**FAIL**")
        embed.add_field(name="Last backup", value=f"`{last_backup}`")
        embed.add_field(
            name="GLM",
            value=(
                f"`{glm_cfg.base_url}`\n"
                f"model `{glm_cfg.model}` · thinking `{glm_cfg.thinking}` · agentic tools enabled"
            ),
            inline=False,
        )
        embed.add_field(name="Audits (24h)", value=f"`{audits_24h}`", inline=True)
        embed.add_field(name="GLM cache", value=f"`{cache_size}` entries", inline=True)
        embed.set_footer(text=FOOTER_OPS)
        await interaction.followup.send(embed=embed)


# ============================== Intel stream listener ======================


class IntelStreamCog(commands.Cog):
    """Autonomous ingestion: react to watchlist hits in INTEL_CHANNEL_IDS."""

    def __init__(self, bot: "MeanMugBot") -> None:
        self.bot = bot
        self._seen: set[int] = set()

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message) -> None:
        if not self._should_handle(message):
            return
        if message.id in self._seen:
            return
        if len(self._seen) >= INTEL_SEEN_CAP:
            self._seen.clear()
        self._seen.add(message.id)

        scan_text = _message_text(message)
        if len(scan_text) < MIN_INTEL_MSG_LEN:
            return
        indicators = intel.extract_indicators(scan_text)
        hits = await database.watch_hits(self.bot.db, indicators)
        if not hits:
            return

        log.info(
            "intel hit in channel %s by %s: %s",
            message.channel.id,
            message.author,
            hits,
        )
        await self._react_and_analyze(message, indicators, hits)

    def _should_handle(self, message: discord.Message) -> bool:
        if self.bot.user and message.author.id == self.bot.user.id:
            return False
        if not message.guild:
            return False
        watched = self.bot.config.intel_channel_ids
        if not watched or message.channel.id not in watched:
            return False
        return True

    async def _react_and_analyze(
        self,
        message: discord.Message,
        indicators: dict[str, list[str]],
        hits: list[tuple[str, str]],
    ) -> None:
        try:
            await message.add_reaction("👀")
        except discord.HTTPException:
            log.debug("could not add reaction (missing perm or rate limit)")

        try:
            enrichment_on = self.bot.config.enrichment_enabled
            has_infra = bool(indicators["ips"] or indicators["domains"])
            infra = (
                await intel.enrich_indicators(self.bot.session, indicators)
                if enrichment_on and has_infra
                else {}
            )
            has_people = bool(indicators["handles"] or indicators["emails"])
            person = (
                await intel.enrich_person(
                    self.bot.session,
                    handles=indicators["handles"],
                    emails=indicators["emails"],
                )
                if enrichment_on and has_people
                else {}
            )
            subject = ", ".join(f"{i} ({k})" for i, k in hits)
            result = await self.bot.glm.analyze_person(
                subject=subject,
                person_intel=person,
                indicators=indicators,
                infra_enrichment=infra,
            )
        except GlmError as exc:
            log.warning("intel-stream GLM failed: %s", exc)
            return
        except Exception:
            log.exception("intel-stream pipeline failed")
            return

        await database.record_audit(
            self.bot.db,
            user_id=message.author.id,
            content=_message_text(message),
            analysis=result.content,
            reasoning=result.reasoning,
            usage=None if result.cached else result.usage,
        )
        await self._deliver(message, hits, result.content)

    async def _deliver(
        self,
        message: discord.Message,
        hits: list[tuple[str, str]],
        analysis: str,
    ) -> None:
        target_channel: Optional[discord.abc.Messageable] = None
        alert_id = self.bot.config.alert_channel_id
        if alert_id:
            target_channel = self.bot.get_channel(alert_id)
        if target_channel is None:
            target_channel = message.channel

        header = (
            f"🔔 **Watchlist hit** — {', '.join(f'`{i}`' for i, _ in hits)}\n"
            f"Source: {message.jump_url}"
        )
        try:
            await target_channel.send(header[:2000])
            for chunk in chunk_text(analysis):
                await target_channel.send(chunk)
        except discord.HTTPException:
            log.exception("failed to deliver intel-stream alert")


# ============================== Bot ========================================


COG_CLASSES = (OSINTCog, PeopleCog, CasesCog, OpsCog, IntelStreamCog)


class MeanMugBot(commands.Bot):
    """Core engine: lifecycle, gateway, shared HTTP + DB + GLM handles."""

    session: aiohttp.ClientSession
    db: aiosqlite.Connection
    glm: GlmClient

    def __init__(self, config: Config) -> None:
        # message_content is privileged but required: the bot listens on
        # INTEL_CHANNEL_IDS for sibling-bot messages and reasons over them.
        intents = discord.Intents.default()
        intents.message_content = True
        super().__init__(command_prefix=config.command_prefix, intents=intents)
        self.config = config
        self.repo_root = REPO_ROOT
        ops.verify_essentials(self.repo_root)

    async def setup_hook(self) -> None:
        self.session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(limit=self.config.http_pool_limit),
        )
        self.db = await database.open_db(self.config.database_path)
        self.glm = GlmClient(self.session, self.config.glm)
        await self._load_cogs()
        await self._sync_commands()
        try:
            result = ops.snapshot(self.repo_root)
            log.info("startup snapshot: %s", result)
        except Exception:
            log.exception("startup snapshot failed")
        log.info("gateway and intelligence fabric initialized")

    async def close(self) -> None:
        if getattr(self, "db", None) is not None:
            await self.db.close()
        if getattr(self, "session", None) is not None:
            await self.session.close()
        await super().close()

    async def _load_cogs(self) -> None:
        loaded = 0
        for cls in COG_CLASSES:
            try:
                await self.add_cog(cls(self))
                loaded += 1
                log.info("loaded cog %s", cls.__name__)
            except Exception:
                log.exception("failed to load cog %s; continuing", cls.__name__)
        if loaded == 0:
            raise RuntimeError("no cogs loaded; refusing to come up")

    async def _sync_commands(self) -> None:
        try:
            if self.config.guild_id:
                guild = discord.Object(id=self.config.guild_id)
                self.tree.copy_global_to(guild=guild)
                synced = await self.tree.sync(guild=guild)
                log.info("synced %d commands to guild %s", len(synced), self.config.guild_id)
            else:
                synced = await self.tree.sync()
                log.info("synced %d global commands", len(synced))
        except discord.HTTPException:
            log.exception("command sync failed; bot will run with stale commands")

    async def on_ready(self) -> None:
        log.info("logged in as %s (id=%s)", self.user, getattr(self.user, "id", "?"))

    async def start_bot(self) -> None:
        async with self:
            await self.start(self.config.discord_token)

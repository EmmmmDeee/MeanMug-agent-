from __future__ import annotations

import logging
from typing import Optional

import discord
from discord.ext import commands

from meanmug.services.discord_io import chunk_text
from meanmug.services.enrich import enrich_indicators
from meanmug.services.extract import extract_indicators
from meanmug.services.glm import GlmError
from meanmug.services.people import enrich_person
from meanmug.services.storage import record_audit, watch_hits

log = logging.getLogger(__name__)

# Hard cap on ingest analysis cost: skip messages shorter than this so we
# don't analyze every "ok" reply.
_MIN_MESSAGE_LEN = 16
# Don't analyze the same message twice on edit storms.
_SEEN_CAP = 4096


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


class IntelStreamCog(commands.Cog):
    """Autonomous ingestion: react to watchlist hits in intel channels."""

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self._seen: set[int] = set()

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message) -> None:
        if not self._should_handle(message):
            return
        if message.id in self._seen:
            return
        if len(self._seen) >= _SEEN_CAP:
            self._seen.clear()
        self._seen.add(message.id)

        scan_text = _message_text(message)
        if len(scan_text) < _MIN_MESSAGE_LEN:
            return
        indicators = extract_indicators(scan_text)
        hits = await watch_hits(self.bot.db, indicators)
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
                await enrich_indicators(self.bot.session, indicators)
                if enrichment_on and has_infra
                else {}
            )
            has_people = bool(indicators["handles"] or indicators["emails"])
            person = (
                await enrich_person(
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

        await record_audit(
            self.bot.db,
            user_id=message.author.id,
            content=_message_text(message),
            analysis=result.content,
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


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(IntelStreamCog(bot))

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
_seen: set[int] = set()
_SEEN_CAP = 4096


class IntelStreamCog(commands.Cog):
    """Autonomous ingestion: react to watchlist hits in intel channels."""

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message) -> None:
        if not self._should_handle(message):
            return
        if message.id in _seen:
            return
        if len(_seen) >= _SEEN_CAP:
            _seen.clear()
        _seen.add(message.id)

        indicators = extract_indicators(message.content)
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
        watched = self.bot.config.intel_channel_ids  # type: ignore[attr-defined]
        if not watched:
            return False
        if message.channel.id not in watched:
            return False
        if not message.content or len(message.content) < _MIN_MESSAGE_LEN:
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
            pass

        try:
            infra = await enrich_indicators(self.bot.session, indicators) if (
                self.bot.config.enrichment_enabled and (indicators["ips"] or indicators["domains"])  # type: ignore[attr-defined]
            ) else {}
            person = await enrich_person(
                self.bot.session,
                handles=indicators["handles"],
                emails=indicators["emails"],
            ) if self.bot.config.enrichment_enabled else {}  # type: ignore[attr-defined]

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
            content=message.content,
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
        alert_id = self.bot.config.alert_channel_id  # type: ignore[attr-defined]
        if alert_id:
            target_channel = self.bot.get_channel(alert_id)
        if target_channel is None:
            target_channel = message.channel

        chunks = chunk_text(analysis)
        header = (
            f"🔔 **Watchlist hit** — {', '.join(f'`{i}`' for i, _ in hits)}\n"
            f"Source: {message.jump_url}\n\n{chunks[0]}"
        )
        try:
            await target_channel.send(header[:2000])
            for chunk in chunks[1:]:
                await target_channel.send(chunk)
        except discord.HTTPException:
            log.exception("failed to deliver intel-stream alert")


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(IntelStreamCog(bot))

from __future__ import annotations

import logging
import pkgutil
from importlib import import_module
from pathlib import Path

import aiohttp
import aiosqlite
import discord
from discord.ext import commands

from meanmug import cogs
from meanmug.core.config import Config
from meanmug.services.backup import snapshot, verify_essentials
from meanmug.services.glm import GlmClient
from meanmug.services.storage import open_db

log = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]


class MeanMugBot(commands.Bot):
    """Core engine: lifecycle, gateway, shared HTTP + DB + GLM handles."""

    session: aiohttp.ClientSession
    db: aiosqlite.Connection
    glm: GlmClient

    def __init__(self, config: Config) -> None:
        # message_content is privileged but required: the bot listens on the
        # configured intel channels for messages posted by sibling bots
        # (OathNet Pro etc.) and reasons over them via GLM-5.1.
        intents = discord.Intents.default()
        intents.message_content = True
        super().__init__(command_prefix=config.command_prefix, intents=intents)
        self.config = config
        self.repo_root = REPO_ROOT
        verify_essentials(self.repo_root)

    async def setup_hook(self) -> None:
        self.session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(limit=self.config.http_pool_limit),
        )
        self.db = await open_db(self.config.database_path)
        self.glm = GlmClient(self.session, self.config.glm)
        await self._load_cogs()
        await self._sync_commands()
        try:
            result = snapshot(self.repo_root)
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
        for module_info in pkgutil.iter_modules(cogs.__path__):
            name = f"{cogs.__name__}.{module_info.name}"
            try:
                module = import_module(name)
                setup = getattr(module, "setup", None)
                if setup is None:
                    log.warning("cog %s has no setup(); skipping", name)
                    continue
                await setup(self)
                loaded += 1
                log.info("loaded cog %s", name)
            except Exception:
                log.exception("failed to load cog %s; continuing", name)
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

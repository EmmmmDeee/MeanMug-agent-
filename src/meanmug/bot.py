from __future__ import annotations

import logging
import pkgutil
from importlib import import_module

import aiohttp
import aiosqlite
import discord
from discord.ext import commands

from meanmug import cogs
from meanmug.core.config import Config
from meanmug.services.storage import open_db

log = logging.getLogger(__name__)


class MeanMugBot(commands.Bot):
    """Core engine: lifecycle, gateway, shared HTTP + DB handles."""

    session: aiohttp.ClientSession
    db: aiosqlite.Connection

    def __init__(self, config: Config) -> None:
        intents = discord.Intents.default()
        intents.message_content = True
        super().__init__(command_prefix=config.command_prefix, intents=intents)
        self.config = config

    async def setup_hook(self) -> None:
        self.session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(limit=self.config.http_pool_limit),
        )
        self.db = await open_db(self.config.database_path)
        await self._load_cogs()
        if self.config.guild_id:
            guild = discord.Object(id=self.config.guild_id)
            self.tree.copy_global_to(guild=guild)
            await self.tree.sync(guild=guild)
        else:
            await self.tree.sync()
        log.info("gateway and intelligence fabric initialized")

    async def close(self) -> None:
        if getattr(self, "db", None) is not None:
            await self.db.close()
        if getattr(self, "session", None) is not None:
            await self.session.close()
        await super().close()

    async def _load_cogs(self) -> None:
        for module_info in pkgutil.iter_modules(cogs.__path__):
            name = f"{cogs.__name__}.{module_info.name}"
            module = import_module(name)
            setup = getattr(module, "setup", None)
            if setup is None:
                continue
            await setup(self)
            log.info("loaded cog %s", name)

    async def on_ready(self) -> None:
        log.info("logged in as %s (id=%s)", self.user, getattr(self.user, "id", "?"))

    async def start_bot(self) -> None:
        async with self:
            await self.start(self.config.discord_token)

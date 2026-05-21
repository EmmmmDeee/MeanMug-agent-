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
        # Slash-only bot: default intents are sufficient. No privileged intents.
        super().__init__(command_prefix=config.command_prefix, intents=discord.Intents.default())
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
        if self.config.guild_id:
            guild = discord.Object(id=self.config.guild_id)
            self.tree.copy_global_to(guild=guild)
            await self.tree.sync(guild=guild)
        else:
            await self.tree.sync()
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

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    discord_token: str
    guild_id: int | None
    command_prefix: str
    log_level: str

    @classmethod
    def from_env(cls) -> "Config":
        token = os.environ.get("DISCORD_TOKEN")
        if not token:
            raise RuntimeError("DISCORD_TOKEN is required")
        guild_raw = os.environ.get("DISCORD_GUILD_ID")
        return cls(
            discord_token=token,
            guild_id=int(guild_raw) if guild_raw else None,
            command_prefix=os.environ.get("COMMAND_PREFIX", "!"),
            log_level=os.environ.get("LOG_LEVEL", "INFO"),
        )

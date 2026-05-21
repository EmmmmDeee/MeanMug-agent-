from __future__ import annotations

import os
from dataclasses import dataclass


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class GlmConfig:
    api_key: str
    base_url: str
    model: str
    timeout: int
    thinking: bool
    temperature: float


@dataclass(frozen=True)
class Config:
    discord_token: str
    guild_id: int | None
    command_prefix: str
    log_level: str
    database_path: str
    http_pool_limit: int
    glm: GlmConfig

    @classmethod
    def from_env(cls) -> "Config":
        token = os.environ.get("DISCORD_TOKEN")
        if not token:
            raise RuntimeError("DISCORD_TOKEN is required")
        api_key = os.environ.get("GLM_API_KEY")
        if not api_key:
            raise RuntimeError("GLM_API_KEY is required")
        guild_raw = os.environ.get("DISCORD_GUILD_ID")
        return cls(
            discord_token=token,
            guild_id=int(guild_raw) if guild_raw else None,
            command_prefix=os.environ.get("COMMAND_PREFIX", "!"),
            log_level=os.environ.get("LOG_LEVEL", "INFO"),
            database_path=os.environ.get("DATABASE_PATH", "intelligence.db"),
            http_pool_limit=int(os.environ.get("HTTP_POOL_LIMIT", "50")),
            glm=GlmConfig(
                api_key=api_key,
                base_url=os.environ.get("GLM_BASE_URL", "https://api.z.ai/api/paas/v4").rstrip("/"),
                model=os.environ.get("GLM_MODEL", "glm-4.6"),
                timeout=int(os.environ.get("GLM_TIMEOUT", "120")),
                thinking=_env_bool("GLM_THINKING", True),
                temperature=float(os.environ.get("GLM_TEMPERATURE", "0.3")),
            ),
        )

from __future__ import annotations

import asyncio
import logging
import sys

import discord

from meanmug.bot import MeanMugBot
from meanmug.core.config import Config
from meanmug.core.logging import configure_logging
from meanmug.services.backup import MissingEssentialError

log = logging.getLogger("meanmug")


def main() -> int:
    try:
        config = Config.from_env()
    except RuntimeError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        print(
            "Set the required values in .env (see .env.example) and try again.",
            file=sys.stderr,
        )
        return 2

    configure_logging(config.log_level)

    try:
        bot = MeanMugBot(config)
    except MissingEssentialError as exc:
        log.error("%s", exc)
        log.error("Refusing to start. Run from the repo root or set MEANMUG_SYSTEM_PROMPT_PATH.")
        return 3
    except FileNotFoundError as exc:
        log.error("%s", exc)
        return 3

    try:
        asyncio.run(bot.start_bot())
        return 0
    except KeyboardInterrupt:
        log.info("interrupted; shutting down")
        return 0
    except discord.LoginFailure:
        log.error("Discord rejected the token. Verify DISCORD_TOKEN in .env.")
        return 4
    except discord.PrivilegedIntentsRequired:
        log.error(
            "Privileged intents required. In the Discord Developer Portal, "
            "open your application → Bot → enable MESSAGE CONTENT INTENT."
        )
        return 5
    except Exception:
        log.exception("fatal error in bot runtime")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

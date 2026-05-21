from __future__ import annotations

import asyncio

from meanmug.core.config import Config
from meanmug.core.logging import configure_logging
from meanmug.bot import MeanMugBot


def main() -> None:
    config = Config.from_env()
    configure_logging(config.log_level)
    bot = MeanMugBot(config)
    asyncio.run(bot.start_bot())


if __name__ == "__main__":
    main()

# MeanMug

Discord-native agent bot. Discord is the sole interface — no web UI, no HTTP API.

## Layout

```
src/meanmug/
  __main__.py      entry point
  bot.py           discord.py Bot subclass; auto-loads cogs
  core/
    config.py      env -> Config dataclass
    logging.py     stdlib logging setup
  cogs/            one module per command group; auto-discovered
    general.py     /ping
  services/        business logic, no Discord types
```

Add a feature by dropping a new module under `cogs/` with an
`async def setup(bot): ...` that registers commands. The bot
discovers it on startup — no central registry to edit.

Keep Discord-aware code in `cogs/` and Discord-agnostic logic
in `services/`.

## Run

```
cp .env.example .env   # fill in DISCORD_TOKEN
pip install -e .
meanmug
```

Set `DISCORD_GUILD_ID` to sync slash commands to a single guild
during development (instant); leave unset for global sync.

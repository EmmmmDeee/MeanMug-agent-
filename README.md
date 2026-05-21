# MeanMug-Agent

Discord-native OSINT bot. Discord is the sole interface — no web UI, no
HTTP API, no frontend assets.

## Layout

```
src/meanmug/
  __main__.py         entry point
  bot.py              Bot subclass; owns aiohttp session + aiosqlite conn; auto-loads cogs
  core/
    config.py         env -> Config
    logging.py        stdlib logging setup
  cogs/               one module per command group; auto-discovered
    osint.py          /osint — extracts indicators, persists audit, replies with embed
  services/           Discord-agnostic logic
    extract.py        regex extraction of IPs, domains, emails
    storage.py        sqlite schema + audit writes
```

### Separation of concerns

- `bot.py` owns process lifecycle and shared handles (`session`, `db`).
- `cogs/` translate Discord interactions to service calls.
- `services/` are pure async functions over standard types — no Discord
  imports — so they're trivial to unit test and reuse across cogs.

### Adding a feature

Drop a new module under `cogs/` exposing `async def setup(bot): ...`.
The bot discovers it on startup; no central registry to edit.

## Run

```
cp .env.example .env       # set DISCORD_TOKEN
pip install -e .
meanmug
```

Set `DISCORD_GUILD_ID` to sync slash commands to a single guild during
development (instant); leave unset for global sync (~1 hour propagation).

## Dependencies

Three runtime packages, all async:

- `discord.py` — gateway + slash commands
- `aiohttp` — outbound HTTP (pooled, ready for external intel APIs)
- `aiosqlite` — local audit persistence

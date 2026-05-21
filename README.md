# MeanMug-Agent

Discord-native OSINT analyst. Reasoning core is **GLM-5.1** over the
**z.ai chat endpoint**. Discord is the sole interface — no web UI, no
HTTP API, no DMs, no webhooks.

The canonical system prompt is [`SYSTEM_PROMPT.md`](SYSTEM_PROMPT.md);
the operational log is [`CHANGELOG.md`](CHANGELOG.md).

## Commands

| Command | Purpose |
| --- | --- |
| `/osint <input> [file] [case]` | Primary analysis. Regex-extract indicators, then run GLM-5.1 with the OSINT prompt. |
| `/pivot <indicator> [case]` | Pursue every downstream lead from one indicator. |
| `/history [limit]` | Your recent audits (ephemeral). |
| `/case start <name>` | Open a new investigation case. |
| `/case list [status]` | List recent cases. |
| `/case show <name>` | Case details and recent audits. |
| `/case close <name>` | Close a case. |
| `/changelog` | Latest 10 entries from `CHANGELOG.md`. |
| `/backup [target]` | Snapshot essential config files. |
| `/health` | Gateway latency, DB integrity, GLM endpoint, last backup. |

Every analytical command defers with `thinking=True` so GLM has the
full Discord 15-minute interaction window for long-horizon reasoning.

## Architecture

```
src/meanmug/
  __main__.py         entry point
  bot.py              Bot subclass; verifies essentials on init; opens
                      aiohttp + aiosqlite + GLM client in setup_hook;
                      auto-discovers cogs; auto-snapshots configs
  core/
    config.py         env -> Config + nested GlmConfig
    logging.py        stdlib logging
  cogs/
    osint.py          /osint, /pivot, /history; app-command error handler
    cases.py          /case start|list|show|close
    ops.py            /changelog, /backup, /health
  services/           Discord-agnostic, individually testable
    extract.py        IP / domain / email regex
    glm.py            GLM-5.1 client; loads SYSTEM_PROMPT.md at import
    discord_io.py     2000-char-safe paragraph-aware text chunker
    storage.py        SQLite schema + audit and case helpers
    backup.py         Essential-file verification + content-hashed snapshots
```

### Layering

- `bot.py` owns process lifecycle and shared handles.
- `cogs/` translate Discord events to service calls — no business logic.
- `services/` is pure Python over standard types — zero Discord imports
  — so every piece is unit-testable in isolation.

### Operational invariants

1. **Refuses to start** if any of `SYSTEM_PROMPT.md`, `.env.example`,
   `pyproject.toml`, `core/config.py`, `services/glm.py`, or
   `services/storage.py` is missing.
2. **Auto-snapshots** the essential set on every successful startup
   into `backups/<UTC-timestamp>/`, content-hashed so no-op runs do
   nothing.
3. **Audit trail.** Every command and every GLM call writes to SQLite
   `audits` (append-only), optionally linked to a case.
4. **No web surface.** Outbound only: Discord gateway + z.ai HTTP.
5. **Sole GLM endpoint.** Reasoning goes only to the configured z.ai
   chat completions URL.

## Run

```
cp .env.example .env       # set DISCORD_TOKEN and GLM_API_KEY
pip install -e .
meanmug
```

Set `DISCORD_GUILD_ID` for instant slash-command sync during development;
omit for global sync.

## GLM-5.1 configuration

| Env var | Purpose | Default |
| --- | --- | --- |
| `GLM_API_KEY` | bearer token | (required) |
| `GLM_BASE_URL` | OpenAI-compatible root | `https://api.z.ai/api/paas/v4` |
| `GLM_MODEL` | model id | `glm-4.6` |
| `GLM_TIMEOUT` | per-request seconds | `120` |
| `GLM_THINKING` | enable extended reasoning | `true` |
| `GLM_TEMPERATURE` | sampling temperature | `0.3` |

## Dependencies

Three runtime packages, all async:

- `discord.py` — gateway + slash commands
- `aiohttp` — GLM HTTP transport (pooled)
- `aiosqlite` — local audits + case persistence

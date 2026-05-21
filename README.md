# MeanMug-Agent

Discord-native OSINT bot powered by GLM-5.1. Discord is the sole
interface — no web UI, no HTTP API, no frontend.

## What it does

`/osint <input_data> [file]`

1. Ingests free-text plus an optional UTF-8 file attachment.
2. Regex-extracts IPs, domains, and emails locally.
3. Sends raw + pre-extracted indicators to GLM-5.1 (thinking mode) with
   an OSINT-analyst system prompt that enforces structured Markdown
   output: Classification → Threat Level → Key Findings → Pivots →
   Caveats.
4. Persists an audit row (input + analysis) to SQLite.
5. Replies with an embed header (extracted indicators + start of the
   report) plus chunked follow-up messages — staying inside Discord's
   2000-char message cap without ever truncating reasoning.

The command defers with `thinking=True`, giving GLM the full 15-minute
interaction window to reason on harder inputs.

## Layout

```
src/meanmug/
  __main__.py         entry point
  bot.py              Bot subclass; owns aiohttp session, aiosqlite conn,
                      GLM client; auto-loads cogs
  core/
    config.py         env -> Config (+ nested GlmConfig)
    logging.py        stdlib logging setup
  cogs/
    osint.py          /osint slash command, error handler, output chunking
  services/           Discord-agnostic, individually testable
    extract.py        IP / domain / email regex
    glm.py            GLM-5.1 client (OpenAI-compatible chat.completions)
    discord_io.py     2000-char-safe text chunker
    storage.py        SQLite schema + audit writes
```

`bot.py` owns shared handles. `cogs/` only translates Discord events to
service calls. `services/` has zero Discord imports, so each piece is
unit-testable in isolation.

## Run

```
cp .env.example .env       # set DISCORD_TOKEN and GLM_API_KEY
pip install -e .
meanmug
```

Set `DISCORD_GUILD_ID` to sync slash commands to a single guild during
development (instant); leave unset for global sync.

## GLM-5.1 configuration

| Env var | Purpose | Default |
| --- | --- | --- |
| `GLM_API_KEY` | bearer token | (required) |
| `GLM_BASE_URL` | OpenAI-compatible root, no trailing `/chat/completions` | `https://api.z.ai/api/paas/v4` |
| `GLM_MODEL` | model id | `glm-4.6` |
| `GLM_TIMEOUT` | per-request seconds | `120` |
| `GLM_THINKING` | enable extended reasoning | `true` |
| `GLM_TEMPERATURE` | sampling temperature | `0.3` |

Any OpenAI-compatible GLM deployment works; only the base URL and model
id change. The `thinking` field is sent only when enabled, so providers
that don't recognise it can ignore it without erroring.

## Dependencies

Three runtime packages, all async:

- `discord.py` — gateway + slash commands
- `aiohttp` — GLM HTTP transport (pooled)
- `aiosqlite` — local audit persistence

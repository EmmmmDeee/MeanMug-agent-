# MeanMug-Agent

Discord-native OSINT analyst. Reasoning core is **GLM-5.1** over the
**z.ai chat endpoint**. Discord is the sole interface — no web UI, no
HTTP API, no DMs, no webhooks.

The canonical system prompt is [`SYSTEM_PROMPT.md`](SYSTEM_PROMPT.md);
the operational log is [`CHANGELOG.md`](CHANGELOG.md).

## Commands

| Command | Purpose |
| --- | --- |
**Infrastructure**
| `/osint <input> [file] [case]` | Regex-extract + live enrichment + GLM analysis. |
| `/pivot <indicator> [case]` | Recursive downstream lead pursuit. |

**People**
| `/investigate <subject> [case]` | Identity correlation across GitHub/GitLab/HN/Gravatar + GLM. |
| `/trace <handle>` | Fast keyless username lookup; embed-only. |

**Watchlist & live ingestion**
| `/watch <identifier> <kind> [note]` | Add `handle`/`email`/`domain`/`ip` to the watchlist. |
| `/unwatch <identifier>` | Remove from watchlist. |
| `/watchlist` | Show what's being watched. |
| _(autonomous)_ | Messages in `INTEL_CHANNEL_IDS` are scanned; on a watchlist hit, MeanMug reacts 👀, runs analysis, posts to source channel or `ALERT_CHANNEL_ID`. |

**Cases & ops**
| `/history [case] [limit]` | Your recent audits, optionally case-filtered. |
| `/case start \| list \| show \| close` | Investigation case lifecycle. |
| `/changelog` | Latest 10 entries from `CHANGELOG.md`. |
| `/backup [target]` | Snapshot essential config files. |
| `/health` | Gateway latency, DB integrity, GLM endpoint, last backup. |

Every analytical command defers with `thinking=True` so GLM has the
full Discord 15-minute interaction window for long-horizon reasoning.

## Architecture

```
src/meanmug/
  __init__.py     version string
  __main__.py     entry point + exit codes
  config.py       env loader, Config + GlmConfig dataclasses, logging setup
  database.py     SQLite schema + audit / case / watchlist helpers
  intel.py        regex extraction · DoH/RDAP/geo/Tor infra lookups
                  · GitHub/GitLab/HN/Gravatar people lookups · TTL cache
  glm.py          GlmClient: pre-enriched chat + agentic loop · tool catalog
                  · response cache · prompt-directive extraction
  ops.py          essential-file verification · content-hashed snapshots
                  · CHANGELOG parser
  bot.py          MeanMugBot · OSINTCog · PeopleCog · CasesCog · OpsCog
                  · IntelStreamCog · Discord helpers (chunker, color, etc.)
```

8 files, ~2,350 LOC. Concerns are grouped by stack layer:
- `config` / `database` / `intel` / `glm` / `ops` have **zero Discord
  imports** — every piece is unit-testable in isolation.
- `bot.py` is the entire Discord-facing surface: the Bot subclass plus
  all five cogs and the small UI helpers (chunker, color, footer).
- `__main__.py` is just the entry point; it wires `Config` → `MeanMugBot`
  → asyncio loop with friendly exit codes.

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

## Deploy

### 1. Discord Developer Portal

1. Create an app at https://discord.com/developers/applications.
2. **Bot** tab: create a bot, copy the token → `DISCORD_TOKEN`.
3. **Bot** tab → Privileged Gateway Intents: enable **MESSAGE CONTENT INTENT** (required to read sibling-bot messages in intel channels).
4. **OAuth2 → URL Generator**: scopes `bot` + `applications.commands`; bot permissions: `Send Messages`, `Embed Links`, `Add Reactions`, `Read Message History`. Invite to your server.

### 2. z.ai GLM-5.1

Get an API key from https://z.ai. The default `GLM_BASE_URL` and `GLM_MODEL` work for z.ai's standard chat endpoint.

### 3. Install and run

```
cp .env.example .env       # fill DISCORD_TOKEN, GLM_API_KEY
pip install -e .
meanmug
```

The bot must be run from the repository root (or set `MEANMUG_SYSTEM_PROMPT_PATH`) so it can find `SYSTEM_PROMPT.md`. On first run it verifies essential files, opens the SQLite store, takes a config snapshot into `backups/`, then syncs slash commands.

`DISCORD_GUILD_ID=<id>` makes slash-command sync instant per guild — recommended during development. Leave it unset for global sync (≈1 hr propagation).

### 4. Wire up live ingestion (optional)

```
INTEL_CHANNEL_IDS=123,456    # comma-separated channel IDs to listen on
ALERT_CHANNEL_ID=789         # optional: where to post autonomous alerts
```

Then in Discord:

```
/watch identifier:badactor kind:handle note:apt-of-interest
/watch identifier:evil.io   kind:domain
```

Anything a sibling bot posts in `123` or `456` that mentions `@badactor` or `evil.io` triggers MeanMug.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Normal shutdown (Ctrl+C) |
| 1 | Unexpected runtime error (check logs) |
| 2 | Missing required env var |
| 3 | Essential config file missing (`SYSTEM_PROMPT.md` etc.) |
| 4 | Discord rejected the token |
| 5 | Privileged intents not enabled in Developer Portal |

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
- `aiohttp` — GLM HTTP transport + enrichment lookups (pooled)
- `aiosqlite` — local audits + case persistence

Dev:

```
pip install -e .[dev]
pytest -q
```

## Enrichment pipeline

On every `/osint` or `/pivot`, indicators are enriched concurrently
against keyless public sources before reaching GLM:

| Source | Fields | Lookups |
| --- | --- | --- |
| Cloudflare DoH | A / AAAA / MX / NS / TXT / PTR | DNS for domains, rDNS for IPs |
| `rdap.org` | network name, country, registrar, registration dates, nameservers | IPs + domains |
| `ipwho.is` | country, region, city, ASN, ISP, proxy flag | IPs |
| Tor Project exit list | exit-node membership | IPs |

Results are TTL-cached (1h for lookups, 6h for the Tor list). Per-user
cooldowns (1 use / 20 s) on the GLM-hitting commands cap token spend.
Each request encodes the enrichment as a JSON block in the user
message; GLM is instructed to cite specific fields (`ptr`, `asn`,
`registrar`, `tor_exit`, …) rather than hedge them as unknown.

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
    people.py         /investigate, /trace, /watch, /unwatch, /watchlist
    intel_stream.py   on_message listener — autonomous trigger on watch hits
    ops.py            /changelog, /backup, /health
  services/           Discord-agnostic, individually testable
    extract.py        IP / domain / email / @handle regex
    enrich.py         Infra lookups: DoH DNS, RDAP, IP geo/ASN, Tor exits
    people.py         Identity lookups: GitHub, GitLab, HackerNews, Gravatar
    glm.py            GLM-5.1 client; loads SYSTEM_PROMPT.md at import
    discord_io.py     2000-char-safe paragraph-aware text chunker
    storage.py        SQLite schema + audits, cases, watchlist helpers
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

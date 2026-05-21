# Changelog

All material changes to MeanMug-Agent behavior, prompts, schema, or
config. Reverse-chronological. Each entry: date (UTC), one-line
summary, commit SHA.

## 2026-05-21
- `719cfff` — End-to-end production fixes: lazy SYSTEM_PROMPT.md loading (env-overridable, CWD-aware, falls back to repo root); GlmClient surfaces network and malformed-response errors as `GlmError`; backup snapshot `mkdir` tolerates same-second races; intel-stream sends header and analysis as separate messages so nothing is truncated; GLM user block now includes extracted handles; `__main__` traps `LoginFailure`, `PrivilegedIntentsRequired`, and `MissingEssentialError` with friendly messages and dedicated exit codes; tests run from any CWD; new `test_glm_errors.py` covers the 4xx, malformed-body, and empty-content paths; README gains a full deployment guide.
- `34a156d` — People-centric autonomous OSINT: `/investigate`, `/trace`, `/watch`, `/unwatch`, `/watchlist`; new `intel_stream` cog listens on `INTEL_CHANNEL_IDS` for sibling-bot messages and triggers GLM analysis on watchlist hits; people-OSINT service (GitHub/GitLab/HackerNews/Gravatar); handle extraction; watchlist table; `message_content` intent re-enabled to ingest sibling-bot messages (Discord is the data bus, not HTTP).
- `450abc4` — Drop unused `message_content` privileged intent; add `ENRICHMENT_ENABLED` toggle for sensitive operations; `/history` gains a `case:` filter; reconcile `SYSTEM_PROMPT.md` with the actual command surface (no `/case append`); add GitHub Actions test workflow.
- `9f10cca` — Add keyless live OSINT enrichment (DoH DNS, RDAP, IP geo/ASN, Tor exit list); GLM receives enrichment block alongside indicators; per-user cooldowns on `/osint` + `/pivot`; pytest suite for pure services; SYSTEM_PROMPT.md updated to direct GLM to cite enrichment fields rather than caveat them.
- `d33e6f6` — Implement spec-mandated commands and startup invariants: `/pivot`, `/history`, `/case start|list|show|close`, `/changelog`, `/backup`, `/health`; refuse start when essential files missing; auto-snapshot configs on startup; audits gain `case_id` and `refusal` columns.
- `dcd2d8e` — Add `SYSTEM_PROMPT.md` as the canonical agent spec; load it from `glm.py`; seed this changelog. Establishes the changelog + config-backup invariants.
- `3d93885` — Wire GLM-5.1 as the OSINT analysis engine; chunked Discord output; audits store input + analysis.
- `1f30992` — Wire OSINT cog onto shared `aiohttp` session + `aiosqlite` connection; centralised app-command error handler.
- `c0c6718` — Scaffold Discord-native MeanMug-Agent; modular `core/`, `cogs/`, `services/` layout; auto-discovered cogs.

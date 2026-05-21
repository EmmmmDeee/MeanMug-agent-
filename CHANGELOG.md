# Changelog

All material changes to MeanMug-Agent behavior, prompts, schema, or
config. Reverse-chronological. Each entry: date (UTC), one-line
summary, commit SHA.

## 2026-05-21
- `dcd2d8e` — Add `SYSTEM_PROMPT.md` as the canonical agent spec; load it from `glm.py`; seed this changelog. Establishes the changelog + config-backup invariants.
- `3d93885` — Wire GLM-5.1 as the OSINT analysis engine; chunked Discord output; audits store input + analysis.
- `1f30992` — Wire OSINT cog onto shared `aiohttp` session + `aiosqlite` connection; centralised app-command error handler.
- `c0c6718` — Scaffold Discord-native MeanMug-Agent; modular `core/`, `cogs/`, `services/` layout; auto-discovered cogs.

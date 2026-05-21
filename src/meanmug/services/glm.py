from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import aiohttp

from meanmug.core.config import GlmConfig

log = logging.getLogger(__name__)

_MAX_ENRICHMENT_CHARS = 4000


def _candidate_prompt_paths() -> list[Path]:
    """Locations to search for SYSTEM_PROMPT.md, in priority order."""
    env_override = os.environ.get("MEANMUG_SYSTEM_PROMPT_PATH")
    candidates: list[Path] = []
    if env_override:
        candidates.append(Path(env_override))
    candidates.append(Path.cwd() / "SYSTEM_PROMPT.md")
    # src/meanmug/services/glm.py → parents[3] is the repo root for editable installs
    candidates.append(Path(__file__).resolve().parents[3] / "SYSTEM_PROMPT.md")
    return candidates


def load_system_prompt() -> str:
    """Read SYSTEM_PROMPT.md from the first existing candidate path.

    Resolved lazily (not at module import) so that test runners and packaging
    layouts that don't have the file at parents[3] still work.
    """
    for path in _candidate_prompt_paths():
        if path.is_file():
            return path.read_text(encoding="utf-8")
    raise FileNotFoundError(
        "SYSTEM_PROMPT.md not found. Set MEANMUG_SYSTEM_PROMPT_PATH or run "
        "the bot from the repository root."
    )


@dataclass(frozen=True)
class GlmResult:
    content: str
    reasoning: str | None


class GlmError(RuntimeError):
    pass


class GlmClient:
    """Thin async wrapper over an OpenAI-compatible chat.completions endpoint."""

    def __init__(self, session: aiohttp.ClientSession, config: GlmConfig) -> None:
        self._session = session
        self._config = config
        self._system_prompt = load_system_prompt()

    @property
    def system_prompt(self) -> str:
        return self._system_prompt

    async def analyze_osint(
        self,
        raw: str,
        indicators: dict[str, list[str]],
        enrichment: dict[str, Any] | None = None,
    ) -> GlmResult:
        user_block = self._render_user_block(raw, indicators, enrichment)
        return await self._chat(system=self._system_prompt, user=user_block)

    async def analyze_person(
        self,
        subject: str,
        person_intel: dict[str, Any],
        indicators: dict[str, list[str]],
        infra_enrichment: dict[str, Any] | None = None,
    ) -> GlmResult:
        focus = (
            f"PERSON FOCUS — Subject: `{subject}`. The Person Intel block contains "
            "results from keyless public lookups (GitHub, GitLab, HackerNews, Gravatar). "
            "Build a digital-footprint report: identity correlation across platforms, "
            "consistent biographical signals, name/location/employer hints, linked "
            "accounts, and confidence-rated pivots for further investigation by "
            "sibling intel bots.\n\n"
        )
        parts = [focus, self._render_user_block(subject, indicators, infra_enrichment)]
        if person_intel:
            blob = json.dumps(person_intel, indent=2, sort_keys=True, default=str)
            if len(blob) > _MAX_ENRICHMENT_CHARS:
                blob = blob[:_MAX_ENRICHMENT_CHARS] + "\n... (truncated)"
            parts.append("")
            parts.append("Person intel (treat as authoritative for this run):")
            parts.append("```json")
            parts.append(blob)
            parts.append("```")
        return await self._chat(system=self._system_prompt, user="\n".join(parts))

    async def analyze_pivot(
        self,
        indicator: str,
        indicators: dict[str, list[str]],
        enrichment: dict[str, Any] | None = None,
    ) -> GlmResult:
        focus = (
            f"PIVOT FOCUS — Treat `{indicator}` as the sole anchor. "
            "Enumerate downstream pivots recursively until each branch resolves "
            "or hits a documented dead end. Be exhaustive within the report cap.\n\n"
        )
        user_block = focus + self._render_user_block(indicator, indicators, enrichment)
        return await self._chat(system=self._system_prompt, user=user_block)

    async def _chat(self, *, system: str, user: str) -> GlmResult:
        payload: dict[str, object] = {
            "model": self._config.model,
            "temperature": self._config.temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if self._config.thinking:
            payload["thinking"] = {"type": "enabled"}

        url = f"{self._config.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self._config.api_key}",
            "Content-Type": "application/json",
        }
        timeout = aiohttp.ClientTimeout(total=self._config.timeout)

        try:
            async with self._session.post(
                url, json=payload, headers=headers, timeout=timeout
            ) as resp:
                if resp.status >= 400:
                    body = await resp.text()
                    raise GlmError(f"GLM HTTP {resp.status}: {body[:500]}")
                data = await resp.json()
        except aiohttp.ClientError as exc:
            raise GlmError(f"GLM network error: {exc}") from exc

        try:
            choice = data["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise GlmError(f"GLM response malformed: {str(data)[:200]}") from exc

        content = (choice.get("content") or "").strip()
        reasoning = choice.get("reasoning_content") or choice.get("reasoning")
        if not content:
            raise GlmError("GLM returned empty content")
        return GlmResult(content=content, reasoning=reasoning)

    @staticmethod
    def _render_user_block(
        raw: str,
        indicators: dict[str, list[str]],
        enrichment: dict[str, Any] | None,
    ) -> str:
        def fmt(values: list[str]) -> str:
            return ", ".join(values) if values else "(none)"

        parts = [
            "Pre-extracted indicators:",
            f"- IPs: {fmt(indicators.get('ips', []))}",
            f"- Domains: {fmt(indicators.get('domains', []))}",
            f"- Emails: {fmt(indicators.get('emails', []))}",
            f"- Handles: {fmt(indicators.get('handles', []))}",
        ]
        if enrichment:
            blob = json.dumps(enrichment, indent=2, sort_keys=True, default=str)
            if len(blob) > _MAX_ENRICHMENT_CHARS:
                blob = blob[:_MAX_ENRICHMENT_CHARS] + "\n... (truncated)"
            parts.append("")
            parts.append("Live enrichment (fresh lookups; treat as authoritative for this run):")
            parts.append("```json")
            parts.append(blob)
            parts.append("```")
        parts.append("")
        parts.append("Operator input:")
        parts.append(raw.strip())
        return "\n".join(parts)

from __future__ import annotations

import logging
from dataclasses import dataclass

import aiohttp

from meanmug.core.config import GlmConfig

log = logging.getLogger(__name__)

OSINT_SYSTEM_PROMPT = """\
You are MeanMug, a focused OSINT analyst operating inside Discord.

Your input is a free-text intelligence dump from an operator, plus a list of
indicators (IPs, domains, emails) pre-extracted by regex.

Produce a tight Markdown report with exactly these sections, in order:

**Classification** — one of: IP / Domain / Email / Alias / Mixed / Insufficient.
**Threat Level** — one of: CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN, with a one-line justification.
**Key Findings** — 3-6 bullet points, each ≤ 25 words. Cite indicators inline using backticks.
**Pivots** — 2-4 concrete next steps an analyst should take (lookups, datasets, queries).
**Caveats** — what you do NOT know; flag anything that needs corroboration.

Hard rules:
- Never fabricate WHOIS, geolocation, ASN, or breach data. If you do not have
  it, say so in Caveats.
- Be terse. No preambles, no apologies, no restating the input.
- Output plain Markdown. No JSON, no code fences around the whole report.
- Stay under 1800 characters total so the report fits Discord cleanly.
"""


@dataclass(frozen=True)
class GlmResult:
    content: str
    reasoning: str | None


class GlmClient:
    """Thin async wrapper over an OpenAI-compatible chat.completions endpoint."""

    def __init__(self, session: aiohttp.ClientSession, config: GlmConfig) -> None:
        self._session = session
        self._config = config

    async def analyze_osint(self, raw: str, indicators: dict[str, list[str]]) -> GlmResult:
        user_block = self._render_user_block(raw, indicators)
        return await self._chat(system=OSINT_SYSTEM_PROMPT, user=user_block)

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

        async with self._session.post(url, json=payload, headers=headers, timeout=timeout) as resp:
            if resp.status >= 400:
                body = await resp.text()
                raise GlmError(f"GLM HTTP {resp.status}: {body[:500]}")
            data = await resp.json()

        choice = data["choices"][0]["message"]
        content = (choice.get("content") or "").strip()
        reasoning = choice.get("reasoning_content") or choice.get("reasoning")
        if not content:
            raise GlmError("GLM returned empty content")
        return GlmResult(content=content, reasoning=reasoning)

    @staticmethod
    def _render_user_block(raw: str, indicators: dict[str, list[str]]) -> str:
        def fmt(values: list[str]) -> str:
            return ", ".join(values) if values else "(none)"

        return (
            "Pre-extracted indicators:\n"
            f"- IPs: {fmt(indicators.get('ips', []))}\n"
            f"- Domains: {fmt(indicators.get('domains', []))}\n"
            f"- Emails: {fmt(indicators.get('emails', []))}\n"
            "\nOperator input:\n"
            f"{raw.strip()}"
        )


class GlmError(RuntimeError):
    pass

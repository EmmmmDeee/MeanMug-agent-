from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import aiohttp

from meanmug.core.config import GlmConfig

log = logging.getLogger(__name__)

_PROMPT_FILE = Path(__file__).resolve().parents[3] / "SYSTEM_PROMPT.md"


def load_system_prompt() -> str:
    if not _PROMPT_FILE.is_file():
        raise FileNotFoundError(
            f"essential config missing: {_PROMPT_FILE}. Refusing to start."
        )
    return _PROMPT_FILE.read_text(encoding="utf-8")


OSINT_SYSTEM_PROMPT = load_system_prompt()


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

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import aiohttp

from meanmug.core.config import GlmConfig
from meanmug.services.tools import DISPATCH, TOOL_SCHEMAS, execute_tool_call

log = logging.getLogger(__name__)

_MAX_ENRICHMENT_CHARS = 4000
_DIRECTIVE_BEGIN = "<!-- glm:directive:begin -->"
_DIRECTIVE_END = "<!-- glm:directive:end -->"

# Response cache: SHA-256(system + user) -> (expiry_monotonic, GlmResult)
_CACHE_TTL_SECONDS = 60 * 60
_CACHE_CAP = 1000


def _candidate_prompt_paths() -> list[Path]:
    env_override = os.environ.get("MEANMUG_SYSTEM_PROMPT_PATH")
    candidates: list[Path] = []
    if env_override:
        candidates.append(Path(env_override))
    candidates.append(Path.cwd() / "SYSTEM_PROMPT.md")
    candidates.append(Path(__file__).resolve().parents[3] / "SYSTEM_PROMPT.md")
    return candidates


def _extract_directive(text: str) -> str:
    """Return the model-facing region between markers, or the whole file.

    Matches only markers that occupy their own line (so references to the
    markers in surrounding prose don't break extraction).
    """
    begin_line = f"\n{_DIRECTIVE_BEGIN}\n"
    end_line = f"\n{_DIRECTIVE_END}\n"
    begin = text.find(begin_line)
    end = text.find(end_line)
    if begin >= 0 and end > begin:
        return text[begin + len(begin_line) : end].strip()
    return text.strip()


def load_system_prompt() -> str:
    """Read SYSTEM_PROMPT.md and return the GLM-facing directive."""
    for path in _candidate_prompt_paths():
        if path.is_file():
            return _extract_directive(path.read_text(encoding="utf-8"))
    raise FileNotFoundError(
        "SYSTEM_PROMPT.md not found. Set MEANMUG_SYSTEM_PROMPT_PATH or run "
        "the bot from the repository root."
    )


@dataclass(frozen=True)
class GlmResult:
    content: str
    reasoning: str | None
    usage: tuple[int, int] | None  # (prompt_tokens, completion_tokens)
    cached: bool = False


@dataclass
class ToolCallRecord:
    name: str
    arguments: dict[str, Any]
    result: dict[str, Any]


@dataclass
class AgenticResult:
    content: str
    reasoning: str | None
    turns: int
    tool_calls: list[ToolCallRecord] = field(default_factory=list)
    hit_turn_cap: bool = False


class GlmError(RuntimeError):
    pass


class GlmClient:
    """Thin async wrapper over an OpenAI-compatible chat.completions endpoint.

    Adds an in-memory response cache (SHA-256 keyed on system+user, TTL 1h,
    FIFO eviction at 1000 entries) so repeat /osint or /pivot on the same
    indicator within an hour doesn't burn tokens.
    """

    def __init__(self, session: aiohttp.ClientSession, config: GlmConfig) -> None:
        self._session = session
        self._config = config
        self._system_prompt = load_system_prompt()
        self._cache: dict[str, tuple[float, GlmResult]] = {}

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

    async def chat_with_tools(
        self,
        user_message: str,
        max_turns: int = 8,
    ) -> AgenticResult:
        """Run an agentic loop: GLM proposes tool_calls, we execute, repeat.

        Returns when GLM emits a final assistant message with no tool_calls,
        or after max_turns (at which point we force a final answer with
        tools disabled).
        """
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": self._system_prompt},
            {"role": "user", "content": user_message},
        ]
        tool_calls_made: list[ToolCallRecord] = []
        reasoning: str | None = None

        for turn in range(1, max_turns + 1):
            assistant_msg = await self._tools_turn(messages, tools=TOOL_SCHEMAS)
            reasoning = assistant_msg.get("reasoning_content") or assistant_msg.get("reasoning") or reasoning
            tool_calls = assistant_msg.get("tool_calls") or []
            if not tool_calls:
                content = (assistant_msg.get("content") or "").strip()
                if not content:
                    raise GlmError("GLM returned no content and no tool calls")
                return AgenticResult(
                    content=content,
                    reasoning=reasoning,
                    turns=turn,
                    tool_calls=tool_calls_made,
                )

            # Append the assistant turn that contains the tool_calls, then
            # execute and append one tool message per call.
            messages.append(self._assistant_record(assistant_msg))
            for tc in tool_calls:
                fn = tc.get("function") or {}
                name = fn.get("name", "")
                args_json = fn.get("arguments", "{}")
                result = await execute_tool_call(self._session, name, args_json)
                try:
                    parsed_args = json.loads(args_json or "{}")
                except json.JSONDecodeError:
                    parsed_args = {"raw": args_json}
                tool_calls_made.append(
                    ToolCallRecord(name=name, arguments=parsed_args, result=result)
                )
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tc.get("id", ""),
                        "content": json.dumps(result, default=str),
                    }
                )

        # Hit the turn cap. Force GLM to produce a final answer without tools.
        log.info("agentic loop hit %d-turn cap; forcing final answer", max_turns)
        messages.append(
            {
                "role": "user",
                "content": (
                    "Tool budget exhausted. Produce the final report now using "
                    "what you've gathered. No more tool calls."
                ),
            }
        )
        final = await self._tools_turn(messages, tools=None)
        content = (final.get("content") or "").strip()
        if not content:
            raise GlmError("GLM returned empty content after turn cap")
        reasoning = final.get("reasoning_content") or final.get("reasoning") or reasoning
        return AgenticResult(
            content=content,
            reasoning=reasoning,
            turns=max_turns + 1,
            tool_calls=tool_calls_made,
            hit_turn_cap=True,
        )

    @staticmethod
    def _assistant_record(msg: dict[str, Any]) -> dict[str, Any]:
        """Project an assistant response down to what the API expects on echo."""
        record: dict[str, Any] = {
            "role": "assistant",
            "content": msg.get("content") or "",
        }
        if msg.get("tool_calls"):
            record["tool_calls"] = msg["tool_calls"]
        return record

    async def _tools_turn(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self._config.model,
            "temperature": self._config.temperature,
            "messages": messages,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
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
            return data["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise GlmError(f"GLM response malformed: {str(data)[:200]}") from exc

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

    @staticmethod
    def _cache_key(system: str, user: str) -> str:
        h = hashlib.sha256()
        h.update(system.encode())
        h.update(b"\x00")
        h.update(user.encode())
        return h.hexdigest()

    async def _chat(self, *, system: str, user: str) -> GlmResult:
        key = self._cache_key(system, user)
        now = time.monotonic()
        hit = self._cache.get(key)
        if hit is not None and hit[0] > now:
            log.debug("glm cache hit %s", key[:12])
            cached_result = hit[1]
            return GlmResult(
                content=cached_result.content,
                reasoning=cached_result.reasoning,
                usage=cached_result.usage,
                cached=True,
            )

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

        usage: tuple[int, int] | None = None
        if isinstance(data, dict) and isinstance(data.get("usage"), dict):
            u = data["usage"]
            pt = u.get("prompt_tokens")
            ct = u.get("completion_tokens")
            if isinstance(pt, int) and isinstance(ct, int):
                usage = (pt, ct)

        result = GlmResult(content=content, reasoning=reasoning, usage=usage, cached=False)
        self._store(key, result, now)
        return result

    def _store(self, key: str, result: GlmResult, now: float) -> None:
        if len(self._cache) >= _CACHE_CAP:
            # Cheap FIFO eviction: drop the oldest 10%.
            drop = list(self._cache)[: _CACHE_CAP // 10]
            for k in drop:
                self._cache.pop(k, None)
        self._cache[key] = (now + _CACHE_TTL_SECONDS, result)

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

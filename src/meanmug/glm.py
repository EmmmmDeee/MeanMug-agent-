"""GLM-5.1 client: pre-enriched chat, agentic tool loop, tool catalog.

Three callable surfaces:
- analyze_osint / analyze_pivot / analyze_person — single-shot calls with
  pre-fetched enrichment; cached by SHA-256 of (system+user) for 1 h.
- chat_with_tools — agentic loop. GLM proposes tool_calls; we execute via
  the dispatch table over `intel`; loop until GLM emits final content or
  hits max_turns.

The directive sent to GLM is extracted from SYSTEM_PROMPT.md between
`<!-- glm:directive:begin -->` and `<!-- glm:directive:end -->` markers.
Everything else in that file is human-facing reference.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

import aiohttp

from meanmug import intel
from meanmug.config import GlmConfig

log = logging.getLogger(__name__)

_MAX_ENRICHMENT_CHARS = 4000
_MAX_TOOL_RESULT_CHARS = 2000
_DIRECTIVE_BEGIN = "<!-- glm:directive:begin -->"
_DIRECTIVE_END = "<!-- glm:directive:end -->"

_CACHE_TTL_SECONDS = 60 * 60
_CACHE_CAP = 1000


# ----------------------------- prompt loading ----------------------------


def _candidate_prompt_paths() -> list[Path]:
    env_override = os.environ.get("MEANMUG_SYSTEM_PROMPT_PATH")
    candidates: list[Path] = []
    if env_override:
        candidates.append(Path(env_override))
    candidates.append(Path.cwd() / "SYSTEM_PROMPT.md")
    candidates.append(Path(__file__).resolve().parents[2] / "SYSTEM_PROMPT.md")
    return candidates


def _extract_directive(text: str) -> str:
    """Return the marked region (anchored on line starts) or the full file."""
    begin_line = f"\n{_DIRECTIVE_BEGIN}\n"
    end_line = f"\n{_DIRECTIVE_END}\n"
    begin = text.find(begin_line)
    end = text.find(end_line)
    if begin >= 0 and end > begin:
        return text[begin + len(begin_line) : end].strip()
    return text.strip()


def load_system_prompt() -> str:
    for path in _candidate_prompt_paths():
        if path.is_file():
            return _extract_directive(path.read_text(encoding="utf-8"))
    raise FileNotFoundError(
        "SYSTEM_PROMPT.md not found. Set MEANMUG_SYSTEM_PROMPT_PATH or run "
        "the bot from the repository root."
    )


# ----------------------------- result types ------------------------------


@dataclass(frozen=True)
class GlmResult:
    content: str
    reasoning: str | None
    usage: tuple[int, int] | None
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


# ----------------------------- tool catalog ------------------------------
# Schemas follow the OpenAI tools format (z.ai's GLM accepts it). Each tool
# wraps a keyless lookup in `intel`. Add a new tool by appending a schema and
# a DISPATCH entry — nothing else changes.


async def _t_dns_lookup(session: aiohttp.ClientSession, name: str, type: str = "A") -> dict:
    return {"name": name, "type": type, "answers": await intel._doh(session, name, type)}


async def _t_rdap_ip(session, ip: str) -> dict:
    return await intel._rdap_ip(session, ip)


async def _t_rdap_domain(session, domain: str) -> dict:
    return await intel._rdap_domain(session, domain)


async def _t_ip_geo(session, ip: str) -> dict:
    return await intel._geo(session, ip)


async def _t_is_tor_exit(session, ip: str) -> dict:
    exits = await intel._tor_exits(session)
    return {"ip": ip, "is_tor_exit": ip in exits, "total_exits_known": len(exits)}


async def _t_github_user(session, username: str) -> dict:
    return await intel._github(session, username.lstrip("@")) or {"username": username, "found": False}


async def _t_gitlab_user(session, username: str) -> dict:
    return await intel._gitlab(session, username.lstrip("@")) or {"username": username, "found": False}


async def _t_hackernews_user(session, username: str) -> dict:
    return await intel._hackernews(session, username) or {"username": username, "found": False}


async def _t_gravatar(session, email: str) -> dict:
    return await intel._gravatar(session, email) or {"email": email, "found": False}


Dispatcher = Callable[..., Awaitable[dict[str, Any]]]


def _schema(name: str, description: str, properties: dict, required: list[str]) -> dict:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {"type": "object", "properties": properties, "required": required},
        },
    }


TOOL_SCHEMAS: list[dict[str, Any]] = [
    _schema("dns_lookup", "DNS-over-HTTPS lookup via Cloudflare. Use type A/AAAA/MX/NS/TXT/PTR.",
            {"name": {"type": "string"}, "type": {"type": "string", "enum": ["A", "AAAA", "MX", "NS", "TXT", "PTR"]}},
            ["name"]),
    _schema("rdap_ip", "RDAP registration data for an IP (network name, country, range).",
            {"ip": {"type": "string"}}, ["ip"]),
    _schema("rdap_domain", "RDAP registration data for a domain (registrar, dates, nameservers).",
            {"domain": {"type": "string"}}, ["domain"]),
    _schema("ip_geo", "ASN, ISP, country/region/city and proxy flag (ipwho.is).",
            {"ip": {"type": "string"}}, ["ip"]),
    _schema("is_tor_exit", "Check whether an IP appears on the Tor Project's bulk exit-node list.",
            {"ip": {"type": "string"}}, ["ip"]),
    _schema("github_user", "Public GitHub profile: name, bio, company, location, repo + follower counts.",
            {"username": {"type": "string"}}, ["username"]),
    _schema("gitlab_user", "Public GitLab profile for the given username.",
            {"username": {"type": "string"}}, ["username"]),
    _schema("hackernews_user", "HackerNews profile: karma, created date, about text.",
            {"username": {"type": "string"}}, ["username"]),
    _schema("gravatar", "Gravatar profile from an email (display name, linked accounts, urls).",
            {"email": {"type": "string"}}, ["email"]),
]


DISPATCH: dict[str, Dispatcher] = {
    "dns_lookup": _t_dns_lookup,
    "rdap_ip": _t_rdap_ip,
    "rdap_domain": _t_rdap_domain,
    "ip_geo": _t_ip_geo,
    "is_tor_exit": _t_is_tor_exit,
    "github_user": _t_github_user,
    "gitlab_user": _t_gitlab_user,
    "hackernews_user": _t_hackernews_user,
    "gravatar": _t_gravatar,
}


async def execute_tool_call(
    session: aiohttp.ClientSession, name: str, arguments_json: str
) -> dict[str, Any]:
    """Run one GLM-requested tool call. Always returns a JSON-serializable dict."""
    fn = DISPATCH.get(name)
    if fn is None:
        return {"error": f"unknown tool: {name}"}
    try:
        args = json.loads(arguments_json or "{}")
    except json.JSONDecodeError:
        return {"error": "tool arguments are not valid JSON"}
    if not isinstance(args, dict):
        return {"error": "tool arguments must be an object"}
    try:
        result = await fn(session, **args)
    except TypeError as exc:
        return {"error": f"bad arguments for {name}: {exc}"}
    except asyncio.TimeoutError:
        return {"error": f"{name} timed out"}
    except Exception as exc:
        log.exception("tool %s failed", name)
        return {"error": f"{name} failed: {exc}"}

    encoded = json.dumps(result, default=str)
    if len(encoded) > _MAX_TOOL_RESULT_CHARS:
        return {"truncated": True, "preview": encoded[:_MAX_TOOL_RESULT_CHARS]}
    return result


# ----------------------------- GLM client --------------------------------


class GlmClient:
    """Async OpenAI-compatible GLM client with response cache + agentic loop."""

    def __init__(self, session: aiohttp.ClientSession, config: GlmConfig) -> None:
        self._session = session
        self._config = config
        self._system_prompt = load_system_prompt()
        self._cache: dict[str, tuple[float, GlmResult]] = {}

    @property
    def system_prompt(self) -> str:
        return self._system_prompt

    # --- single-shot calls (pre-enriched) ---

    async def analyze_osint(
        self,
        raw: str,
        indicators: dict[str, list[str]],
        enrichment: dict[str, Any] | None = None,
    ) -> GlmResult:
        user_block = self._render_user_block(raw, indicators, enrichment)
        return await self._chat(system=self._system_prompt, user=user_block)

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
            "accounts, and confidence-rated pivots.\n\n"
        )
        parts = [focus, self._render_user_block(subject, indicators, infra_enrichment)]
        if person_intel:
            blob = json.dumps(person_intel, indent=2, sort_keys=True, default=str)
            if len(blob) > _MAX_ENRICHMENT_CHARS:
                blob = blob[:_MAX_ENRICHMENT_CHARS] + "\n... (truncated)"
            parts.extend(["", "Person intel (treat as authoritative for this run):", "```json", blob, "```"])
        return await self._chat(system=self._system_prompt, user="\n".join(parts))

    # --- agentic loop ---

    async def chat_with_tools(self, user_message: str, max_turns: int = 8) -> AgenticResult:
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
                    content=content, reasoning=reasoning, turns=turn, tool_calls=tool_calls_made
                )

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
                tool_calls_made.append(ToolCallRecord(name=name, arguments=parsed_args, result=result))
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.get("id", ""),
                    "content": json.dumps(result, default=str),
                })

        log.info("agentic loop hit %d-turn cap; forcing final answer", max_turns)
        messages.append({
            "role": "user",
            "content": (
                "Tool budget exhausted. Produce the final report now using "
                "what you've gathered. No more tool calls."
            ),
        })
        final = await self._tools_turn(messages, tools=None)
        content = (final.get("content") or "").strip()
        if not content:
            raise GlmError("GLM returned empty content after turn cap")
        reasoning = final.get("reasoning_content") or final.get("reasoning") or reasoning
        return AgenticResult(
            content=content, reasoning=reasoning, turns=max_turns + 1,
            tool_calls=tool_calls_made, hit_turn_cap=True,
        )

    # --- HTTP layer ---

    @staticmethod
    def _assistant_record(msg: dict[str, Any]) -> dict[str, Any]:
        record: dict[str, Any] = {"role": "assistant", "content": msg.get("content") or ""}
        if msg.get("tool_calls"):
            record["tool_calls"] = msg["tool_calls"]
        return record

    async def _tools_turn(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None
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
        msg, _envelope = await self._post(payload)
        return msg

    async def _chat(self, *, system: str, user: str) -> GlmResult:
        key = self._cache_key(system, user)
        now = time.monotonic()
        hit = self._cache.get(key)
        if hit is not None and hit[0] > now:
            log.debug("glm cache hit %s", key[:12])
            r = hit[1]
            return GlmResult(content=r.content, reasoning=r.reasoning, usage=r.usage, cached=True)

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

        choice, envelope = await self._post(payload)
        content = (choice.get("content") or "").strip()
        reasoning = choice.get("reasoning_content") or choice.get("reasoning")
        if not content:
            raise GlmError("GLM returned empty content")

        usage: tuple[int, int] | None = None
        u = envelope.get("usage") if isinstance(envelope, dict) else None
        if isinstance(u, dict):
            pt, ct = u.get("prompt_tokens"), u.get("completion_tokens")
            if isinstance(pt, int) and isinstance(ct, int):
                usage = (pt, ct)

        result = GlmResult(content=content, reasoning=reasoning, usage=usage, cached=False)
        self._store(key, result, now)
        return result

    async def _post(
        self, payload: dict[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """POST to z.ai chat completions. Return (assistant_message, full_envelope)."""
        url = f"{self._config.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self._config.api_key}",
            "Content-Type": "application/json",
        }
        timeout = aiohttp.ClientTimeout(total=self._config.timeout)
        try:
            async with self._session.post(url, json=payload, headers=headers, timeout=timeout) as resp:
                if resp.status >= 400:
                    body = await resp.text()
                    raise GlmError(f"GLM HTTP {resp.status}: {body[:500]}")
                data = await resp.json()
        except aiohttp.ClientError as exc:
            raise GlmError(f"GLM network error: {exc}") from exc
        try:
            msg = data["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise GlmError(f"GLM response malformed: {str(data)[:200]}") from exc
        return msg, data if isinstance(data, dict) else {}

    def _store(self, key: str, result: GlmResult, now: float) -> None:
        if len(self._cache) >= _CACHE_CAP:
            drop = list(self._cache)[: _CACHE_CAP // 10]
            for k in drop:
                self._cache.pop(k, None)
        self._cache[key] = (now + _CACHE_TTL_SECONDS, result)

    @staticmethod
    def _cache_key(system: str, user: str) -> str:
        h = hashlib.sha256()
        h.update(system.encode())
        h.update(b"\x00")
        h.update(user.encode())
        return h.hexdigest()

    @staticmethod
    def _render_user_block(
        raw: str, indicators: dict[str, list[str]], enrichment: dict[str, Any] | None
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
            parts.extend([
                "",
                "Live enrichment (fresh lookups; treat as authoritative for this run):",
                "```json",
                blob,
                "```",
            ])
        parts.append("")
        parts.append("Operator input:")
        parts.append(raw.strip())
        return "\n".join(parts)



"""GLM-5.1 agentic tool catalog.

Each tool wraps an existing keyless OSINT lookup. The schemas follow the
OpenAI tools format (which z.ai's GLM endpoint accepts). The dispatch
table maps tool names to async callables that take the shared aiohttp
session plus the tool's parameters.

GlmClient.chat_with_tools() drives the agentic loop: GLM responds with
`tool_calls`; we execute them concurrently here; results go back as
`role: tool` messages; GLM either calls more tools or returns a final
answer.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Awaitable, Callable

import aiohttp

from meanmug.services import enrich, people

log = logging.getLogger(__name__)

# Cap per-tool-result payload size so a chatty source can't blow GLM's context.
_MAX_RESULT_CHARS = 2000


# ----------------------------- thin wrappers ------------------------------


async def _t_dns_lookup(session: aiohttp.ClientSession, name: str, type: str = "A") -> dict:
    answers = await enrich._doh(session, name, type)
    return {"name": name, "type": type, "answers": answers}


async def _t_rdap_ip(session: aiohttp.ClientSession, ip: str) -> dict:
    return await enrich._rdap_ip(session, ip)


async def _t_rdap_domain(session: aiohttp.ClientSession, domain: str) -> dict:
    return await enrich._rdap_domain(session, domain)


async def _t_ip_geo(session: aiohttp.ClientSession, ip: str) -> dict:
    return await enrich._geo(session, ip)


async def _t_is_tor_exit(session: aiohttp.ClientSession, ip: str) -> dict:
    exits = await enrich._tor_exits(session)
    return {"ip": ip, "is_tor_exit": ip in exits, "total_exits_known": len(exits)}


async def _t_github_user(session: aiohttp.ClientSession, username: str) -> dict:
    data = await people._github(session, username.lstrip("@"))
    return data or {"username": username, "found": False}


async def _t_gitlab_user(session: aiohttp.ClientSession, username: str) -> dict:
    data = await people._gitlab(session, username.lstrip("@"))
    return data or {"username": username, "found": False}


async def _t_hackernews_user(session: aiohttp.ClientSession, username: str) -> dict:
    data = await people._hackernews(session, username)
    return data or {"username": username, "found": False}


async def _t_gravatar(session: aiohttp.ClientSession, email: str) -> dict:
    data = await people._gravatar(session, email)
    return data or {"email": email, "found": False}


# ----------------------------- schemas + dispatch -------------------------


TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "dns_lookup",
            "description": "DNS-over-HTTPS lookup via Cloudflare. Use type A/AAAA/MX/NS/TXT/PTR.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "DNS name or reverse-IP for PTR"},
                    "type": {
                        "type": "string",
                        "enum": ["A", "AAAA", "MX", "NS", "TXT", "PTR"],
                        "description": "Record type",
                    },
                },
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "rdap_ip",
            "description": "RDAP registration data for an IP (network name, country, range).",
            "parameters": {
                "type": "object",
                "properties": {"ip": {"type": "string"}},
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "rdap_domain",
            "description": "RDAP registration data for a domain (registrar, dates, nameservers).",
            "parameters": {
                "type": "object",
                "properties": {"domain": {"type": "string"}},
                "required": ["domain"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ip_geo",
            "description": "ASN, ISP, country/region/city and proxy flag for an IP (ipwho.is).",
            "parameters": {
                "type": "object",
                "properties": {"ip": {"type": "string"}},
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "is_tor_exit",
            "description": "Check whether an IP appears on the Tor Project's bulk exit-node list.",
            "parameters": {
                "type": "object",
                "properties": {"ip": {"type": "string"}},
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "github_user",
            "description": "Public GitHub profile: name, bio, company, location, blog, twitter link, repo + follower counts.",
            "parameters": {
                "type": "object",
                "properties": {"username": {"type": "string"}},
                "required": ["username"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "gitlab_user",
            "description": "Public GitLab profile for the given username.",
            "parameters": {
                "type": "object",
                "properties": {"username": {"type": "string"}},
                "required": ["username"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "hackernews_user",
            "description": "HackerNews profile: karma, created date, about text.",
            "parameters": {
                "type": "object",
                "properties": {"username": {"type": "string"}},
                "required": ["username"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "gravatar",
            "description": "Gravatar profile from an email (display name, linked accounts, urls).",
            "parameters": {
                "type": "object",
                "properties": {"email": {"type": "string"}},
                "required": ["email"],
            },
        },
    },
]


Dispatcher = Callable[..., Awaitable[dict[str, Any]]]


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
    session: aiohttp.ClientSession,
    name: str,
    arguments_json: str,
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

    # Truncate over-large payloads so chatty sources don't blow context.
    encoded = json.dumps(result, default=str)
    if len(encoded) > _MAX_RESULT_CHARS:
        return {"truncated": True, "preview": encoded[:_MAX_RESULT_CHARS]}
    return result

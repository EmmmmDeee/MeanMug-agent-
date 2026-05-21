"""OSINT intelligence layer: indicator extraction + keyless live lookups.

Three concerns:
- extract_indicators: regex over free text → IPs / domains / emails / handles.
- Infrastructure lookups: DoH DNS, RDAP for IPs and domains, ipwho.is geo,
  Tor exit-node membership. Wrapped by enrich_indicators() which fans out
  concurrently and absorbs per-lookup failures.
- People lookups: GitHub, GitLab, HackerNews user APIs + Gravatar by email.
  Wrapped by enrich_person().

All lookups are keyless. Results are TTL-cached in process memory (1h for
infrastructure, 30m for people, 6h for the Tor exit list).
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
from typing import Any

import aiohttp

log = logging.getLogger(__name__)


# ----------------------------- extraction ---------------------------------


_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_HANDLE = re.compile(r"(?:^|[\s\.,;:!?\(\)\[\]<>])@([A-Za-z][A-Za-z0-9_]{2,29})(?!\w)")


def extract_indicators(text: str) -> dict[str, list[str]]:
    return {
        "ips": sorted(set(_IPV4.findall(text))),
        "domains": sorted(set(_DOMAIN.findall(text))),
        "emails": sorted(set(_EMAIL.findall(text))),
        "handles": sorted({h.lower() for h in _HANDLE.findall(text)}),
    }


# ----------------------------- shared HTTP helpers -----------------------


_TIMEOUT = aiohttp.ClientTimeout(total=5)
_UA = "MeanMug-Agent/1.0 (+osint-research)"

_CACHE_TTL_SHORT = 60 * 60          # 1 h for RDAP / DNS / geo / people
_CACHE_TTL_LONG = 6 * 60 * 60        # 6 h for Tor exit list
_cache: dict[str, tuple[float, Any]] = {}


def _cache_get(key: str) -> Any | None:
    hit = _cache.get(key)
    if hit is None:
        return None
    expiry, value = hit
    if expiry < time.monotonic():
        _cache.pop(key, None)
        return None
    return value


def _cache_set(key: str, value: Any, ttl: int = _CACHE_TTL_SHORT) -> None:
    _cache[key] = (time.monotonic() + ttl, value)


async def _get_json(
    session: aiohttp.ClientSession, url: str, headers: dict[str, str] | None = None
) -> Any | None:
    try:
        async with session.get(
            url, headers={"User-Agent": _UA, **(headers or {})}, timeout=_TIMEOUT
        ) as resp:
            if resp.status >= 400:
                return None
            return await resp.json(content_type=None)
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        log.debug("GET %s failed: %s", url, exc)
        return None


async def _get_text(session: aiohttp.ClientSession, url: str) -> str | None:
    try:
        async with session.get(url, headers={"User-Agent": _UA}, timeout=_TIMEOUT) as resp:
            if resp.status >= 400:
                return None
            return await resp.text()
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        log.debug("GET %s failed: %s", url, exc)
        return None


# ----------------------------- infrastructure ----------------------------


_DOH = "https://cloudflare-dns.com/dns-query"
_RDAP_IP = "https://rdap.org/ip/"
_RDAP_DOMAIN = "https://rdap.org/domain/"
_GEO = "https://ipwho.is/"
_TOR_EXITS_URL = "https://check.torproject.org/torbulkexitlist"


async def _doh(session: aiohttp.ClientSession, name: str, qtype: str) -> list[str]:
    key = f"doh:{qtype}:{name}"
    cached = _cache_get(key)
    if cached is not None:
        return cached
    data = await _get_json(
        session,
        f"{_DOH}?name={name}&type={qtype}",
        headers={"Accept": "application/dns-json"},
    )
    answers: list[str] = []
    if isinstance(data, dict):
        for ans in data.get("Answer", []) or []:
            value = ans.get("data")
            if isinstance(value, str):
                answers.append(value.rstrip("."))
    _cache_set(key, answers)
    return answers


async def _rdap_ip(session: aiohttp.ClientSession, ip: str) -> dict[str, Any]:
    key = f"rdap:ip:{ip}"
    cached = _cache_get(key)
    if cached is not None:
        return cached
    data = await _get_json(session, f"{_RDAP_IP}{ip}")
    out: dict[str, Any] = {}
    if isinstance(data, dict):
        out["network_name"] = data.get("name")
        out["handle"] = data.get("handle")
        out["country"] = data.get("country")
        out["start"] = data.get("startAddress")
        out["end"] = data.get("endAddress")
    _cache_set(key, out)
    return out


async def _rdap_domain(session: aiohttp.ClientSession, domain: str) -> dict[str, Any]:
    key = f"rdap:domain:{domain}"
    cached = _cache_get(key)
    if cached is not None:
        return cached
    data = await _get_json(session, f"{_RDAP_DOMAIN}{domain}")
    out: dict[str, Any] = {}
    if isinstance(data, dict):
        out["handle"] = data.get("handle")
        out["status"] = data.get("status")
        events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", []) or []}
        out["registered"] = events.get("registration")
        out["expires"] = events.get("expiration")
        out["changed"] = events.get("last changed")
        registrar = None
        for entity in data.get("entities", []) or []:
            roles = entity.get("roles") or []
            if "registrar" in roles:
                for line in entity.get("vcardArray", [None, []])[1] or []:
                    if isinstance(line, list) and len(line) >= 4 and line[0] == "fn":
                        registrar = line[3]
        out["registrar"] = registrar
        out["nameservers"] = [
            (ns.get("ldhName") or "").lower()
            for ns in data.get("nameservers", []) or []
            if ns.get("ldhName")
        ]
    _cache_set(key, out)
    return out


async def _geo(session: aiohttp.ClientSession, ip: str) -> dict[str, Any]:
    key = f"geo:{ip}"
    cached = _cache_get(key)
    if cached is not None:
        return cached
    data = await _get_json(session, f"{_GEO}{ip}")
    out: dict[str, Any] = {}
    if isinstance(data, dict) and data.get("success", True):
        out["country"] = data.get("country")
        out["region"] = data.get("region")
        out["city"] = data.get("city")
        out["org"] = (data.get("connection") or {}).get("org")
        out["asn"] = (data.get("connection") or {}).get("asn")
        out["isp"] = (data.get("connection") or {}).get("isp")
        out["is_proxy"] = data.get("security", {}).get("proxy") if data.get("security") else None
    _cache_set(key, out)
    return out


async def _tor_exits(session: aiohttp.ClientSession) -> set[str]:
    key = "tor:exits"
    cached = _cache_get(key)
    if cached is not None:
        return cached
    text = await _get_text(session, _TOR_EXITS_URL)
    exits: set[str] = set()
    if text:
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                exits.add(line)
    _cache_set(key, exits, _CACHE_TTL_LONG)
    return exits


async def enrich_ip(session: aiohttp.ClientSession, ip: str) -> dict[str, Any]:
    rdap, geo, ptr, tor = await asyncio.gather(
        _rdap_ip(session, ip),
        _geo(session, ip),
        _doh(session, ip, "PTR"),
        _tor_exits(session),
    )
    return {"rdap": rdap, "geo": geo, "ptr": ptr, "tor_exit": ip in tor}


async def enrich_domain(session: aiohttp.ClientSession, domain: str) -> dict[str, Any]:
    rdap, a, aaaa, mx, ns, txt = await asyncio.gather(
        _rdap_domain(session, domain),
        _doh(session, domain, "A"),
        _doh(session, domain, "AAAA"),
        _doh(session, domain, "MX"),
        _doh(session, domain, "NS"),
        _doh(session, domain, "TXT"),
    )
    return {"rdap": rdap, "a": a, "aaaa": aaaa, "mx": mx, "ns": ns, "txt": txt}


async def enrich_email(session: aiohttp.ClientSession, email: str) -> dict[str, Any]:
    _, _, domain = email.partition("@")
    if not domain:
        return {}
    return {"domain": domain, "domain_intel": await enrich_domain(session, domain)}


async def enrich_indicators(
    session: aiohttp.ClientSession, indicators: dict[str, list[str]]
) -> dict[str, Any]:
    """Fan out enrichment lookups concurrently. Individual failures are absorbed."""
    ip_tasks = {ip: asyncio.create_task(enrich_ip(session, ip)) for ip in indicators.get("ips", [])[:8]}
    domain_tasks = {d: asyncio.create_task(enrich_domain(session, d)) for d in indicators.get("domains", [])[:8]}
    email_tasks = {e: asyncio.create_task(enrich_email(session, e)) for e in indicators.get("emails", [])[:8]}

    result: dict[str, dict[str, Any]] = {"ips": {}, "domains": {}, "emails": {}}
    for ip, task in ip_tasks.items():
        try:
            result["ips"][ip] = await task
        except Exception:
            log.exception("ip enrichment failed for %s", ip)
            result["ips"][ip] = {"error": "lookup failed"}
    for d, task in domain_tasks.items():
        try:
            result["domains"][d] = await task
        except Exception:
            log.exception("domain enrichment failed for %s", d)
            result["domains"][d] = {"error": "lookup failed"}
    for e, task in email_tasks.items():
        try:
            result["emails"][e] = await task
        except Exception:
            log.exception("email enrichment failed for %s", e)
            result["emails"][e] = {"error": "lookup failed"}
    return result


# ----------------------------- people ------------------------------------


async def _github(session: aiohttp.ClientSession, handle: str) -> dict[str, Any] | None:
    data = await _get_json(session, f"https://api.github.com/users/{handle}")
    if not isinstance(data, dict) or "login" not in data:
        return None
    return {
        "login": data.get("login"),
        "name": data.get("name"),
        "company": data.get("company"),
        "blog": data.get("blog"),
        "location": data.get("location"),
        "bio": data.get("bio"),
        "twitter_username": data.get("twitter_username"),
        "public_repos": data.get("public_repos"),
        "followers": data.get("followers"),
        "created_at": data.get("created_at"),
        "url": data.get("html_url"),
    }


async def _gitlab(session: aiohttp.ClientSession, handle: str) -> dict[str, Any] | None:
    data = await _get_json(session, f"https://gitlab.com/api/v4/users?username={handle}")
    if not isinstance(data, list) or not data:
        return None
    u = data[0]
    return {
        "username": u.get("username"),
        "name": u.get("name"),
        "state": u.get("state"),
        "url": u.get("web_url"),
        "avatar_url": u.get("avatar_url"),
    }


async def _hackernews(session: aiohttp.ClientSession, handle: str) -> dict[str, Any] | None:
    data = await _get_json(session, f"https://hacker-news.firebaseio.com/v0/user/{handle}.json")
    if not isinstance(data, dict) or "id" not in data:
        return None
    return {
        "id": data.get("id"),
        "karma": data.get("karma"),
        "created": data.get("created"),
        "about": (data.get("about") or "")[:200],
    }


async def _gravatar(session: aiohttp.ClientSession, email: str) -> dict[str, Any] | None:
    h = hashlib.md5(email.strip().lower().encode()).hexdigest()
    data = await _get_json(session, f"https://www.gravatar.com/{h}.json")
    if not isinstance(data, dict):
        return None
    entries = data.get("entry") or []
    if not entries:
        return None
    e = entries[0]
    return {
        "hash": h,
        "display_name": e.get("displayName"),
        "preferred_username": e.get("preferredUsername"),
        "profile_url": e.get("profileUrl"),
        "accounts": [
            {"shortname": a.get("shortname"), "url": a.get("url")}
            for a in (e.get("accounts") or [])
        ],
        "urls": [u.get("value") for u in (e.get("urls") or []) if u.get("value")],
    }


async def enrich_handle(session: aiohttp.ClientSession, handle: str) -> dict[str, Any]:
    handle = handle.lstrip("@").lower()
    key = f"handle:{handle}"
    cached = _cache_get(key)
    if cached is not None:
        return cached
    gh, gl, hn = await asyncio.gather(
        _github(session, handle),
        _gitlab(session, handle),
        _hackernews(session, handle),
    )
    result = {
        "handle": handle,
        "github": gh,
        "gitlab": gl,
        "hackernews": hn,
        "platforms_found": sum(1 for x in (gh, gl, hn) if x),
    }
    _cache_set(key, result, 30 * 60)
    return result


async def enrich_email_person(session: aiohttp.ClientSession, email: str) -> dict[str, Any]:
    key = f"email-person:{email.lower()}"
    cached = _cache_get(key)
    if cached is not None:
        return cached
    gravatar = await _gravatar(session, email)
    result = {"email": email, "gravatar": gravatar}
    _cache_set(key, result, 30 * 60)
    return result


async def enrich_person(
    session: aiohttp.ClientSession,
    handles: list[str] | None = None,
    emails: list[str] | None = None,
) -> dict[str, Any]:
    handles = handles or []
    emails = emails or []
    handle_tasks = {h: asyncio.create_task(enrich_handle(session, h)) for h in handles[:8]}
    email_tasks = {e: asyncio.create_task(enrich_email_person(session, e)) for e in emails[:8]}
    out: dict[str, dict[str, Any]] = {"handles": {}, "emails": {}}
    for h, task in handle_tasks.items():
        try:
            out["handles"][h] = await task
        except Exception:
            log.exception("handle enrichment failed for %s", h)
            out["handles"][h] = {"error": "lookup failed"}
    for e, task in email_tasks.items():
        try:
            out["emails"][e] = await task
        except Exception:
            log.exception("email-person enrichment failed for %s", e)
            out["emails"][e] = {"error": "lookup failed"}
    return out

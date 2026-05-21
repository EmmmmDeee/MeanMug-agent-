from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import aiohttp

log = logging.getLogger(__name__)

_TIMEOUT = aiohttp.ClientTimeout(total=5)
_UA = "MeanMug-Agent/1.0 (+osint-research)"
_DOH = "https://cloudflare-dns.com/dns-query"
_RDAP_IP = "https://rdap.org/ip/"
_RDAP_DOMAIN = "https://rdap.org/domain/"
_GEO = "https://ipwho.is/"
_TOR_EXITS_URL = "https://check.torproject.org/torbulkexitlist"

_CACHE_TTL_SHORT = 60 * 60          # 1 hour for RDAP/DNS/geo
_CACHE_TTL_LONG = 6 * 60 * 60        # 6 hours for Tor exit list
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


def _cache_set(key: str, value: Any, ttl: int) -> None:
    _cache[key] = (time.monotonic() + ttl, value)


async def _get_json(session: aiohttp.ClientSession, url: str, headers: dict[str, str] | None = None) -> Any | None:
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
    _cache_set(key, answers, _CACHE_TTL_SHORT)
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
    _cache_set(key, out, _CACHE_TTL_SHORT)
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
    _cache_set(key, out, _CACHE_TTL_SHORT)
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
    _cache_set(key, out, _CACHE_TTL_SHORT)
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
    return {
        "rdap": rdap,
        "geo": geo,
        "ptr": ptr,
        "tor_exit": ip in tor,
    }


async def enrich_domain(session: aiohttp.ClientSession, domain: str) -> dict[str, Any]:
    rdap, a, aaaa, mx, ns, txt = await asyncio.gather(
        _rdap_domain(session, domain),
        _doh(session, domain, "A"),
        _doh(session, domain, "AAAA"),
        _doh(session, domain, "MX"),
        _doh(session, domain, "NS"),
        _doh(session, domain, "TXT"),
    )
    return {
        "rdap": rdap,
        "a": a,
        "aaaa": aaaa,
        "mx": mx,
        "ns": ns,
        "txt": txt,
    }


async def enrich_email(session: aiohttp.ClientSession, email: str) -> dict[str, Any]:
    _, _, domain = email.partition("@")
    if not domain:
        return {}
    return {"domain": domain, "domain_intel": await enrich_domain(session, domain)}


async def enrich_indicators(
    session: aiohttp.ClientSession, indicators: dict[str, list[str]]
) -> dict[str, Any]:
    """Fan out enrichment lookups concurrently. Individual failures are absorbed."""
    ips = indicators.get("ips", [])[:8]
    domains = indicators.get("domains", [])[:8]
    emails = indicators.get("emails", [])[:8]

    ip_tasks = {ip: asyncio.create_task(enrich_ip(session, ip)) for ip in ips}
    domain_tasks = {d: asyncio.create_task(enrich_domain(session, d)) for d in domains}
    email_tasks = {e: asyncio.create_task(enrich_email(session, e)) for e in emails}

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

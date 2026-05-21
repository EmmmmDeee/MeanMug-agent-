from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from typing import Any

import aiohttp

log = logging.getLogger(__name__)

_TIMEOUT = aiohttp.ClientTimeout(total=5)
_UA = "MeanMug-Agent/1.0 (+osint-research)"
_CACHE_TTL = 30 * 60
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


def _cache_set(key: str, value: Any) -> None:
    _cache[key] = (time.monotonic() + _CACHE_TTL, value)


async def _get_json(session: aiohttp.ClientSession, url: str) -> Any | None:
    try:
        async with session.get(url, headers={"User-Agent": _UA}, timeout=_TIMEOUT) as resp:
            if resp.status != 200:
                return None
            return await resp.json(content_type=None)
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        log.debug("GET %s failed: %s", url, exc)
        return None


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
    data = await _get_json(
        session, f"https://gitlab.com/api/v4/users?username={handle}"
    )
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
    data = await _get_json(
        session, f"https://hacker-news.firebaseio.com/v0/user/{handle}.json"
    )
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
    _cache_set(key, result)
    return result


async def enrich_email_person(
    session: aiohttp.ClientSession, email: str
) -> dict[str, Any]:
    key = f"email-person:{email.lower()}"
    cached = _cache_get(key)
    if cached is not None:
        return cached
    gravatar = await _gravatar(session, email)
    result = {"email": email, "gravatar": gravatar}
    _cache_set(key, result)
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

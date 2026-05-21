from __future__ import annotations

import re

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
# @handle: anchored on start/whitespace/punct so emails don't match;
# trailing word-boundary so we don't grab too much.
_HANDLE = re.compile(r"(?:^|[\s\.,;:!?\(\)\[\]<>])@([A-Za-z][A-Za-z0-9_]{2,29})(?!\w)")


def extract_indicators(text: str) -> dict[str, list[str]]:
    return {
        "ips": sorted(set(_IPV4.findall(text))),
        "domains": sorted(set(_DOMAIN.findall(text))),
        "emails": sorted(set(_EMAIL.findall(text))),
        "handles": sorted({h.lower() for h in _HANDLE.findall(text)}),
    }

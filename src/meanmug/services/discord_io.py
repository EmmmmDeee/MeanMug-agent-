from __future__ import annotations

import re

import discord

DISCORD_MESSAGE_LIMIT = 2000

_THREAT_RE = re.compile(
    r"\*\*Threat Level\*\*\s*[—\-:]\s*(CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN)",
    re.IGNORECASE,
)
_THREAT_COLORS: dict[str, "discord.Color"] = {
    "CRITICAL": discord.Color.from_str("#ef4444"),
    "HIGH": discord.Color.from_str("#f59e0b"),
    "MEDIUM": discord.Color.from_str("#eab308"),
    "LOW": discord.Color.from_str("#22c55e"),
    "UNKNOWN": discord.Color.dark_gray(),
}


def color_for_analysis(analysis: str) -> discord.Color:
    """Pick an embed color from the analysis's **Threat Level** line."""
    match = _THREAT_RE.search(analysis or "")
    if not match:
        return discord.Color.green()
    return _THREAT_COLORS.get(match.group(1).upper(), discord.Color.green())


def chunk_text(text: str, limit: int = 1900) -> list[str]:
    """Split text into Discord-safe chunks.

    Boundary preference (each rejected if it falls before half the limit):
    1. Markdown section header (`\\n**`) — preserves the report's structure.
    2. Paragraph break (`\\n\\n`).
    3. Line break (`\\n`).
    4. Word boundary (` `).
    5. Hard cut at `limit`.
    """
    text = text.strip()
    if len(text) <= limit:
        return [text]

    chunks: list[str] = []
    remaining = text
    half = limit // 2
    while len(remaining) > limit:
        window = remaining[:limit]
        cut = window.rfind("\n**")
        if cut < half:
            cut = window.rfind("\n\n")
        if cut < half:
            cut = window.rfind("\n")
        if cut < half:
            cut = window.rfind(" ")
        if cut <= 0:
            cut = limit
        chunks.append(remaining[:cut].rstrip())
        remaining = remaining[cut:].lstrip()
    if remaining:
        chunks.append(remaining)
    return chunks

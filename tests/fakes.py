"""Minimal fakes for Discord + GLM + aiohttp so cogs can be exercised end-to-end."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from meanmug.services.glm import GlmResult


# ----------------------------- aiohttp fakes -------------------------------


class FakeHttpResponse:
    def __init__(self, status: int = 200, json_data: Any = None, text: str = "") -> None:
        self.status = status
        self._json = json_data
        self._text = text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    async def json(self, content_type=None):
        return self._json

    async def text(self):
        return self._text


class FakeHttpSession:
    """aiohttp.ClientSession-compatible double. Records calls; returns canned responses."""

    def __init__(self) -> None:
        self.posts: list[tuple[str, dict, dict]] = []
        self.gets: list[str] = []
        self._post_response = FakeHttpResponse(
            json_data={"choices": [{"message": {"content": "stub analysis"}}]}
        )

    def set_post_response(self, response: FakeHttpResponse) -> None:
        self._post_response = response

    def post(self, url, json=None, headers=None, timeout=None):
        self.posts.append((url, json or {}, headers or {}))
        return self._post_response

    def get(self, url, headers=None, timeout=None):
        self.gets.append(url)
        return FakeHttpResponse(json_data=None)


# ----------------------------- Discord fakes -------------------------------


@dataclass
class FakeAuthor:
    id: int = 1
    name: str = "operator"

    def __hash__(self) -> int:
        return self.id


@dataclass
class FakeChannel:
    id: int = 100
    sent: list[str] = field(default_factory=list)

    async def send(self, content: Any = None, embed: Any = None) -> None:
        self.sent.append(content if content is not None else f"<embed:{getattr(embed, 'title', '?')}>")


@dataclass
class FakeGuild:
    id: int = 999


@dataclass
class FakeResponse:
    _done: bool = False
    messages: list[dict] = field(default_factory=list)

    async def defer(self, thinking: bool = False, ephemeral: bool = False) -> None:
        self._done = True

    async def send_message(self, content: Any = None, embed: Any = None, ephemeral: bool = False) -> None:
        self.messages.append({"content": content, "embed": embed, "ephemeral": ephemeral})
        self._done = True

    def is_done(self) -> bool:
        return self._done


@dataclass
class FakeFollowup:
    messages: list[dict] = field(default_factory=list)

    async def send(self, content: Any = None, embed: Any = None, ephemeral: bool = False) -> None:
        self.messages.append({"content": content, "embed": embed, "ephemeral": ephemeral})


@dataclass
class FakeInteraction:
    user: FakeAuthor = field(default_factory=FakeAuthor)
    channel: FakeChannel = field(default_factory=FakeChannel)
    guild: FakeGuild | None = field(default_factory=FakeGuild)
    response: FakeResponse = field(default_factory=FakeResponse)
    followup: FakeFollowup = field(default_factory=FakeFollowup)

    def all_sent(self) -> list[dict]:
        return list(self.response.messages) + list(self.followup.messages)


@dataclass
class FakeEmbed:
    title: str | None = None
    description: str | None = None
    fields: list = field(default_factory=list)
    footer: Any = None


@dataclass
class FakeMessage:
    id: int = 1
    content: str = ""
    embeds: list = field(default_factory=list)
    author: FakeAuthor = field(default_factory=FakeAuthor)
    channel: FakeChannel = field(default_factory=FakeChannel)
    guild: FakeGuild | None = field(default_factory=FakeGuild)
    reactions_added: list[str] = field(default_factory=list)
    jump_url: str = "https://discord.com/channels/999/100/1"

    async def add_reaction(self, emoji: str) -> None:
        self.reactions_added.append(emoji)


# ----------------------------- bot harness ---------------------------------


class FakeBot:
    """Lightweight stand-in for MeanMugBot exposing the attributes cogs read."""

    def __init__(self, db, session, glm, config) -> None:
        self.db = db
        self.session = session
        self.glm = glm
        self.config = config
        self.user = FakeAuthor(id=42, name="MeanMug")
        self._latency = 0.012
        self._channels: dict[int, FakeChannel] = {}

    @property
    def latency(self) -> float:
        return self._latency

    def get_channel(self, channel_id: int):
        return self._channels.get(channel_id)

    def register_channel(self, channel: FakeChannel) -> None:
        self._channels[channel.id] = channel


class CannedGlm:
    """GlmClient stand-in. Records the methods called and the args."""

    def __init__(self, content: str = "stub analysis") -> None:
        self._content = content
        self.calls: list[tuple[str, tuple, dict]] = []

    async def analyze_osint(self, *args, **kwargs) -> GlmResult:
        self.calls.append(("osint", args, kwargs))
        return GlmResult(content=self._content, reasoning=None)

    async def analyze_pivot(self, *args, **kwargs) -> GlmResult:
        self.calls.append(("pivot", args, kwargs))
        return GlmResult(content=self._content, reasoning=None)

    async def analyze_person(self, *args, **kwargs) -> GlmResult:
        self.calls.append(("person", args, kwargs))
        return GlmResult(content=self._content, reasoning=None)

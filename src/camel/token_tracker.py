"""Per-task API token tracking for both P-LLM and Q-LLM calls.

Usage:
    token_tracker.reset()          # before each task
    ...run task...
    usage = token_tracker.get()    # after each task
    usage.pllm.input_tokens        # P-LLM input tokens
    usage.qllm.output_tokens       # Q-LLM output tokens
    usage.total.input_tokens       # combined
"""

from dataclasses import dataclass, field

import anthropic
from anthropic import AsyncAnthropic


@dataclass
class LLMUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0

    def __iadd__(self, other: "LLMUsage") -> "LLMUsage":
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        self.cache_creation_input_tokens += other.cache_creation_input_tokens
        self.cache_read_input_tokens += other.cache_read_input_tokens
        return self


@dataclass
class UsageTotals:
    pllm: LLMUsage = field(default_factory=LLMUsage)
    qllm: LLMUsage = field(default_factory=LLMUsage)

    @property
    def total(self) -> LLMUsage:
        combined = LLMUsage()
        combined += self.pllm
        combined += self.qllm
        return combined

    # Convenience accessors kept for backwards-compatibility
    @property
    def input_tokens(self) -> int:
        return self.total.input_tokens

    @property
    def output_tokens(self) -> int:
        return self.total.output_tokens

    @property
    def cache_creation_input_tokens(self) -> int:
        return self.total.cache_creation_input_tokens

    @property
    def cache_read_input_tokens(self) -> int:
        return self.total.cache_read_input_tokens


_tracker = UsageTotals()


def reset() -> None:
    global _tracker
    _tracker = UsageTotals()


def get() -> UsageTotals:
    return _tracker


def accumulate_pllm(usage: anthropic.types.Usage) -> None:
    _tracker.pllm.input_tokens += usage.input_tokens or 0
    _tracker.pllm.output_tokens += usage.output_tokens or 0
    _tracker.pllm.cache_creation_input_tokens += getattr(usage, "cache_creation_input_tokens", 0) or 0
    _tracker.pllm.cache_read_input_tokens += getattr(usage, "cache_read_input_tokens", 0) or 0


def accumulate_qllm(usage) -> None:
    """Accept a pydantic_ai Usage object. The details dict carries the raw breakdown."""
    details = (usage.details or {}) if usage is not None else {}
    _tracker.qllm.input_tokens += details.get("input_tokens", 0)
    _tracker.qllm.output_tokens += details.get("output_tokens", 0)
    _tracker.qllm.cache_creation_input_tokens += details.get("cache_creation_input_tokens", 0)
    _tracker.qllm.cache_read_input_tokens += details.get("cache_read_input_tokens", 0)


# ---------------------------------------------------------------------------
# Async Anthropic client wrapper — intercepts P-LLM usage
# ---------------------------------------------------------------------------


class _TrackedAsyncStream:
    """Wraps an AsyncMessageStreamManager to capture usage from get_final_message()."""

    def __init__(self, stream_cm):
        self._cm = stream_cm
        self._stream = None

    async def __aenter__(self):
        self._stream = await self._cm.__aenter__()
        return self

    async def __aexit__(self, *args):
        return await self._cm.__aexit__(*args)

    async def get_final_message(self):
        msg = await self._stream.get_final_message()
        if msg.usage is not None:
            accumulate_pllm(msg.usage)
        return msg

    def __getattr__(self, name):
        return getattr(self._stream, name)


class _TrackedAsyncMessages:
    """Wraps the AsyncMessages resource to intercept stream() calls."""

    def __init__(self, messages):
        self._messages = messages

    def stream(self, *args, **kwargs):
        return _TrackedAsyncStream(self._messages.stream(*args, **kwargs))

    def __getattr__(self, name):
        return getattr(self._messages, name)


class TrackedAsyncAnthropic(AsyncAnthropic):
    """AsyncAnthropic subclass that accumulates token usage into the global tracker."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.messages = _TrackedAsyncMessages(self.messages)

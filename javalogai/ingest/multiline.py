"""Reassembles physical lines into logical events.

This is the layer that batch log tooling built for single-line formats does not
have, and it is why such tooling degrades on JVM logs: a stack trace arrives as
40+ physical lines that are all one event. Feeding them to a template miner
individually mints a junk template per distinct frame combination and buries the
real signal.

Strategy, in order of preference:

1. **Header-driven** (robust, the default). A new event begins at any line
   matching a header pattern -- in practice a leading timestamp. Everything
   after it belongs to that event until the next header. This copes with
   arbitrary junk inside a trace, including multi-line exception messages,
   `Caused by:` chains and interleaved framework noise.
2. **Heuristic fallback**, used only for lines appearing before any header has
   matched (truncated file, unknown format). A line is treated as a
   continuation if it looks like one: indented, a frame, a `Caused by:`, an
   `... N more`, or a bare fully-qualified throwable name.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Iterator

# A line starting an event: leading timestamp in any of the common JVM layouts.
# 2024-01-15 10:23:45.123 | 2024-01-15T10:23:45,123 | 15-Jan-2024 10:23:45
DEFAULT_HEADER_PATTERN = re.compile(
    r"""^(?:
        \d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}
      | \d{2}[-/][A-Za-z]{3}[-/]\d{4}\s+\d{2}:\d{2}:\d{2}
      | \[\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}
      | \d{2}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}
      | \d{6}\s+\d{6}\s+\d+\s+(?:TRACE|DEBUG|INFO|WARN|ERROR|FATAL)
    )""",
    re.VERBOSE,
)

_FRAME = re.compile(r"^\s+at\s")
_CAUSED_BY = re.compile(r"^\s*(?:Caused by|Suppressed):")
_OMITTED = re.compile(r"^\s*\.\.\.\s*\d+\s+(?:more|common frames omitted)")
# A bare throwable line: fully-qualified class name, optionally followed by ": msg"
_BARE_THROWABLE = re.compile(r"^(?:[\w$]+\.)+[\w$]*(?:Exception|Error|Throwable)[\w$]*(?::|$)")

#: Guard against a pathological trace consuming unbounded memory.
DEFAULT_MAX_LINES = 5000


@dataclass(slots=True)
class RawEvent:
    """A logical event before any parsing: a header line plus its continuations."""

    header: str
    continuations: list[str] = field(default_factory=list)
    line_number: int = 0
    matched_header: bool = False
    truncated: bool = False

    @property
    def raw(self) -> str:
        return "\n".join([self.header, *self.continuations])


def looks_like_continuation(line: str) -> bool:
    """Heuristic used only before the first header match."""
    if not line.strip():
        return False
    return bool(
        _FRAME.match(line)
        or _CAUSED_BY.match(line)
        or _OMITTED.match(line)
        or _BARE_THROWABLE.match(line)
        or (line[:1].isspace() and line.strip())
    )


class MultilineAssembler:
    """Groups an iterable of physical lines into :class:`RawEvent` objects.

    Streaming by construction: it holds at most one in-flight event, so memory
    is bounded by the longest single stack trace rather than by input size.
    """

    def __init__(
        self,
        header_pattern: re.Pattern[str] | str | None = None,
        max_lines: int = DEFAULT_MAX_LINES,
    ) -> None:
        if header_pattern is None:
            self.header_pattern = DEFAULT_HEADER_PATTERN
        elif isinstance(header_pattern, str):
            self.header_pattern = re.compile(header_pattern)
        else:
            self.header_pattern = header_pattern
        self.max_lines = max_lines

    def is_header(self, line: str) -> bool:
        return bool(self.header_pattern.match(line))

    def assemble(self, lines: Iterable[str]) -> Iterator[RawEvent]:
        current: RawEvent | None = None
        seen_header = False

        for lineno, raw_line in enumerate(lines, start=1):
            line = raw_line.rstrip("\n\r")
            if not line.strip() and current is None:
                continue

            if self.is_header(line):
                if current is not None:
                    yield current
                current = RawEvent(header=line, line_number=lineno, matched_header=True)
                seen_header = True
                continue

            if current is None:
                # Nothing in flight and not a header: start an unparsed event.
                current = RawEvent(header=line, line_number=lineno, matched_header=False)
                continue

            # Before the first real header we cannot trust position alone, so fall
            # back to shape. After it, everything up to the next header belongs here.
            if seen_header or looks_like_continuation(line):
                if len(current.continuations) >= self.max_lines:
                    current.truncated = True
                else:
                    current.continuations.append(line)
            else:
                yield current
                current = RawEvent(header=line, line_number=lineno, matched_header=False)

        if current is not None:
            yield current

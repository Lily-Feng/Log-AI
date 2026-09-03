"""Parses the header line of a JVM log event into structured fields.

Patterns are tried in order, most specific first, and the first match wins. Each
supplies named groups; all are optional except `msg`. Add site-specific layouts
by passing extra patterns to :class:`HeaderParser` rather than editing this list.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Iterable, NamedTuple

from ..schema import Severity

_TS = r"(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?)"
_LEVEL = r"(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|SEVERE|FINE|FINER|FINEST)"
_LOGGER = r"(?P<logger>[\w$]+(?:\.[\w$]+)*)"

#: Spring Boot with Micrometer/Sleuth tracing: [service,traceId,spanId]
SPRING_BOOT_TRACED = re.compile(
    rf"^{_TS}\s+{_LEVEL}\s+"
    r"\[(?P<service>[^,\]]*),(?P<trace_id>[0-9a-fA-F]*),(?P<span_id>[0-9a-fA-F]*)[^\]]*\]\s+"
    r"(?P<pid>\d+)?\s*-{2,3}\s*"
    r"\[\s*(?P<thread>[^\]]*?)\s*\]\s+"
    rf"{_LOGGER}\s*:\s*(?P<msg>.*)$"
)

#: Spring Boot default: `ts  LEVEL pid --- [thread] logger : msg`
SPRING_BOOT = re.compile(
    rf"^{_TS}\s+{_LEVEL}\s+(?P<pid>\d+)?\s*-{{2,3}}\s*"
    r"\[\s*(?P<thread>[^\]]*?)\s*\]\s+"
    rf"{_LOGGER}\s*:\s*(?P<msg>.*)$"
)

#: Logback/Log4j2 common: `ts LEVEL [thread] logger - msg`
LOGBACK = re.compile(
    rf"^{_TS}\s+{_LEVEL}\s+\[\s*(?P<thread>[^\]]*?)\s*\]\s+{_LOGGER}\s+[-:]\s+(?P<msg>.*)$"
)

#: Same, without a thread field.
LOGBACK_NO_THREAD = re.compile(rf"^{_TS}\s+{_LEVEL}\s+{_LOGGER}\s+[-:]\s+(?P<msg>.*)$")

#: Last resort: a timestamp and a level, everything after is the message.
GENERIC = re.compile(rf"^{_TS}\s+\[?{_LEVEL}\]?\s+(?P<msg>.*)$")

DEFAULT_PATTERNS: tuple[re.Pattern[str], ...] = (
    SPRING_BOOT_TRACED,
    SPRING_BOOT,
    LOGBACK,
    LOGBACK_NO_THREAD,
    GENERIC,
)

_TS_FORMATS = (
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S,%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S,%f",
    "%Y-%m-%dT%H:%M:%S",
)


def parse_timestamp(text: str | None) -> datetime | None:
    if not text:
        return None
    t = text.strip()
    try:  # ISO-8601 with offset/Z, the cheap path
        return datetime.fromisoformat(t.replace(",", ".").replace("Z", "+00:00"))
    except ValueError:
        pass
    normalized = re.sub(r"(?:Z|[+-]\d{2}:?\d{2})$", "", t)
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(normalized, fmt)
        except ValueError:
            continue
    return None


class Header(NamedTuple):
    timestamp: datetime | None
    severity: Severity
    logger: str | None
    thread: str | None
    message: str
    service: str | None
    trace_id: str | None
    span_id: str | None
    matched: bool


class HeaderParser:
    """Tries each layout in turn; falls back to treating the line as a bare message."""

    def __init__(self, patterns: Iterable[re.Pattern[str]] | None = None) -> None:
        self.patterns = tuple(patterns) if patterns is not None else DEFAULT_PATTERNS

    def parse(self, line: str) -> Header:
        for pattern in self.patterns:
            m = pattern.match(line)
            if not m:
                continue
            g = m.groupdict()
            return Header(
                timestamp=parse_timestamp(g.get("ts")),
                severity=Severity.parse(g.get("level")),
                logger=g.get("logger") or None,
                thread=g.get("thread") or None,
                message=(g.get("msg") or "").strip(),
                service=g.get("service") or None,
                trace_id=(g.get("trace_id") or None),
                span_id=(g.get("span_id") or None),
                matched=True,
            )
        return Header(None, Severity.UNKNOWN, None, None, line.strip(), None, None, None, False)

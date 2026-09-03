"""Core record types.

The schema is OpenTelemetry-shaped so events interoperate with OTel collectors,
but unlike a columnar/DataFrame model each event is a standalone object: events
flow one at a time through the pipeline and never require the whole batch to be
resident. That is what makes the same code usable on a stream.

OTel mapping:
    timestamp     -> Timestamp
    severity      -> SeverityText / SeverityNumber
    message       -> Body
    attributes    -> Attributes
    service       -> Resource["service.name"]
    trace_id/span_id -> TraceId / SpanId

Everything below `# --- JVM-specific ---` has no OTel equivalent; it is the part
that makes this useful for Java rather than for logs in general.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Iterator


class Severity(str, Enum):
    TRACE = "TRACE"
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"
    FATAL = "FATAL"
    UNKNOWN = "UNKNOWN"

    @property
    def number(self) -> int:
        """OTel SeverityNumber."""
        return _SEVERITY_NUMBERS[self]

    @classmethod
    def parse(cls, text: str | None) -> "Severity":
        if not text:
            return cls.UNKNOWN
        t = text.strip().upper()
        if t in ("WARNING",):
            return cls.WARN
        if t in ("SEVERE", "CRITICAL", "CRIT"):
            return cls.FATAL
        if t in ("FINE", "FINER", "FINEST"):
            return cls.DEBUG
        try:
            return cls(t)
        except ValueError:
            return cls.UNKNOWN

    def at_least(self, other: "Severity") -> bool:
        return self.number >= other.number


_SEVERITY_NUMBERS = {
    Severity.TRACE: 1,
    Severity.DEBUG: 5,
    Severity.INFO: 9,
    Severity.WARN: 13,
    Severity.ERROR: 17,
    Severity.FATAL: 21,
    Severity.UNKNOWN: 0,
}


@dataclass(frozen=True, slots=True)
class StackFrame:
    """One `at ...` line of a stack trace."""

    declaring_class: str
    method: str
    file: str | None = None
    line: int | None = None
    module: str | None = None
    is_application: bool = False

    def signature(self, include_line: bool = False) -> str:
        base = f"{self.declaring_class}.{self.method}"
        return f"{base}:{self.line}" if include_line and self.line is not None else base

    def __str__(self) -> str:
        loc = f"{self.file}:{self.line}" if self.file and self.line else (self.file or "Unknown Source")
        return f"at {self.declaring_class}.{self.method}({loc})"


@dataclass(slots=True)
class ExceptionInfo:
    """One link in a throwable chain (the head, or one `Caused by:`)."""

    exception_class: str
    message: str | None = None
    frames: list[StackFrame] = field(default_factory=list)
    omitted_frames: int = 0
    is_suppressed: bool = False

    @property
    def simple_name(self) -> str:
        return self.exception_class.rsplit(".", 1)[-1]


@dataclass(slots=True)
class LogEvent:
    """A single logical log event. A stack trace spanning 40 lines is ONE event."""

    # --- OTel core ---
    timestamp: datetime | None = None
    severity: Severity = Severity.UNKNOWN
    message: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)
    service: str | None = None
    trace_id: str | None = None
    span_id: str | None = None

    # --- provenance ---
    raw: str = ""
    line_number: int | None = None
    parsed: bool = False  # did a header pattern match?

    # --- JVM-specific ---
    logger: str | None = None
    thread: str | None = None
    exceptions: list[ExceptionInfo] = field(default_factory=list)
    fingerprint: str | None = None

    # --- enrichment ---
    template_id: int | None = None
    template: str | None = None
    is_new_template: bool = False
    scrub_hits: dict[str, int] = field(default_factory=dict)

    @property
    def has_exception(self) -> bool:
        return bool(self.exceptions)

    @property
    def root_cause(self) -> ExceptionInfo | None:
        """The deepest link in the chain: the `Caused by:` that actually explains it."""
        non_suppressed = [e for e in self.exceptions if not e.is_suppressed]
        return non_suppressed[-1] if non_suppressed else None

    @property
    def exception_chain(self) -> list[str]:
        return [e.exception_class for e in self.exceptions if not e.is_suppressed]

    def iter_frames(self) -> Iterator[StackFrame]:
        for exc in self.exceptions:
            yield from exc.frames

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["severity_number"] = self.severity.number
        d["timestamp"] = self.timestamp.isoformat() if self.timestamp else None
        return d

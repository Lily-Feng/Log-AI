"""Parses a JVM stack trace into a structured throwable chain.

Two things here carry most of the downstream value:

* **The chain**, not just the head. `ServiceException` tells you nothing;
  the `Caused by: java.sql.SQLTransientConnectionException` at the bottom is the
  actual defect. :attr:`LogEvent.root_cause` reads the last link.
* **Application vs framework frames.** A 60-frame trace typically contains 4
  frames of your code and 56 of Tomcat, Spring and Hibernate. Grouping on the
  whole trace splits one bug across every entry path that reaches it; grouping
  on the application frames alone collapses them correctly. That classification
  is made here so it happens in a single pass.
"""

from __future__ import annotations

import re
from typing import Callable, Iterable, Sequence

from ..schema import ExceptionInfo, StackFrame

#: Packages treated as infrastructure. Frames in these are excluded from
#: fingerprints unless a trace contains nothing else.
FRAMEWORK_PREFIXES: tuple[str, ...] = (
    "java.", "javax.", "jakarta.", "jdk.", "sun.", "com.sun.", "kotlin.", "scala.",
    "org.springframework.", "org.apache.", "org.hibernate.", "org.jboss.",
    "org.eclipse.jetty.", "io.undertow.", "org.glassfish.", "io.netty.",
    "reactor.", "io.micrometer.", "io.opentelemetry.",
    "com.zaxxer.hikari.", "com.mysql.", "org.postgresql.", "oracle.jdbc.",
    "com.fasterxml.jackson.", "com.google.common.",
    "ch.qos.logback.", "org.slf4j.", "org.apache.logging.",
    "org.junit.", "org.mockito.", "org.aspectj.", "net.sf.cglib.", "javassist.",
)

_FRAME = re.compile(
    r"^\s*at\s+(?:(?P<module>[\w.$]+(?:@[\w.\-]+)?)/)?"
    r"(?P<decl>[\w$]+(?:\.[\w$]+)*)\.(?P<method>[\w$<>]+)"
    r"\((?P<src>[^)]*)\)"
)
_CAUSED_BY = re.compile(r"^\s*Caused by:\s*(?P<rest>.*)$")
_SUPPRESSED = re.compile(r"^\s*Suppressed:\s*(?P<rest>.*)$")
_OMITTED = re.compile(r"^\s*\.\.\.\s*(?P<n>\d+)\s+(?:more|common frames omitted)")
_THROWABLE = re.compile(r"^\s*(?P<cls>(?:[\w$]+\.)+[\w$]+|[\w$]*(?:Exception|Error|Throwable)[\w$]*)"
                        r"(?::\s?(?P<msg>.*))?$")
_SRC_LINE = re.compile(r"^(?P<file>[^:]+):(?P<line>\d+)$")

FrameClassifier = Callable[[str], bool]


def is_application_frame(declaring_class: str, app_packages: Sequence[str] | None = None) -> bool:
    """True if the frame is your code.

    When `app_packages` is given (recommended -- e.g. `("com.visa.",)`) the test
    is an allow-list, which is exact. Otherwise it is a deny-list against
    :data:`FRAMEWORK_PREFIXES`, which is a decent default but will misclassify
    vendor code that does not look like a framework.
    """
    if app_packages:
        return any(declaring_class.startswith(p) for p in app_packages)
    return not declaring_class.startswith(FRAMEWORK_PREFIXES)


def parse_frame(line: str, classifier: FrameClassifier) -> StackFrame | None:
    m = _FRAME.match(line)
    if not m:
        return None
    src = (m.group("src") or "").strip()
    file_name: str | None = None
    line_no: int | None = None
    if sm := _SRC_LINE.match(src):
        file_name, line_no = sm.group("file"), int(sm.group("line"))
    elif src and src not in ("Native Method", "Unknown Source"):
        file_name = src
    decl = m.group("decl")
    return StackFrame(
        declaring_class=decl,
        method=m.group("method"),
        file=file_name,
        line=line_no,
        module=m.group("module"),
        is_application=classifier(decl),
    )


def _split_throwable(text: str) -> tuple[str, str | None] | None:
    m = _THROWABLE.match(text.strip())
    if not m:
        return None
    return m.group("cls"), (m.group("msg") or None)


def parse_exception_chain(
    lines: Iterable[str],
    app_packages: Sequence[str] | None = None,
) -> list[ExceptionInfo]:
    """Parse continuation lines into an ordered chain.

    Index 0 is the outermost throwable; each subsequent non-suppressed entry is
    a `Caused by:`, so the last one is the root cause.
    """

    def classify(decl: str) -> bool:
        return is_application_frame(decl, app_packages)

    chain: list[ExceptionInfo] = []
    current: ExceptionInfo | None = None

    for line in lines:
        if not line.strip():
            continue

        if frame := parse_frame(line, classify):
            if current is not None:
                current.frames.append(frame)
            continue

        if m := _OMITTED.match(line):
            if current is not None:
                current.omitted_frames = int(m.group("n"))
            continue

        for pattern, suppressed in ((_CAUSED_BY, False), (_SUPPRESSED, True)):
            if m := pattern.match(line):
                if parts := _split_throwable(m.group("rest")):
                    cls, msg = parts
                    current = ExceptionInfo(cls, msg, is_suppressed=suppressed)
                    chain.append(current)
                break
        else:
            # Not a frame, not a chain marker: either the head throwable or a
            # continuation of the previous exception's message.
            parts = _split_throwable(line)
            if parts and (current is None or current.frames):
                cls, msg = parts
                current = ExceptionInfo(cls, msg)
                chain.append(current)
            elif current is not None and not current.frames:
                extra = line.strip()
                current.message = f"{current.message}\n{extra}" if current.message else extra

    return chain

"""Stable identity for a failure.

The question the explain stage has to answer is "is this the same bug as last
Tuesday?".
Grouping by exception class is far too coarse -- half a large codebase throws
`NullPointerException`. Grouping by the full stack trace is far too fine: the
same defect reached through a REST controller, a Kafka consumer and a scheduled
job produces three different traces and looks like three incidents.

The fingerprint therefore combines:

* the throwable chain (outermost class through root cause), and
* the top N *application* frames, ignoring framework noise.

Two defaults encode that intent, and both are deliberate:

`top_n=1` -- hash only the throw site. Frames run innermost-first, so frame 0 is
where the exception was raised and later frames are the call path that reached
it. Including more than one frame re-introduces exactly the split we are trying
to avoid: the REST path and the Kafka path share frame 0 but diverge at frame 1.
Raise `top_n` only if you want path-sensitive grouping and accept the split.

`include_lines=False` -- a fingerprint should not change because someone added
an import above the throw site. Set it True if you would rather split
aggressively than merge two distinct bugs that share a method.
"""

from __future__ import annotations

import hashlib
from typing import Sequence

from ..schema import ExceptionInfo, StackFrame

DEFAULT_TOP_N = 1
DIGEST_LENGTH = 16


def _relevant_frames(
    chain: Sequence[ExceptionInfo], top_n: int
) -> tuple[list[StackFrame], bool]:
    """Application frames across the chain, or all frames if there are none."""
    app = [f for exc in chain for f in exc.frames if f.is_application]
    if app:
        return app[:top_n], True
    allf = [f for exc in chain for f in exc.frames]
    return allf[:top_n], False


def fingerprint_exception(
    chain: Sequence[ExceptionInfo],
    top_n: int = DEFAULT_TOP_N,
    include_lines: bool = False,
) -> str | None:
    """Return a short stable digest for a throwable chain, or None if empty."""
    if not chain:
        return None

    classes = [e.exception_class for e in chain if not e.is_suppressed]
    frames, app_only = _relevant_frames(chain, top_n)

    parts = [
        "v1",
        "chain=" + ">".join(classes),
        "scope=" + ("app" if app_only else "all"),
        "frames=" + "|".join(f.signature(include_lines) for f in frames),
    ]
    digest = hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()
    return digest[:DIGEST_LENGTH]


def describe_fingerprint(chain: Sequence[ExceptionInfo], top_n: int = DEFAULT_TOP_N) -> str:
    """Human-readable form of what the fingerprint hashed. Used in reports."""
    if not chain:
        return ""
    root = [e for e in chain if not e.is_suppressed][-1]
    frames, app_only = _relevant_frames(chain, top_n)
    scope = "app frames" if app_only else "all frames (no application frames present)"
    top = frames[0].signature() if frames else "no frames"
    return f"{root.simple_name} at {top} [{scope}]"

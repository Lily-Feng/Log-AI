"""Redacts sensitive values before anything leaves the host.

Placement matters as much as the rules: this runs in tier 1, on the box, ahead
of template mining and long before any model call. Everything downstream sees
redacted text only, so the "does data cross a boundary" review covers masked
templates rather than raw payment logs.

Card numbers are matched by shape *and* validated with the Luhn checksum. Shape
alone is unusable here -- a 16-digit order id, an epoch-nanos timestamp and a
trace id all match `\\d{16}` -- and over-redaction destroys the debuggability
that justifies keeping logs at all.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Iterable, NamedTuple

Replacer = Callable[[re.Match[str]], str]


class Rule(NamedTuple):
    name: str
    pattern: re.Pattern[str]
    replacement: str | Replacer
    #: Rules that are useful but too aggressive for every deployment.
    optional: bool = False


def luhn_valid(digits: str) -> bool:
    """Standard mod-10 checksum used by all major card networks."""
    if not digits.isdigit() or not 13 <= len(digits) <= 19:
        return False
    total, parity = 0, len(digits) % 2
    for i, ch in enumerate(digits):
        d = ord(ch) - 48
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _make_pan_replacer(keep_last4: bool) -> Replacer:
    def replace(m: re.Match[str]) -> str:
        raw = m.group(0)
        digits = re.sub(r"[ -]", "", raw)
        if not luhn_valid(digits):
            return raw  # shape matched but checksum failed: leave it alone
        return f"[PAN:...{digits[-4:]}]" if keep_last4 else "[PAN]"

    return replace


# Ordered: earlier rules win the text they consume.
_JWT = Rule("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+"), "[JWT]")
_BEARER = Rule("bearer", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"), "Bearer [REDACTED]")
_SECRET_KV = Rule(
    "secret_kv",
    re.compile(
        r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|"
        r"refresh[_-]?token|id[_-]?token|auth[_-]?token|token|authorization|"
        r"private[_-]?key|client[_-]?secret|credential[s]?)"
        r"(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;&)}\]]+)"
    ),
    r"\1\2[REDACTED]",
)
_CVV = Rule("cvv", re.compile(r"(?i)\b(cvv2?|cvc2?|cid|csc)(\s*[=:]\s*)(\d{3,4})\b"), r"\1\2[CVV]")
_EMAIL = Rule("email", re.compile(r"\b[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}\b"), "[EMAIL]")
_SSN = Rule("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN]")
_IBAN = Rule("iban", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"), "[IBAN]")
_IPV4 = Rule("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[IP]", optional=True)
_PHONE = Rule("phone", re.compile(r"(?<!\d)\+?\d{1,2}[ -]?\(?\d{3}\)?[ -]\d{3}[ -]\d{4}(?!\d)"), "[PHONE]", optional=True)
_UUID = Rule(
    "uuid",
    re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
    "[UUID]",
    optional=True,
)


@dataclass(slots=True)
class ScrubResult:
    text: str
    hits: dict[str, int] = field(default_factory=dict)

    @property
    def redacted(self) -> bool:
        return bool(self.hits)


class Scrubber:
    """Applies redaction rules in order, counting every hit.

    The hit counts are not decoration: "we redacted N PANs from M events today"
    is the evidence an auditor asks for, and a sudden change in the count is
    itself a signal that an upstream service started logging something new.
    """

    def __init__(
        self,
        enable_optional: Iterable[str] = (),
        disable: Iterable[str] = (),
        pan_keep_last4: bool = False,
        extra_rules: Iterable[Rule] = (),
    ) -> None:
        # The guards must exclude word characters, not just digits: a hex trace id
        # such as `c69589cd62e07957166693998c2eb4ef` contains a 14-digit run that
        # passes Luhn roughly one time in ten. Matching it would both raise false
        # PAN alarms and corrupt the trace id that correlation depends on.
        pan = Rule("pan", re.compile(r"(?<![\w.])(?:\d[ -]?){12,18}\d(?![\w.])"),
                   _make_pan_replacer(pan_keep_last4))
        base = [_JWT, _BEARER, _SECRET_KV, _CVV, _EMAIL, _SSN, _IBAN, pan, _PHONE, _IPV4, _UUID]
        enabled = set(enable_optional)
        disabled = set(disable)
        self.rules: list[Rule] = [
            r for r in [*base, *extra_rules]
            if r.name not in disabled and (not r.optional or r.name in enabled)
        ]
        self.totals: Counter[str] = Counter()

    def scrub(self, text: str | None, track: bool = True) -> ScrubResult:
        """Redact `text`. Set `track=False` when rescrubbing a field already
        counted via the full raw record, so audit totals are not double counted."""
        if not text:
            return ScrubResult(text or "")
        hits: dict[str, int] = {}
        out = text
        for rule in self.rules:
            if callable(rule.replacement):
                # A callable replacer may decline (a Luhn failure leaves the text
                # alone), so count what actually changed rather than what matched
                # -- "we redacted N card numbers" has to be literally true.
                applied = 0

                def _replace(m: re.Match[str], _rule: Rule = rule) -> str:
                    nonlocal applied
                    replaced = _rule.replacement(m)
                    if replaced != m.group(0):
                        applied += 1
                    return replaced

                out = rule.pattern.sub(_replace, out)
                n = applied
            else:
                out, n = rule.pattern.subn(rule.replacement, out)
            if n:
                hits[rule.name] = hits.get(rule.name, 0) + n
        if track:
            self.totals.update(hits)
        return ScrubResult(out, hits)

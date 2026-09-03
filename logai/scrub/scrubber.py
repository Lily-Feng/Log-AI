"""Redacts sensitive values before anything leaves the host.

Placement matters as much as the rules: this runs in detect, on the box, ahead
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
from typing import Callable, Container, Iterable, NamedTuple

Replacer = Callable[[re.Match[str]], str]


class Rule(NamedTuple):
    name: str
    pattern: re.Pattern[str]
    replacement: str | Replacer
    #: Rules that are useful but too aggressive for every deployment.
    optional: bool = False


#: Issuer Identification Number prefixes and the card lengths each network
#: actually issues. Luhn alone is not enough at volume: roughly one in ten
#: random digit runs passes the checksum, so on a corpus with millisecond epoch
#: timestamps (13 digits, and every one of them starting with `1`) the checksum
#: leaks a steady trickle of false positives. No network issues cards starting
#: with 0, 1, 7, 8 or 9, so the prefix test removes that entire class.
_CARD_NETWORKS: tuple[tuple[str, re.Pattern[str], frozenset[int]], ...] = (
    ("visa", re.compile(r"^4"), frozenset({13, 16, 19})),
    ("mastercard",
     re.compile(r"^(?:5[1-5]|2(?:22[1-9]|2[3-9]\d|[3-6]\d{2}|7[01]\d|720))"),
     frozenset({16})),
    ("amex", re.compile(r"^3[47]"), frozenset({15})),
    ("discover",
     re.compile(r"^(?:6011|64[4-9]|65|622(?:12[6-9]|1[3-9]\d|[2-8]\d{2}|9[01]\d|92[0-5]))"),
     frozenset({16, 19})),
    ("jcb", re.compile(r"^35(?:2[89]|[3-8]\d)"), frozenset({16, 17, 18, 19})),
    ("diners", re.compile(r"^3(?:0[0-5]|095|[68])"), frozenset({14, 16, 19})),
    ("unionpay", re.compile(r"^62"), frozenset({16, 17, 18, 19})),
    ("maestro",
     re.compile(r"^(?:5018|5020|5038|5893|6304|6759|676[1-3])"),
     frozenset(range(12, 20))),
)


def card_network(digits: str, allowed_lengths: Container[int] | None = None) -> str | None:
    """Name the issuing network whose IIN and length the digits match, if any.

    `allowed_lengths` narrows acceptance to the card lengths your systems
    actually handle. It only ever removes matches, so it trades recall for
    precision and must be set deliberately -- see :class:`Scrubber`.
    """
    length = len(digits)
    if allowed_lengths is not None and length not in allowed_lengths:
        return None
    for name, prefix, lengths in _CARD_NETWORKS:
        if length in lengths and prefix.match(digits):
            return name
    return None


def is_probable_card(digits: str, allowed_lengths: Container[int] | None = None) -> bool:
    """A card number must look like one *and* checksum. Both, not either."""
    return bool(
        digits.isdigit()
        and card_network(digits, allowed_lengths)
        and luhn_valid(digits)
    )


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


def _make_pan_replacer(keep_last4: bool, allowed_lengths: Container[int] | None) -> Replacer:
    def replace(m: re.Match[str]) -> str:
        raw = m.group(0)
        digits = re.sub(r"[ -]", "", raw)
        if not is_probable_card(digits, allowed_lengths):
            return raw  # not a card shape, or checksum failed: leave it alone
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
        pan_lengths: Iterable[int] | None = None,
        extra_rules: Iterable[Rule] = (),
    ) -> None:
        """`pan_lengths` narrows PAN matching to those card lengths.

        Leave it unset unless you know what your systems carry. The default
        accepts every length the networks issue, which is the safe direction:
        over-redaction costs debuggability, under-redaction costs a PCI finding.

        It exists because 19 digits is a legitimate Visa length and also the
        shape of a Spark RPC request id. Across 33.2M lines of real Spark logs
        seven such ids passed both the IIN and Luhn tests -- a rate of roughly
        one in five million lines, but not zero, and each one corrupts an
        identifier that correlation depends on. A shop that only ever handles
        16-digit cards can pass `pan_lengths={16}` and remove the class.
        """
        # The guards must exclude word characters, not just digits: a hex trace id
        # such as `c69589cd62e07957166693998c2eb4ef` contains a 14-digit run that
        # passes Luhn roughly one time in ten. Matching it would both raise false
        # PAN alarms and corrupt the trace id that correlation depends on.
        lengths = frozenset(pan_lengths) if pan_lengths is not None else None
        pan = Rule("pan", re.compile(r"(?<![\w.])(?:\d[ -]?){12,18}\d(?![\w.])"),
                   _make_pan_replacer(pan_keep_last4, lengths))
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

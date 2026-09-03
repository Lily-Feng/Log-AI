"""Detect: the deterministic path. No model calls, no network, no tokens.

    raw lines
      -> MultilineAssembler   one logical event per stack trace
      -> HeaderParser         timestamp, severity, logger, thread, trace ids
      -> Scrubber             PAN/PII redaction, before anything is stored
      -> parse_exception_chain  throwable chain + application frames
      -> fingerprint_exception  stable identity for the failure
      -> TemplateMiner        drain3 template id
      -> BaselineDetector     novelty / rate breach / severity burst
      -> Signal               the hand-off record to react and explain

Cost here is CPU-per-line and nothing else, which is what lets it run over the
full firehose. Only :class:`Signal` objects travel further, so spend downstream
scales with incidents rather than with volume.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Iterator, Sequence

from .baseline.detector import BaselineDetector, DetectorConfig, Signal
from .ingest.exceptions import parse_exception_chain
from .ingest.java_format import HeaderParser
from .ingest.multiline import MultilineAssembler, RawEvent
from .schema import LogEvent, Severity
from .scrub.scrubber import Scrubber
from .template.fingerprint import DEFAULT_TOP_N, fingerprint_exception
from .template.miner import MinerConfig, TemplateMiner


@dataclass(slots=True)
class PipelineConfig:
    #: Your own package prefixes, e.g. ("com.visa.",). Supplying these turns frame
    #: classification into an exact allow-list instead of a framework deny-list,
    #: and is the single highest-value piece of configuration here.
    app_packages: Sequence[str] = ()
    default_service: str | None = None
    header_pattern: re.Pattern[str] | str | None = None
    fingerprint_top_n: int = DEFAULT_TOP_N
    fingerprint_include_lines: bool = False
    scrub_optional: Sequence[str] = ()
    scrub_disable: Sequence[str] = ()
    pan_keep_last4: bool = False
    #: Narrow PAN matching to these card lengths; None accepts all issued lengths.
    pan_lengths: Sequence[int] | None = None
    miner: MinerConfig = field(default_factory=MinerConfig)
    detector: DetectorConfig = field(default_factory=DetectorConfig)


@dataclass(slots=True)
class PipelineStats:
    raw_lines: int = 0
    events: int = 0
    parsed_events: int = 0
    events_with_exception: int = 0
    errors: int = 0
    redacted_events: int = 0
    templates: int = 0
    fingerprints: int = 0
    signals: int = 0

    @property
    def compression(self) -> float:
        """Raw lines per distinct template -- the economics in one number."""
        return self.raw_lines / self.templates if self.templates else 0.0


class Pipeline:
    def __init__(self, config: PipelineConfig | None = None) -> None:
        self.config = config or PipelineConfig()
        self.assembler = MultilineAssembler(self.config.header_pattern)
        self.header_parser = HeaderParser()
        self.scrubber = Scrubber(
            enable_optional=self.config.scrub_optional,
            disable=self.config.scrub_disable,
            pan_keep_last4=self.config.pan_keep_last4,
            pan_lengths=self.config.pan_lengths,
        )
        self.miner = TemplateMiner(self.config.miner)
        self.detector = BaselineDetector(self.config.detector)
        self.stats = PipelineStats()

    # -- single event ------------------------------------------------------
    def build_event(self, raw: RawEvent) -> LogEvent:
        header = self.header_parser.parse(raw.header)

        # Scrub the whole record once for storage and for the audit trail, then
        # rescrub individual fields untracked so counts are not doubled.
        scrubbed_raw = self.scrubber.scrub(raw.raw)
        message = self.scrubber.scrub(header.message, track=False).text

        chain = parse_exception_chain(raw.continuations, self.config.app_packages)
        for exc in chain:
            if exc.message:
                exc.message = self.scrubber.scrub(exc.message, track=False).text

        event = LogEvent(
            timestamp=header.timestamp,
            severity=header.severity,
            message=message,
            service=header.service or self.config.default_service,
            trace_id=header.trace_id,
            span_id=header.span_id,
            raw=scrubbed_raw.text,
            line_number=raw.line_number,
            parsed=header.matched,
            logger=header.logger,
            thread=header.thread,
            exceptions=chain,
            scrub_hits=scrubbed_raw.hits,
        )
        event.fingerprint = fingerprint_exception(
            chain,
            top_n=self.config.fingerprint_top_n,
            include_lines=self.config.fingerprint_include_lines,
        )

        # Mine on the message only. Including the stack trace would make every
        # distinct frame combination its own template, which is the failure mode
        # this whole layer exists to prevent.
        if mined := self.miner.mine(message):
            event.template_id = mined.template_id
            event.template = mined.template
            event.is_new_template = mined.is_new

        return event

    # -- streaming ---------------------------------------------------------
    def stream(self, lines: Iterable[str]) -> Iterator[tuple[LogEvent, list[Signal]]]:
        """Yield each event with any signals it triggered. Constant memory."""
        counted = self._counting(lines)
        for raw in self.assembler.assemble(counted):
            event = self.build_event(raw)
            self._tally(event)
            signals = list(self.detector.observe(event))
            self.stats.signals += len(signals)
            yield event, signals
        self._finalize()

    def events(self, lines: Iterable[str]) -> Iterator[LogEvent]:
        for event, _ in self.stream(lines):
            yield event

    def run(self, lines: Iterable[str]) -> tuple[list[LogEvent], list[Signal]]:
        """Convenience for batch use: materialises everything."""
        events: list[LogEvent] = []
        signals: list[Signal] = []
        for event, sigs in self.stream(lines):
            events.append(event)
            signals.extend(sigs)
        trailing = list(self.detector.flush())
        self.stats.signals += len(trailing)
        signals.extend(trailing)
        self._finalize()
        return events, signals

    # -- internals ---------------------------------------------------------
    def _counting(self, lines: Iterable[str]) -> Iterator[str]:
        for line in lines:
            self.stats.raw_lines += 1
            yield line

    def _tally(self, event: LogEvent) -> None:
        s = self.stats
        s.events += 1
        s.parsed_events += int(event.parsed)
        s.events_with_exception += int(event.has_exception)
        s.errors += int(event.severity.at_least(Severity.ERROR))
        s.redacted_events += int(bool(event.scrub_hits))

    def _finalize(self) -> None:
        self.stats.templates = self.miner.template_count
        self.stats.fingerprints = len(self.detector.seen_fingerprints)

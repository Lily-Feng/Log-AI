"""Decides which events are worth a model call.

This is the gate that makes the economics work. Everything upstream is
arithmetic over templates; everything downstream (embedding, LLM triage) is paid
per call. A signal emitted here is the unit of work handed to the expensive
tiers, so the volume of signals -- not the volume of logs -- sets the bill.

Three detectors, cheapest first:

* **novelty** -- a template or exception fingerprint never seen before. Free:
  it is a set membership test, and it is the highest-value signal in practice
  because a genuinely new message usually means a genuinely new condition.
* **rate breach** -- a known template firing far outside its own baseline,
  tracked with an EWMA of mean and variance so each template is compared only
  against itself. A template that normally fires 10,000 times a minute and one
  that fires twice an hour both get sensible thresholds without hand-tuning.
* **severity burst** -- aggregate ERROR/FATAL volume for a service, which
  catches broad degradation that no single template makes obvious.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

from ..schema import LogEvent, Severity
from .counters import Bucket, TimeBucketCounter

NOVEL_TEMPLATE = "novel_template"
NOVEL_FINGERPRINT = "novel_fingerprint"
RATE_BREACH = "rate_breach"
SEVERITY_BURST = "severity_burst"


@dataclass(slots=True)
class Signal:
    """A candidate incident. The hand-off record to tier 2/3."""

    kind: str
    key: str
    detail: str
    observed: float = 0.0
    expected: float | None = None
    score: float | None = None
    bucket_start: datetime | None = None
    service: str | None = None
    template_id: int | None = None
    template: str | None = None
    fingerprint: str | None = None
    sample: LogEvent | None = None

    def to_dict(self, include_sample: bool = True) -> dict[str, Any]:
        d = {
            "kind": self.kind,
            "key": self.key,
            "detail": self.detail,
            "observed": self.observed,
            "expected": self.expected,
            "score": self.score,
            "bucket_start": self.bucket_start.isoformat() if self.bucket_start else None,
            "service": self.service,
            "template_id": self.template_id,
            "template": self.template,
            "fingerprint": self.fingerprint,
        }
        if include_sample and self.sample is not None:
            d["sample"] = self.sample.to_dict()
        return d


@dataclass(slots=True)
class _Ewma:
    """Exponentially weighted mean and variance."""

    alpha: float
    mean: float = 0.0
    var: float = 0.0
    n: int = 0

    def update(self, x: float) -> None:
        if self.n == 0:
            self.mean, self.var = x, 0.0
        else:
            delta = x - self.mean
            self.mean += self.alpha * delta
            self.var = (1 - self.alpha) * (self.var + self.alpha * delta * delta)
        self.n += 1

    @property
    def stddev(self) -> float:
        return math.sqrt(self.var)

    def zscore(self, x: float) -> float:
        # A template with a perfectly flat history has zero variance; fall back to
        # a relative comparison so a flat 5 -> 500 still scores, rather than /0.
        sd = self.stddev
        if sd < 1e-9:
            return 0.0 if x <= self.mean else (x - self.mean) / max(self.mean, 1.0)
        return (x - self.mean) / sd


@dataclass(slots=True)
class DetectorConfig:
    bucket_seconds: int = 60
    window: int = 60
    alpha: float = 0.3
    #: Buckets of history required before a rate breach can fire.
    min_observations: int = 5
    #: Absolute floor: 1 -> 3 occurrences is not an incident.
    min_count: int = 10
    z_threshold: float = 3.0
    #: Observed must also be this multiple of the baseline. A z-score alone is
    #: too eager on high-volume templates: ordinary jitter of 27 -> 34 requests a
    #: minute clears z=3 while being entirely normal. Requiring a real multiple
    #: as well is what separates an incident from noise.
    min_ratio: float = 2.0
    #: Cap on novelty signals per template/fingerprint (they only fire once anyway)
    report_novel_templates: bool = True
    report_novel_fingerprints: bool = True
    error_burst_min: int = 20
    error_burst_z: float = 3.0
    #: Where to persist fingerprints and EWMA baselines between runs. Without it
    #: a restart re-warms from zero and re-announces known failures as novel.
    state_path: str | None = None


class BaselineDetector:
    def __init__(self, config: DetectorConfig | None = None) -> None:
        self.config = config or DetectorConfig()
        self.counter = TimeBucketCounter(self.config.bucket_seconds, self.config.window)
        self.error_counter = TimeBucketCounter(self.config.bucket_seconds, self.config.window)
        self._baselines: dict[tuple[str | None, int], _Ewma] = {}
        self._error_baselines: dict[str | None, _Ewma] = {}
        self.seen_templates: set[int] = set()
        self.seen_fingerprints: set[str] = set()
        self._samples: dict[tuple[str | None, int], LogEvent] = {}
        self._meta: dict[tuple[str | None, int], str] = {}
        if self.config.state_path:
            self.load_state(self.config.state_path)

    def observe(self, event: LogEvent) -> Iterator[Signal]:
        """Feed one event; yields any signals it produces."""
        # --- novelty: free, and fires immediately rather than at bucket close ---
        # Novelty is whether the *miner* had ever seen this template, not whether
        # this process has. drain3 persists that across restarts; a set kept here
        # would not, and would re-announce every template as new after every
        # deploy -- alert spam that bills straight through to tier 3.
        if (
            self.config.report_novel_templates
            and event.template_id is not None
            and event.is_new_template
            and event.template_id not in self.seen_templates
        ):
            self.seen_templates.add(event.template_id)
            yield Signal(
                kind=NOVEL_TEMPLATE,
                key=f"{event.service}/template:{event.template_id}",
                detail=f"first occurrence of template: {event.template}",
                observed=1,
                bucket_start=event.timestamp,
                service=event.service,
                template_id=event.template_id,
                template=event.template,
                sample=event,
            )

        if (
            self.config.report_novel_fingerprints
            and event.fingerprint
            and event.fingerprint not in self.seen_fingerprints
        ):
            self.seen_fingerprints.add(event.fingerprint)
            root = event.root_cause
            yield Signal(
                kind=NOVEL_FINGERPRINT,
                key=f"{event.service}/fingerprint:{event.fingerprint}",
                detail=f"first occurrence of failure: {root.exception_class if root else 'unknown'}",
                observed=1,
                bucket_start=event.timestamp,
                service=event.service,
                fingerprint=event.fingerprint,
                sample=event,
            )

        if event.timestamp is None or event.template_id is None:
            return

        key = (event.service, event.template_id)
        self._samples.setdefault(key, event)
        self._meta.setdefault(key, event.template or "")

        for bucket in self.counter.add(event.timestamp, key):
            yield from self._evaluate(bucket)

        if event.severity.at_least(Severity.ERROR):
            for bucket in self.error_counter.add(event.timestamp, event.service):
                yield from self._evaluate_errors(bucket)

    def _evaluate(self, bucket: Bucket) -> Iterator[Signal]:
        cfg = self.config
        # Keys absent from this bucket counted zero; updating their baselines keeps
        # a quiet period from looking like normal traffic later.
        for key in list(self._baselines.keys() | bucket.counts.keys()):
            count = bucket.counts.get(key, 0)
            baseline = self._baselines.setdefault(key, _Ewma(cfg.alpha))
            if baseline.n >= cfg.min_observations and count >= cfg.min_count:
                z = baseline.zscore(count)
                ratio = count / baseline.mean if baseline.mean > 0 else float("inf")
                if z >= cfg.z_threshold and ratio >= cfg.min_ratio:
                    service, template_id = key
                    yield Signal(
                        kind=RATE_BREACH,
                        key=f"{service}/template:{template_id}",
                        detail=(
                            f"rate {count} in {cfg.bucket_seconds}s vs baseline "
                            f"{baseline.mean:.1f} ({ratio:.1f}x, z={z:.1f})"
                        ),
                        observed=count,
                        expected=baseline.mean,
                        score=z,
                        bucket_start=bucket.start,
                        service=service,
                        template_id=template_id,
                        template=self._meta.get(key),
                        sample=self._samples.get(key),
                    )
            baseline.update(count)

    def _evaluate_errors(self, bucket: Bucket) -> Iterator[Signal]:
        cfg = self.config
        for service in list(self._error_baselines.keys() | bucket.counts.keys()):
            count = bucket.counts.get(service, 0)
            baseline = self._error_baselines.setdefault(service, _Ewma(cfg.alpha))
            if baseline.n >= cfg.min_observations and count >= cfg.error_burst_min:
                z = baseline.zscore(count)
                ratio = count / baseline.mean if baseline.mean > 0 else float("inf")
                if z >= cfg.error_burst_z and ratio >= cfg.min_ratio:
                    yield Signal(
                        kind=SEVERITY_BURST,
                        key=f"{service}/errors",
                        detail=(
                            f"{count} ERROR+ events in {cfg.bucket_seconds}s vs baseline "
                            f"{baseline.mean:.1f} (z={z:.1f})"
                        ),
                        observed=count,
                        expected=baseline.mean,
                        score=z,
                        bucket_start=bucket.start,
                        service=service,
                    )
            baseline.update(count)

    def flush(self) -> Iterator[Signal]:
        for bucket in self.counter.flush():
            yield from self._evaluate(bucket)
        for bucket in self.error_counter.flush():
            yield from self._evaluate_errors(bucket)

    # -- persistence -------------------------------------------------------
    def state_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "fingerprints": sorted(self.seen_fingerprints),
            "baselines": [
                {"service": svc, "template_id": tid, "mean": b.mean, "var": b.var, "n": b.n}
                for (svc, tid), b in self._baselines.items()
            ],
            "error_baselines": [
                {"service": svc, "mean": b.mean, "var": b.var, "n": b.n}
                for svc, b in self._error_baselines.items()
            ],
        }

    def load_state(self, path: str | Path) -> bool:
        """Restore fingerprints and baselines. Returns False if there is nothing to load."""
        p = Path(path)
        if not p.exists():
            return False
        data = json.loads(p.read_text())
        if data.get("version") != 1:
            return False
        self.seen_fingerprints = set(data.get("fingerprints", []))
        alpha = self.config.alpha
        for row in data.get("baselines", []):
            self._baselines[(row["service"], row["template_id"])] = _Ewma(
                alpha, row["mean"], row["var"], row["n"]
            )
        for row in data.get("error_baselines", []):
            self._error_baselines[row["service"]] = _Ewma(alpha, row["mean"], row["var"], row["n"])
        return True

    def save_state(self, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.state_dict(), indent=2))

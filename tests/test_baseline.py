from datetime import datetime, timedelta

from javalogai.baseline.counters import TimeBucketCounter
from javalogai.baseline.detector import (
    NOVEL_TEMPLATE, RATE_BREACH, BaselineDetector, DetectorConfig,
)
from javalogai.schema import LogEvent, Severity

T0 = datetime(2024, 1, 15, 10, 0, 0)


def event(minute, template_id=1, second=0, severity=Severity.INFO, is_new=False):
    return LogEvent(
        timestamp=T0 + timedelta(minutes=minute, seconds=second),
        severity=severity,
        message="m",
        service="svc",
        template_id=template_id,
        template="t",
        is_new_template=is_new,
    )


def run(detector, events):
    out = []
    for e in events:
        out.extend(detector.observe(e))
    out.extend(detector.flush())
    return out


def test_bucket_boundaries():
    c = TimeBucketCounter(bucket_seconds=60)
    assert not list(c.add(T0, "k"))
    assert not list(c.add(T0 + timedelta(seconds=59), "k"))
    closed = list(c.add(T0 + timedelta(seconds=60), "k"))
    assert len(closed) == 1 and closed[0].counts["k"] == 2


def test_empty_intervening_buckets_are_closed_not_skipped():
    c = TimeBucketCounter(bucket_seconds=60)
    list(c.add(T0, "k"))
    closed = list(c.add(T0 + timedelta(minutes=3), "k"))
    assert len(closed) == 3
    assert closed[0].counts["k"] == 1 and closed[1].total == 0 and closed[2].total == 0


def test_novel_template_fires_once():
    d = BaselineDetector()
    signals = run(d, [event(0, is_new=True), event(0, second=1), event(1)])
    assert [s.kind for s in signals].count(NOVEL_TEMPLATE) == 1


def test_rate_breach_fires_on_a_real_spike():
    d = BaselineDetector(DetectorConfig(min_observations=3, min_count=10))
    events = [event(m, second=s) for m in range(10) for s in range(5)]      # 5/min baseline
    events += [event(10, second=s % 59) for s in range(200)]                 # 200 in one minute
    events += [event(11)]                                                    # close the spike bucket
    breaches = [s for s in run(d, events) if s.kind == RATE_BREACH]
    assert len(breaches) == 1
    assert breaches[0].observed == 200 and breaches[0].expected < 10


def test_ordinary_jitter_does_not_fire():
    # Regression: a z-score alone flagged 27 -> 34 requests/min as an incident.
    # The min_ratio guard is what makes this quiet.
    d = BaselineDetector(DetectorConfig(min_observations=3, min_count=10))
    counts = [27, 31, 25, 34, 28, 33, 26, 34, 29, 30]
    events = [event(m, second=i % 59) for m, n in enumerate(counts) for i in range(n)]
    assert [s for s in run(d, events) if s.kind == RATE_BREACH] == []


def test_min_count_floor_suppresses_tiny_absolute_numbers():
    d = BaselineDetector(DetectorConfig(min_observations=3, min_count=50))
    events = [event(m) for m in range(8)] + [event(8, second=s) for s in range(40)] + [event(9)]
    assert [s for s in run(d, events) if s.kind == RATE_BREACH] == []


def test_events_without_timestamp_still_yield_novelty_only():
    d = BaselineDetector()
    e = LogEvent(message="m", template_id=7, template="t", is_new_template=True)
    kinds = [s.kind for s in d.observe(e)]
    assert kinds == [NOVEL_TEMPLATE]


def test_signal_serialises_without_sample():
    d = BaselineDetector()
    sig = next(iter(d.observe(event(0, is_new=True))))
    assert "sample" not in sig.to_dict(include_sample=False)
    assert sig.to_dict()["template_id"] == 1

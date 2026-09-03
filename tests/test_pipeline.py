from pathlib import Path

from javalogai import PipelineConfig, Tier1Pipeline
from javalogai.baseline.detector import NOVEL_FINGERPRINT, NOVEL_TEMPLATE, RATE_BREACH
from javalogai.schema import Severity

FIXTURE = Path(__file__).parent.parent / "fixtures" / "payment-service.log"


def build():
    return Tier1Pipeline(PipelineConfig(app_packages=("com.visa.",), default_service="payment-svc"))


def analyse():
    p = build()
    events, signals = p.run(FIXTURE.read_text().splitlines())
    return p, events, signals


def test_fixture_exists():
    assert FIXTURE.exists(), "run: python fixtures/generate.py"


def test_every_line_parses_into_a_logical_event():
    p, events, _ = analyse()
    assert p.stats.raw_lines > p.stats.events          # traces collapsed
    assert p.stats.parsed_events == p.stats.events     # no unparsed headers


def test_template_compression_is_the_economic_claim():
    p, _, _ = analyse()
    assert p.stats.templates < 10
    assert p.stats.compression > 100                   # >100 raw lines per template


def test_three_stack_traces_collapse_to_one_failure():
    p, events, _ = analyse()
    assert p.stats.events_with_exception == 3
    assert len({e.fingerprint for e in events if e.fingerprint}) == 1


def test_root_cause_is_the_bottom_of_the_chain():
    _, events, _ = analyse()
    failure = next(e for e in events if e.has_exception)
    assert failure.exception_chain[0] == "java.lang.NullPointerException"
    assert failure.root_cause.simple_name == "SQLTransientConnectionException"


def test_cardholder_data_never_survives_into_an_event():
    _, events, _ = analyse()
    for e in events:
        assert "4111111111111111" not in e.raw.replace(" ", "").replace("-", "")
        assert "jane.doe@example.com" not in e.raw
    assert any("[PAN]" in e.message for e in events)


def test_trace_context_survives_scrubbing():
    _, events, _ = analyse()
    traced = [e for e in events if e.trace_id]
    assert len(traced) > 1000
    assert all(len(e.trace_id) == 32 for e in traced)


def test_expected_signals_are_produced():
    _, _, signals = analyse()
    kinds = {s.kind for s in signals}
    assert {NOVEL_TEMPLATE, NOVEL_FINGERPRINT, RATE_BREACH} <= kinds


def test_the_spike_is_the_only_rate_breach():
    _, _, signals = analyse()
    breaches = [s for s in signals if s.kind == RATE_BREACH]
    assert len(breaches) == 1
    assert breaches[0].observed == 200


def test_signals_are_a_tiny_fraction_of_events():
    p, events, signals = analyse()
    assert len(signals) / len(events) < 0.01


def test_streaming_and_batch_agree():
    streamed = [e.template_id for e in build().events(FIXTURE.read_text().splitlines())]
    batch = [e.template_id for e in analyse()[1]]
    assert streamed == batch


def test_severity_parsed():
    _, events, _ = analyse()
    assert {e.severity for e in events} >= {Severity.INFO, Severity.WARN, Severity.ERROR}

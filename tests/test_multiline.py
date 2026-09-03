from javalogai.ingest.multiline import MultilineAssembler

TRACE = """2024-01-15 10:23:45.123 ERROR [main] com.lily.P - boom
java.lang.NullPointerException: acct is null
\tat com.lily.P.run(P.java:1)
\tat com.lily.Q.call(Q.java:2)
\t... 12 common frames omitted
Caused by: java.sql.SQLException: timeout
\tat com.lily.R.db(R.java:3)
2024-01-15 10:23:46.000  INFO [main] com.lily.P - recovered""".split("\n")


def test_stack_trace_is_one_event():
    events = list(MultilineAssembler().assemble(TRACE))
    assert len(events) == 2
    assert events[0].continuations and len(events[0].continuations) == 6
    assert events[1].header.endswith("recovered")


def test_raw_roundtrip_preserves_every_line():
    events = list(MultilineAssembler().assemble(TRACE))
    assert events[0].raw.count("\n") == 6
    assert "Caused by" in events[0].raw


def test_leading_orphan_lines_before_first_header():
    lines = ["\tat com.lily.P.run(P.java:1)", "2024-01-15 10:00:00.000  INFO [m] c.v.P - ok"]
    events = list(MultilineAssembler().assemble(lines))
    assert len(events) == 2
    assert events[0].matched_header is False
    assert events[1].matched_header is True


def test_max_lines_guard_marks_truncated():
    lines = ["2024-01-15 10:00:00.000 ERROR [m] c.v.P - boom"] + [f"\tat com.lily.P.f{i}(P.java:{i})" for i in range(50)]
    events = list(MultilineAssembler(max_lines=10).assemble(lines))
    assert len(events) == 1
    assert events[0].truncated is True
    assert len(events[0].continuations) == 10


def test_blank_lines_between_events_are_dropped():
    lines = ["2024-01-15 10:00:00.000  INFO [m] c.v.P - a", "", "2024-01-15 10:00:01.000  INFO [m] c.v.P - b"]
    assert len(list(MultilineAssembler().assemble(lines))) == 2

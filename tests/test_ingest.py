import pytest

from javalogai.ingest.exceptions import is_application_frame, parse_exception_chain, parse_frame
from javalogai.ingest.java_format import HeaderParser, parse_timestamp
from javalogai.schema import Severity

parser = HeaderParser()


@pytest.mark.parametrize(
    "line,level,logger,thread",
    [
        ("2024-01-15 10:23:45.123  INFO 1 --- [nio-8080-exec-3] c.v.p.PaymentService : ok",
         Severity.INFO, "c.v.p.PaymentService", "nio-8080-exec-3"),
        ("2024-01-15 10:23:45.123 ERROR [http-nio-1] com.lily.P - bad",
         Severity.ERROR, "com.lily.P", "http-nio-1"),
        ("2024-01-15 10:23:45,123 WARN  [main] com.lily.Foo - retry",
         Severity.WARN, "com.lily.Foo", "main"),
    ],
)
def test_layout_variants(line, level, logger, thread):
    h = parser.parse(line)
    assert h.matched and h.severity is level and h.logger == logger and h.thread == thread


def test_trace_context_is_extracted():
    h = parser.parse(
        "2024-01-15 10:23:45.123  INFO [payment-svc,4bf92f3577b34da6,00f067aa0ba902b7] 9 --- [main] c.v.P : hi"
    )
    assert h.service == "payment-svc"
    assert h.trace_id == "4bf92f3577b34da6"
    assert h.span_id == "00f067aa0ba902b7"


def test_unparseable_line_degrades_to_message():
    h = parser.parse("total garbage")
    assert h.matched is False and h.message == "total garbage"
    assert h.severity is Severity.UNKNOWN


def test_timestamp_formats():
    assert parse_timestamp("2024-01-15 10:23:45.123").minute == 23
    assert parse_timestamp("2024-01-15T10:23:45,123").second == 45
    assert parse_timestamp("nonsense") is None


def test_frame_with_jpms_module_prefix():
    f = parse_frame("\tat java.base/java.util.Objects.requireNonNull(Objects.java:233)", lambda c: False)
    assert f.module == "java.base"
    assert f.declaring_class == "java.util.Objects"
    assert f.method == "requireNonNull" and f.line == 233


def test_frame_without_source_location():
    f = parse_frame("\tat com.lily.P.run(Native Method)", lambda c: True)
    assert f.file is None and f.line is None


def test_app_package_allowlist_beats_framework_denylist():
    # A vendor class that does not look like a framework is app code by the
    # deny-list default, but not when an allow-list is supplied.
    assert is_application_frame("com.acme.vendor.Thing") is True
    assert is_application_frame("com.acme.vendor.Thing", ("com.lily.",)) is False
    assert is_application_frame("org.springframework.web.X") is False


CHAIN = """java.lang.IllegalStateException: outer
\tat com.lily.A.a(A.java:1)
\tat org.springframework.X.y(X.java:9)
\t... 42 common frames omitted
Caused by: java.sql.SQLTransientConnectionException: pool timeout
\tat com.lily.B.b(B.java:2)
\t... 3 more""".split("\n")


def test_chain_order_and_root_cause():
    chain = parse_exception_chain(CHAIN, app_packages=("com.lily.",))
    assert [e.exception_class for e in chain] == [
        "java.lang.IllegalStateException", "java.sql.SQLTransientConnectionException"
    ]
    assert chain[0].omitted_frames == 42
    assert chain[1].omitted_frames == 3


def test_application_frames_are_separated_from_framework():
    chain = parse_exception_chain(CHAIN, app_packages=("com.lily.",))
    app = [f.declaring_class for e in chain for f in e.frames if f.is_application]
    assert app == ["com.lily.A", "com.lily.B"]


def test_multiline_exception_message_is_joined():
    chain = parse_exception_chain(
        ["java.lang.IllegalArgumentException: line one", "line two continues", "\tat com.lily.A.a(A.java:1)"],
        app_packages=("com.lily.",),
    )
    assert chain[0].message == "line one\nline two continues"

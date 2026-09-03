import pytest

from logai.ingest.java_format import HeaderParser
from logai.ingest.multiline import MultilineAssembler
from logai.schema import Severity
from logai.sources import loghub

parser = HeaderParser()
JVM = [n for n, d in loghub.DATASETS.items() if d.jvm]


def test_registry_flags_non_jvm_control_case():
    assert loghub.DATASETS["openstack"].jvm is False
    assert set(JVM) == {"hadoop", "zookeeper", "spark", "hdfs"}


def test_no_published_sample_claims_stack_traces():
    # Documented limitation: the 2k samples are single-line. If this ever flips,
    # the README claim and the fixture rationale need revisiting.
    assert all(not d.has_stack_traces for d in loghub.DATASETS.values())


def test_unknown_dataset_rejected():
    with pytest.raises(KeyError):
        loghub.resolve("nope")


@pytest.mark.parametrize("line,level,logger", [
    ("2015-10-18 18:01:47,978 INFO [main] org.apache.hadoop.mapreduce.v2.app.MRAppMaster: Created",
     Severity.INFO, "org.apache.hadoop.mapreduce.v2.app.MRAppMaster"),
    ("17/06/09 20:10:40 INFO executor.CoarseGrainedExecutorBackend: Registered signal handlers",
     Severity.INFO, "executor.CoarseGrainedExecutorBackend"),
    ("081109 203615 148 INFO dfs.DataNode$PacketResponder: PacketResponder 1 terminating",
     Severity.INFO, "dfs.DataNode$PacketResponder"),
])
def test_real_loghub_layouts_parse(line, level, logger):
    h = parser.parse(line)
    assert h.matched and h.severity is level and h.logger == logger


def test_zookeeper_logger_is_unpacked_from_the_thread_bracket():
    h = parser.parse(
        "2015-07-29 17:41:44,747 - INFO  [QuorumPeer[myid=1]/0:0:0:0:0:0:0:0:2181"
        ":FastLeaderElection@774] - Notification time out: 3200"
    )
    assert h.matched
    assert h.logger == "FastLeaderElection"
    assert h.thread == "QuorumPeer[myid=1]/0:0:0:0:0:0:0:0:2181"
    assert h.message == "Notification time out: 3200"


@pytest.mark.parametrize("line", [
    "17/06/09 20:10:40 INFO executor.Backend: x",
    "081109 203615 148 INFO dfs.DataNode: x",
    "2015-10-18 18:01:47,978 INFO [main] o.a.h.MRAppMaster: x",
])
def test_loghub_layouts_are_recognised_as_event_headers(line):
    # Multiline assembly keys off the header pattern; a layout it does not
    # recognise would silently glue every line onto the previous event.
    assert MultilineAssembler().is_header(line)


def test_aws_sources_import_without_boto3():
    from logai.sources.aws import CloudWatchLogsSource, S3LogSource
    assert S3LogSource(bucket="b").prefix == ""
    assert CloudWatchLogsSource(log_group="g").limit is None


def test_aws_source_raises_a_clear_error_without_boto3():
    pytest.importorskip("builtins")
    from logai.sources.aws import S3LogSource
    try:
        import boto3  # noqa: F401
        pytest.skip("boto3 installed; the lazy-import path is not exercised")
    except ImportError:
        pass
    with pytest.raises(ImportError, match="logai\\[aws\\]"):
        list(S3LogSource(bucket="b"))


def test_full_dataset_metadata_matches_what_was_measured():
    hadoop = loghub.resolve("hadoop")
    assert hadoop.full_has_traces is True
    assert hadoop.full_mb == 2.6
    # Only the full archive carries traces; the 2k sample never does.
    assert hadoop.has_stack_traces is False


def test_datasets_without_a_full_archive_are_rejected_clearly():
    from dataclasses import replace
    fake = replace(loghub.resolve("hadoop"), full_mb=None)
    loghub.DATASETS["_fake"] = fake
    try:
        with pytest.raises(ValueError, match="no full archive"):
            loghub.fetch_full("_fake")
    finally:
        del loghub.DATASETS["_fake"]


# -- non-JVM formats: the generality claim, checked ---------------------------

def test_prefixed_timestamp_format_parses():
    # OpenStack leads with a source filename before the real timestamp. Anchoring
    # the timestamp at position 0 gave 0% parse on that corpus, which made
    # templates structural noise (they tokenised the timestamp itself) rather
    # than message semantics.
    h = parser.parse(
        "nova-api.log.1.2017-05-16_13:53:08 2017-05-16 00:00:00.008 25746 INFO "
        "nova.osapi_compute.wsgi.server [req-38101a0b-2096-447d-96ea-a692162415ae "
        "113d3a99 54fadb41 - - -] 10.11.10.1 \"GET /v2/servers/detail HTTP/1.1\" status: 200"
    )
    assert h.matched
    assert h.severity is Severity.INFO
    assert h.logger == "nova.osapi_compute.wsgi.server"
    assert h.timestamp is not None and h.timestamp.year == 2017
    assert h.message.startswith("10.11.10.1")


def test_prefixed_line_is_recognised_as_an_event_header():
    assert MultilineAssembler().is_header(
        "nova-api.log.1.2017-05-16_13:53:08 2017-05-16 00:00:00.008 25746 INFO nova.x: msg"
    )


@pytest.mark.parametrize("line", [
    "\tat com.lily.payments.PaymentService.authorize(PaymentService.java:142)",
    "Caused by: java.sql.SQLException: timeout",
    "\t... 42 common frames omitted",
])
def test_widening_the_header_pattern_did_not_swallow_continuations(line):
    # The prefix group allows a leading token before the timestamp. Continuation
    # lines must still not look like the start of a new event, or every stack
    # trace would fragment.
    assert not MultilineAssembler().is_header(line)


def test_non_jvm_logs_use_the_pipeline_without_the_exception_layer():
    from logai import PipelineConfig, Tier1Pipeline
    pipeline = Tier1Pipeline(PipelineConfig(default_service="openstack"))
    events = list(pipeline.events(loghub.load("openstack")))
    assert pipeline.stats.parsed_events == pipeline.stats.events   # 100% parsed
    assert pipeline.stats.events_with_exception == 0               # no JVM traces
    assert pipeline.stats.templates > 1                            # mining still works
    assert all(e.fingerprint is None for e in events)              # layer no-ops cleanly

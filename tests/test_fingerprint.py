from logai.ingest.exceptions import parse_exception_chain
from logai.template.fingerprint import DEFAULT_TOP_N, describe_fingerprint, fingerprint_exception

APP = ("com.lily.",)
HEAD = ["java.lang.NullPointerException: acct is null",
        "\tat com.lily.payments.PaymentService.authorize(PaymentService.java:142)"]
PATHS = {
    "rest": "\tat com.lily.payments.api.PaymentController.submit(PaymentController.java:57)",
    "kafka": "\tat com.lily.payments.stream.SettlementConsumer.onMessage(SettlementConsumer.java:31)",
    "batch": "\tat com.lily.payments.batch.NightlyReconJob.run(NightlyReconJob.java:214)",
}


def fp(lines, **kw):
    return fingerprint_exception(parse_exception_chain(lines, app_packages=APP), **kw)


def test_same_defect_via_different_entry_paths_shares_a_fingerprint():
    prints = {fp(HEAD + [frame]) for frame in PATHS.values()}
    assert len(prints) == 1


def test_default_grouping_is_throw_site_not_call_path():
    assert DEFAULT_TOP_N == 1


def test_path_sensitive_grouping_available_when_wanted():
    prints = {fp(HEAD + [frame], top_n=5) for frame in PATHS.values()}
    assert len(prints) == 3


def test_different_defects_do_not_collide():
    other = ["java.lang.NullPointerException: cfg is null", "\tat com.lily.billing.Invoice.render(Invoice.java:20)"]
    assert fp(HEAD + [PATHS["rest"]]) != fp(other)


def test_different_root_cause_changes_the_fingerprint():
    a = HEAD + ["Caused by: java.sql.SQLException: timeout", "\tat com.lily.db.R.q(R.java:3)"]
    b = HEAD + ["Caused by: java.io.IOException: refused", "\tat com.lily.db.R.q(R.java:3)"]
    assert fp(a) != fp(b)


def test_line_numbers_excluded_by_default_survive_refactoring():
    moved = ["java.lang.NullPointerException: acct is null",
             "\tat com.lily.payments.PaymentService.authorize(PaymentService.java:988)"]
    assert fp(HEAD) == fp(moved)
    assert fp(HEAD, include_lines=True) != fp(moved, include_lines=True)


def test_framework_only_trace_falls_back_to_all_frames():
    fw = ["java.lang.IllegalStateException: x", "\tat org.springframework.web.X.y(X.java:9)"]
    chain = parse_exception_chain(fw, app_packages=APP)
    assert fingerprint_exception(chain) is not None
    assert "no application frames" in describe_fingerprint(chain)


def test_empty_chain_has_no_fingerprint():
    assert fingerprint_exception([]) is None


def test_top_n_1_ignores_unstable_scala_lambda_frames():
    # Scala numbers anonymous functions ($$anonfun$...$1) at compile time, so
    # those names can shift between builds. Frame 0 is the throw site and is a
    # real named method; measured on the full Spark dataset, no throw site in
    # the sample was compiler-generated. top_n=1 therefore stays stable across a
    # recompile that renumbers the lambdas deeper in the stack.
    head = ["org.apache.spark.rpc.RpcTimeoutException: Cannot receive any reply",
            "\tat org.apache.spark.rpc.RpcTimeout.createRpcTimeoutException(RpcTimeout.scala:48)"]
    build_a = head + ["\tat org.apache.spark.rpc.RpcTimeout$$anonfun$1.applyOrElse(RpcTimeout.scala:63)"]
    build_b = head + ["\tat org.apache.spark.rpc.RpcTimeout$$anonfun$7.applyOrElse(RpcTimeout.scala:63)"]

    def fp_spark(lines, **kw):
        return fingerprint_exception(
            parse_exception_chain(lines, app_packages=("org.apache.spark.",)), **kw
        )

    assert fp_spark(build_a) == fp_spark(build_b)
    assert fp_spark(build_a, top_n=5) != fp_spark(build_b, top_n=5)

import pytest

from logai.baseline.detector import (
    NOVEL_FINGERPRINT, NOVEL_TEMPLATE, RATE_BREACH, SEVERITY_BURST, Signal,
)
from logai.ingest.exceptions import parse_exception_chain
from logai.react.actions import (
    DENIED, DRY_RUN, EXECUTED, FAILED, NO_HANDLER, SKIPPED_RISK, Action, RiskLevel,
)
from logai.react.engine import ReactionEngine, build_evidence
from logai.react.execute import ActionExecutor, ExecutorConfig
from logai.react.llm import AnthropicPlanner, parse_risk
from logai.react.plan import LLM, PLAYBOOK, FALLBACK
from logai.schema import LogEvent, Severity

APP = ("com.lily.",)


def event_with(trace_lines, **kw):
    return LogEvent(
        message="boom", severity=Severity.ERROR,
        exceptions=parse_exception_chain(trace_lines, app_packages=APP), **kw
    )


def signal(kind, **kw):
    kw.setdefault("key", "k")
    kw.setdefault("detail", "d")
    kw.setdefault("service", "lily-payments")
    return Signal(kind=kind, **kw)


# -- playbook matching -------------------------------------------------------

def test_pool_exhaustion_matches_on_root_cause():
    sample = event_with([
        "java.lang.IllegalStateException: outer",
        "\tat com.lily.payments.PaymentService.authorize(PaymentService.java:1)",
        "Caused by: java.sql.SQLTransientConnectionException: HikariPool-1 timeout",
        "\tat com.lily.payments.db.AccountRepository.find(AccountRepository.java:2)",
    ])
    plan = ReactionEngine().plan(signal(NOVEL_FINGERPRINT, sample=sample))
    assert plan.playbook_id == "db-pool-exhaustion"
    assert plan.generated_by == PLAYBOOK
    assert plan.routing.page is True


def test_oom_matches_and_pages():
    sample = event_with(["java.lang.OutOfMemoryError: Java heap space",
                         "\tat com.lily.batch.Job.run(Job.java:9)"])
    plan = ReactionEngine().plan(signal(NOVEL_FINGERPRINT, sample=sample))
    assert plan.playbook_id == "jvm-oom"
    assert any(a.kind == "observe" and "heap dump" in a.description.lower() for a in plan.actions)


def test_more_specific_playbook_wins_over_catch_all():
    # npe-regression (2 conditions) must beat novel-failure (1 condition).
    sample = event_with(["java.lang.NullPointerException: acct is null",
                         "\tat com.lily.payments.PaymentService.authorize(PaymentService.java:1)"])
    plan = ReactionEngine().plan(signal(NOVEL_FINGERPRINT, sample=sample))
    assert plan.playbook_id == "npe-regression"


def test_catch_all_matches_when_nothing_specific_does():
    sample = event_with(["com.lily.custom.WeirdException: never seen",
                         "\tat com.lily.a.B.c(B.java:1)"])
    plan = ReactionEngine().plan(signal(NOVEL_FINGERPRINT, sample=sample))
    assert plan.playbook_id == "novel-failure"


def test_decline_spike_is_payments_routed():
    plan = ReactionEngine().plan(signal(
        RATE_BREACH, template="Payment declined by issuer code=<NUM>",
        observed=200, expected=5, score=39,
    ))
    assert plan.playbook_id == "issuer-decline-spike"
    assert plan.routing.team == "payments-ops"


def test_severity_burst_matches():
    assert ReactionEngine().plan(signal(SEVERITY_BURST)).playbook_id == "error-burst"


def test_novel_template_is_lowest_priority_and_observe_only():
    plan = ReactionEngine().plan(signal(NOVEL_TEMPLATE, template="something new"))
    assert plan.playbook_id == "novel-template"
    assert plan.max_risk == RiskLevel.OBSERVE


def test_unmatched_signal_falls_back_without_a_planner():
    plan = ReactionEngine(playbooks=[]).plan(signal(RATE_BREACH))
    assert plan.generated_by == FALLBACK
    assert plan.confidence < 0.5


# -- routing escalation ------------------------------------------------------

def test_large_deviation_escalates_a_non_paging_playbook():
    # downstream-timeout routes page=False by default; a 100x deviation overrides it.
    sample = event_with(["java.net.SocketTimeoutException: Read timed out",
                         "\tat com.lily.client.IssuerClient.call(IssuerClient.java:3)"])
    engine = ReactionEngine()
    quiet = engine.plan(signal(RATE_BREACH, sample=sample, observed=12, expected=10))
    assert quiet.playbook_id == "downstream-timeout" and quiet.routing.page is False

    loud = engine.plan(signal(RATE_BREACH, sample=sample, observed=500, expected=5))
    assert loud.routing.page is True and loud.routing.ticket_priority == "P1"
    assert any("escalated to page" in e for e in loud.evidence)


def test_escalation_does_not_mutate_the_shared_playbook():
    engine = ReactionEngine()
    engine.plan(signal(SEVERITY_BURST, observed=5000, expected=1))
    quiet = engine.plan(signal(NOVEL_TEMPLATE, template="t"))
    assert quiet.routing.page is False


# -- evidence ----------------------------------------------------------------

def test_evidence_is_extracted_not_invented():
    sample = event_with(
        ["java.lang.IllegalStateException: outer",
         "\tat com.lily.payments.PaymentService.authorize(PaymentService.java:1)",
         "Caused by: java.sql.SQLException: pool timeout",
         "\tat com.lily.payments.db.Repo.find(Repo.java:2)"],
        trace_id="abc123", logger="c.l.p.PaymentService",
    )
    ev = build_evidence(signal(NOVEL_FINGERPRINT, sample=sample, fingerprint="ff00"))
    joined = "\n".join(ev)
    assert "IllegalStateException -> java.sql.SQLException" in joined
    assert "pool timeout" in joined
    assert "com.lily.payments.PaymentService.authorize" in joined
    assert "abc123" in joined and "ff00" in joined


# -- gated execution ---------------------------------------------------------

def plan_with(*actions):
    engine = ReactionEngine(playbooks=[])
    plan = engine.plan(signal(RATE_BREACH))
    plan.actions = list(actions)
    return plan


OBSERVE = Action("o", "observe", "look", RiskLevel.OBSERVE)
NOTIFY = Action("n", "notify", "tell", RiskLevel.NOTIFY)
RESTART = Action("r", "restart", "bounce", RiskLevel.REMEDIATE)


def test_dry_run_is_the_default_and_runs_nothing():
    results = ActionExecutor().execute(plan_with(OBSERVE, NOTIFY))
    assert {r.status for r in results} == {DRY_RUN}


def test_risk_ceiling_blocks_even_with_approval():
    ex = ActionExecutor(
        ExecutorConfig(dry_run=False, max_risk=RiskLevel.NOTIFY),
        approver=lambda a, p: True,
        handlers={"restart": lambda a, p: "restarted"},
    )
    statuses = {r.action.id: r.status for r in ex.execute(plan_with(NOTIFY, RESTART))}
    assert statuses["r"] == SKIPPED_RISK


def test_approval_is_denied_by_default():
    ex = ActionExecutor(ExecutorConfig(dry_run=False, max_risk=RiskLevel.DESTRUCTIVE),
                        handlers={"restart": lambda a, p: "restarted"})
    assert {r.action.id: r.status for r in ex.execute(plan_with(RESTART))}["r"] == DENIED


def test_unregistered_kind_never_executes():
    ex = ActionExecutor(ExecutorConfig(dry_run=False, max_risk=RiskLevel.DESTRUCTIVE),
                        approver=lambda a, p: True)
    assert {r.status for r in ex.execute(plan_with(RESTART))} == {NO_HANDLER}


def test_registered_handler_runs_and_is_audited():
    ex = ActionExecutor(ExecutorConfig(dry_run=False, max_risk=RiskLevel.NOTIFY),
                        handlers={"notify": lambda a, p: "paged"})
    results = ex.execute(plan_with(NOTIFY))
    assert results[0].status == EXECUTED and results[0].detail == "paged"
    assert len(ex.audit) == 1


def test_handler_exception_is_contained():
    def boom(a, p):
        raise RuntimeError("pager down")

    ex = ActionExecutor(ExecutorConfig(dry_run=False, max_risk=RiskLevel.NOTIFY),
                        handlers={"notify": boom})
    result = ex.execute(plan_with(NOTIFY, OBSERVE))[0]
    assert result.status == FAILED and "pager down" in result.error


# -- llm planner safety ------------------------------------------------------

@pytest.mark.parametrize("value", ["nonsense", "", None, "critical", "low"])
def test_unrecognised_risk_fails_closed(value):
    assert parse_risk(value) is RiskLevel.DESTRUCTIVE


@pytest.mark.parametrize("value,expected", [
    ("observe", RiskLevel.OBSERVE), ("MITIGATE", RiskLevel.MITIGATE),
    (" remediate ", RiskLevel.REMEDIATE), ("notify", RiskLevel.NOTIFY),
])
def test_known_risk_parses_case_and_space_insensitively(value, expected):
    assert parse_risk(value) is expected


def test_model_proposed_actions_can_never_auto_execute():
    plan = AnthropicPlanner.to_plan(signal(NOVEL_FINGERPRINT), ["ev"], {
        "title": "t", "hypotheses": ["h"], "blast_radius": "b", "confidence": 0.6,
        "routing": {"team": "x", "channel": "#c", "page": False, "ticket_priority": "P2"},
        "actions": [
            {"id": "a", "kind": "observe", "description": "d", "risk": "observe",
             "command": None, "rollback": None},
            {"id": "b", "kind": "deploy", "description": "roll back", "risk": "remediate",
             "command": None, "rollback": "redeploy"},
        ],
    })
    assert plan.generated_by == LLM
    assert all(a.needs_approval() for a in plan.actions)
    assert plan.auto_actions == []


def test_unknown_action_kind_is_coerced_to_observe():
    plan = AnthropicPlanner.to_plan(signal(NOVEL_FINGERPRINT), [], {
        "title": "t", "hypotheses": [], "blast_radius": "b", "confidence": 0.5,
        "routing": {"team": "x", "channel": "#c", "page": False, "ticket_priority": "P3"},
        "actions": [{"id": "a", "kind": "rm-rf", "description": "d", "risk": "observe",
                     "command": None, "rollback": None}],
    })
    assert plan.actions[0].kind == "observe"


def test_planner_is_only_consulted_when_no_playbook_matches():
    class Boom:
        def plan(self, signal, evidence):
            raise AssertionError("planner must not be called on a matched signal")

    ReactionEngine(planner=Boom()).plan(signal(SEVERITY_BURST))  # matches error-burst


def test_planner_result_is_used_when_nothing_matches():
    class Stub:
        def plan(self, sig, evidence):
            return AnthropicPlanner.to_plan(sig, list(evidence), {
                "title": "generated", "hypotheses": ["h"], "blast_radius": "b",
                "confidence": 0.5,
                "routing": {"team": "x", "channel": "#c", "page": False,
                            "ticket_priority": "P3"},
                "actions": [],
            })

    plan = ReactionEngine(playbooks=[], planner=Stub()).plan(signal(RATE_BREACH))
    assert plan.generated_by == LLM and plan.title == "generated"


def test_plan_serialises():
    d = ReactionEngine().plan(signal(SEVERITY_BURST)).to_dict()
    assert d["playbook_id"] == "error-burst"
    assert isinstance(d["actions"], list) and d["actions"][0]["risk"]


def test_generic_rate_breach_has_a_catch_all():
    # Found by running the Spark corpus: 83 of 183 signals were rate breaches
    # that matched nothing, because the only rate-breach playbook was the
    # payments-specific decline spike. Any non-payments service hit the
    # unclassified fallback for its most common signal kind.
    plan = ReactionEngine().plan(signal(
        RATE_BREACH, template="Executor heartbeat timed out after <DURATION>",
        observed=120, expected=4,
    ))
    assert plan.playbook_id == "rate-breach"
    assert plan.generated_by == PLAYBOOK
    assert plan.max_risk <= RiskLevel.NOTIFY


def test_payments_decline_spike_still_beats_the_generic_rate_breach():
    plan = ReactionEngine().plan(signal(
        RATE_BREACH, template="Payment declined by issuer code=<NUM>", observed=200, expected=5,
    ))
    assert plan.playbook_id == "issuer-decline-spike"

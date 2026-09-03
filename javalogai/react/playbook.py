"""Deterministic reaction playbooks.

A playbook is a match condition plus the response to it. Matching is pure
predicate evaluation over a :class:`Signal` and its sample event -- free,
reproducible, and explainable months later, which matters more for the reaction
than it does for the detection. "Why did we open the circuit breaker at 03:14"
has to have an answer that does not depend on re-running a model.

Playbooks are ranked by specificity, so a rule naming an exception class beats a
generic rule matching every novel fingerprint. Anything unmatched falls through
to the LLM planner (see :mod:`javalogai.react.llm`), which is where novel
failures get handled.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Sequence

from ..baseline.detector import NOVEL_FINGERPRINT, NOVEL_TEMPLATE, RATE_BREACH, SEVERITY_BURST, Signal
from ..schema import Severity
from .actions import Action, RiskLevel
from .plan import Routing


@dataclass(slots=True)
class Match:
    """Conditions, ANDed. An unset condition is simply not tested."""

    signal_kinds: Sequence[str] = ()
    exception_contains: Sequence[str] = ()
    template_regex: str | None = None
    logger_regex: str | None = None
    services: Sequence[str] = ()
    min_score: float | None = None
    severity_at_least: Severity | None = None

    @property
    def specificity(self) -> int:
        return sum(
            1
            for c in (
                self.signal_kinds, self.exception_contains, self.template_regex,
                self.logger_regex, self.services, self.min_score, self.severity_at_least,
            )
            if c
        )

    def matches(self, signal: Signal) -> bool:
        if self.signal_kinds and signal.kind not in self.signal_kinds:
            return False
        if self.services and signal.service not in self.services:
            return False
        if self.min_score is not None and (signal.score or 0) < self.min_score:
            return False

        sample = signal.sample
        if self.exception_contains:
            chain = " ".join(sample.exception_chain) if sample else ""
            if not any(token in chain for token in self.exception_contains):
                return False
        if self.template_regex:
            haystack = signal.template or (sample.message if sample else "") or ""
            if not re.search(self.template_regex, haystack, re.IGNORECASE):
                return False
        if self.logger_regex:
            logger = (sample.logger if sample else "") or ""
            if not re.search(self.logger_regex, logger, re.IGNORECASE):
                return False
        if self.severity_at_least is not None:
            if not sample or not sample.severity.at_least(self.severity_at_least):
                return False
        return True


@dataclass(slots=True)
class Playbook:
    id: str
    title: str
    match: Match
    hypotheses: list[str] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)
    routing: Routing = field(default_factory=Routing)
    blast_radius: str = "unknown"
    confidence: float = 0.7
    references: list[str] = field(default_factory=list)


def _a(id_: str, kind: str, desc: str, risk: RiskLevel = RiskLevel.OBSERVE, **kw) -> Action:
    return Action(id=id_, kind=kind, description=desc, risk=risk, **kw)


BUILTIN_PLAYBOOKS: list[Playbook] = [
    Playbook(
        id="db-pool-exhaustion",
        title="Database connection pool exhausted",
        match=Match(exception_contains=("SQLTransientConnectionException", "HikariPool",
                                        "PoolExhaustedException", "CannotGetJdbcConnection")),
        hypotheses=[
            "Downstream database is slow or unreachable, so connections are held until timeout.",
            "A query regression or missing index has raised average connection hold time.",
            "A connection leak: a code path is not closing connections (check for a recent deploy).",
            "Legitimate traffic growth has outgrown the configured pool size.",
        ],
        actions=[
            _a("pool-metrics", "observe", "Pull Hikari pool metrics: active, idle, pending, timeout rate",
               RiskLevel.OBSERVE, command="curl -s localhost:8081/actuator/metrics/hikaricp.connections.pending"),
            _a("db-health", "observe", "Check database CPU, active sessions and slow-query log",
               RiskLevel.OBSERVE),
            _a("recent-deploys", "observe", "List deploys to this service in the last 2 hours",
               RiskLevel.OBSERVE),
            _a("notify-oncall", "notify", "Notify the service on-call with pool saturation evidence",
               RiskLevel.NOTIFY),
            _a("raise-pool", "config", "Temporarily raise maximumPoolSize (relieves symptom, not cause)",
               RiskLevel.MITIGATE, params={"property": "spring.datasource.hikari.maximum-pool-size"},
               rollback="Restore the previous pool size once the root cause is fixed"),
            _a("shed-load", "traffic", "Shed or queue non-critical traffic to protect authorisation flow",
               RiskLevel.MITIGATE, rollback="Restore full traffic"),
            _a("rollback-deploy", "deploy", "Roll back the correlated deploy if a leak is confirmed",
               RiskLevel.REMEDIATE, rollback="Re-deploy the previous version"),
        ],
        routing=Routing(team="platform-db", channel="#db-incidents", page=True, ticket_priority="P1"),
        blast_radius="Service-wide: every request needing a connection will queue then fail.",
        confidence=0.85,
        references=["runbooks/db-pool-exhaustion.md"],
    ),
    Playbook(
        id="jvm-oom",
        title="JVM out of memory",
        match=Match(exception_contains=("OutOfMemoryError",)),
        hypotheses=[
            "A memory leak has exhausted the heap; the process will not recover on its own.",
            "A single oversized request or batch allocated beyond the heap ceiling.",
            "Heap is undersized for current traffic after a legitimate growth in load.",
            "Metaspace or direct buffer exhaustion rather than heap (check the OOM message).",
        ],
        actions=[
            _a("heap-dump", "observe", "Capture a heap dump before the process is replaced",
               RiskLevel.OBSERVE, command="jcmd <pid> GC.heap_dump /var/tmp/heap.hprof"),
            _a("gc-logs", "observe", "Pull GC logs and check for a rising post-collection floor",
               RiskLevel.OBSERVE),
            _a("page-oncall", "notify", "Page on-call: an OOM is not self-healing", RiskLevel.NOTIFY),
            _a("drain-instance", "traffic", "Drain the affected instance from the load balancer",
               RiskLevel.MITIGATE, rollback="Return the instance to the pool"),
            _a("restart-instance", "restart", "Restart the affected instance after the dump is captured",
               RiskLevel.REMEDIATE, rollback="None: restart is not reversible, but is usually safe"),
        ],
        routing=Routing(team="service-owner", channel="#jvm-incidents", page=True, ticket_priority="P1"),
        blast_radius="Single instance, escalating to the fleet if the cause is a shared leak.",
        confidence=0.9,
        references=["runbooks/jvm-oom.md"],
    ),
    Playbook(
        id="downstream-timeout",
        title="Downstream dependency timing out",
        match=Match(exception_contains=("SocketTimeoutException", "ConnectTimeoutException",
                                        "TimeoutException", "ReadTimeoutException",
                                        "ResourceAccessException")),
        hypotheses=[
            "The downstream dependency is degraded or overloaded.",
            "Network path or DNS problem between this service and the dependency.",
            "Our client timeout is set below the dependency's realistic p99.",
        ],
        actions=[
            _a("dep-health", "observe", "Check the dependency's health endpoint and its own error rate",
               RiskLevel.OBSERVE),
            _a("latency-percentiles", "observe", "Compare client-side p50/p99 against the configured timeout",
               RiskLevel.OBSERVE),
            _a("notify-dep-owner", "notify", "Notify the dependency's owning team with request ids",
               RiskLevel.NOTIFY),
            _a("open-breaker", "traffic", "Open the circuit breaker to fail fast instead of queueing",
               RiskLevel.MITIGATE, rollback="Close the breaker once the dependency recovers"),
            _a("failover", "traffic", "Fail over to the secondary endpoint or region",
               RiskLevel.REMEDIATE, rollback="Fail back to primary"),
        ],
        routing=Routing(team="service-owner", channel="#alerts", page=False, ticket_priority="P2"),
        blast_radius="Requests depending on this call; thread pool exhaustion if timeouts are long.",
        confidence=0.8,
    ),
    Playbook(
        id="circuit-breaker-open",
        title="Circuit breaker opened",
        match=Match(template_regex=r"circuit breaker.*open"),
        hypotheses=[
            "The protected dependency crossed its failure threshold and is now being bypassed.",
            "Breaker thresholds are too tight for normal error rates and are tripping spuriously.",
        ],
        actions=[
            _a("breaker-state", "observe", "Read breaker state, failure rate and the window that tripped it",
               RiskLevel.OBSERVE),
            _a("dep-health", "observe", "Check the protected dependency directly", RiskLevel.OBSERVE),
            _a("notify-oncall", "notify", "Notify on-call that traffic is being shed", RiskLevel.NOTIFY),
            _a("verify-fallback", "observe", "Confirm the fallback path is serving correct results",
               RiskLevel.OBSERVE),
        ],
        routing=Routing(team="service-owner", channel="#alerts", page=False, ticket_priority="P2"),
        blast_radius="All calls through this breaker take the fallback path.",
        confidence=0.75,
    ),
    Playbook(
        id="issuer-decline-spike",
        title="Issuer decline rate spike",
        match=Match(signal_kinds=(RATE_BREACH,), template_regex=r"declin(e|ed|es)|issuer|auth.*(fail|reject)"),
        hypotheses=[
            "A specific issuer or BIN range is degraded and declining valid authorisations.",
            "A rules or risk-model change is rejecting traffic it previously approved.",
            "An upstream tokenisation or 3DS step is failing, producing downstream declines.",
            "Genuine fraud pressure: the rise is correct and should not be suppressed.",
        ],
        actions=[
            _a("segment-declines", "observe", "Break declines down by issuer, BIN, response code and region",
               RiskLevel.OBSERVE),
            _a("compare-baseline", "observe", "Compare against the same window on previous days",
               RiskLevel.OBSERVE),
            _a("rules-changes", "observe", "List risk-rule and model changes in the last 24 hours",
               RiskLevel.OBSERVE),
            _a("notify-payments-ops", "notify", "Notify payments operations with the decline breakdown",
               RiskLevel.NOTIFY),
            _a("page-risk", "notify", "Page the risk team if a single rule change correlates",
               RiskLevel.NOTIFY),
            _a("revert-rule", "config", "Revert the correlated risk rule change",
               RiskLevel.REMEDIATE, rollback="Re-apply the rule once validated"),
        ],
        routing=Routing(team="payments-ops", channel="#payments-incidents", page=True, ticket_priority="P1"),
        blast_radius="Revenue-affecting: valid transactions are being declined.",
        confidence=0.7,
        references=["runbooks/decline-spike.md"],
    ),
    Playbook(
        id="npe-regression",
        title="Null pointer regression",
        match=Match(signal_kinds=(NOVEL_FINGERPRINT,), exception_contains=("NullPointerException",)),
        hypotheses=[
            "A recent deploy introduced an unguarded path; the throw site names the field.",
            "An upstream contract changed and now omits a field this code assumes present.",
            "A data condition never seen before reached a path with no null handling.",
        ],
        actions=[
            _a("correlate-deploy", "observe", "Correlate first occurrence against deploys to this service",
               RiskLevel.OBSERVE),
            _a("blame-throw-site", "observe", "Get git blame for the throw site named in the fingerprint",
               RiskLevel.OBSERVE),
            _a("sample-requests", "observe", "Pull sample trace ids to identify the triggering input",
               RiskLevel.OBSERVE),
            _a("file-ticket", "ticket", "File a defect with the fingerprint as the dedup key",
               RiskLevel.NOTIFY),
            _a("rollback-deploy", "deploy", "Roll back if first occurrence lands within the deploy window",
               RiskLevel.REMEDIATE, rollback="Re-deploy once patched"),
        ],
        routing=Routing(team="service-owner", channel="#alerts", page=False, ticket_priority="P2"),
        blast_radius="Every request reaching the affected path fails.",
        confidence=0.75,
    ),
    Playbook(
        id="error-burst",
        title="Service-wide error burst",
        match=Match(signal_kinds=(SEVERITY_BURST,)),
        hypotheses=[
            "A deploy just landed and regressed a widely used path.",
            "A shared dependency (database, cache, auth) is degraded.",
            "Infrastructure: node loss, network partition, or DNS.",
        ],
        actions=[
            _a("group-by-fingerprint", "observe", "Group the burst by fingerprint to see if it is one bug or many",
               RiskLevel.OBSERVE),
            _a("recent-deploys", "observe", "List deploys across the service and its dependencies",
               RiskLevel.OBSERVE),
            _a("page-oncall", "notify", "Page on-call", RiskLevel.NOTIFY),
            _a("rollback-deploy", "deploy", "Roll back the correlated deploy",
               RiskLevel.REMEDIATE, rollback="Re-deploy once the cause is understood"),
        ],
        routing=Routing(team="service-owner", channel="#incidents", page=True, ticket_priority="P1"),
        blast_radius="Service-wide.",
        confidence=0.65,
    ),
    Playbook(
        id="novel-failure",
        title="Previously unseen failure",
        match=Match(signal_kinds=(NOVEL_FINGERPRINT,)),
        hypotheses=["A failure mode with no prior occurrence; no playbook covers it yet."],
        actions=[
            _a("capture-context", "observe", "Capture the full trace, trace ids and surrounding events",
               RiskLevel.OBSERVE),
            _a("correlate-deploy", "observe", "Correlate against recent deploys and config changes",
               RiskLevel.OBSERVE),
            _a("file-ticket", "ticket", "File a defect keyed on the fingerprint", RiskLevel.NOTIFY),
        ],
        routing=Routing(team="service-owner", channel="#alerts", page=False, ticket_priority="P3"),
        blast_radius="Unknown; first occurrence.",
        confidence=0.4,
    ),
    Playbook(
        id="novel-template",
        title="New log template observed",
        match=Match(signal_kinds=(NOVEL_TEMPLATE,)),
        hypotheses=[
            "A deploy introduced new logging; usually benign.",
            "A code path that had never executed before has now run.",
        ],
        actions=[
            _a("record-template", "observe", "Record the template and watch its rate over the next hour",
               RiskLevel.OBSERVE),
        ],
        routing=Routing(team="service-owner", channel="#log-changes", page=False, ticket_priority="P4"),
        blast_radius="None expected.",
        confidence=0.3,
    ),
]

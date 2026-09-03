# Log-AI — tier-1 log intelligence for JVM applications

Deterministic log analysis for Java services: multiline stack-trace assembly, PCI
scrubbing, template mining, exception fingerprinting and baseline breach
detection. No model calls, no network, no tokens.

It is the bottom layer of a three-tier design. The point of the layer is to make
the expensive tiers affordable by changing what their cost is proportional to.

| Tier | Cost scales with | Does | Status |
| --- | --- | --- | --- |
| **1. Deterministic** | lines/day — billions | Assemble → scrub → template → fingerprint → baseline. CPU only. | built |
| **R. Reaction** | signals/day — dozens | Playbook match → ranked hypotheses, evidence, gated actions. Free when a playbook matches. | built |
| **3. Model fallback** | *unmatched* signals/day — a handful | Claude plans the long tail no playbook covers. | built (opt-in) |
| 2. Cheap model | *new templates*/day — thousands | Embed novel templates for dedup/clustering. | not built |

On the bundled fixture, 1,837 raw lines reduce to **5 templates** and **7
signals** — a 99.6% reduction in what any model would need to read.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

python fixtures/generate.py
javalogai analyze fixtures/payment-service.log --app-package com.lily.

# with reaction plans
javalogai analyze fixtures/payment-service.log --app-package com.lily. --react

# against real production JVM logs (Hadoop, ZooKeeper, Spark, HDFS)
javalogai loghub list
javalogai analyze --loghub hadoop
```

```
Tier-1 report  fixtures/payment-service.log
========================================================================
  Input        1,837 raw lines -> 1,810 logical events (100.0% parsed)
  Templates    5  (367 raw lines per template)
  Failures     1 distinct fingerprint(s) across 3 events with a stack trace
  Redaction    1 events redacted  [cvv=1 email=1 pan=1]
  Signals      7 escalated to tier 2/3

Distinct failures
  faf083413eb888fc  x3  NullPointerException -> SQLTransientConnectionException
      SQLTransientConnectionException at com.lily.payments.PaymentService.authorize
      3 distinct call paths merged into this one failure
```

Use as a library:

```python
from javalogai import Tier1Pipeline, PipelineConfig

pipeline = Tier1Pipeline(PipelineConfig(app_packages=("com.lily.",)))
for event, signals in pipeline.stream(open("app.log")):
    for signal in signals:
        handoff_to_tier3(signal)      # only these cost money
```

`stream()` holds one event at a time; memory is bounded by the longest stack
trace, not by input size.

## The reaction tier

A signal says something changed. A plan says what to do about it. `--react`
turns every signal into a :class:`ReactionPlan`: ranked hypotheses, the evidence
they rest on, a blast-radius note, routing, and a list of actions each carrying
a risk level.

```
Issuer decline rate spike
  signal      rate_breach  lily-payments/template:2
  source      playbook (issuer-decline-spike)   confidence 70%
  routing     payments-ops -> #payments-incidents  PAGE  [P1]
  blast       Revenue-affecting: valid transactions are being declined.
  evidence
    - rate 200 in 60s vs baseline 5.0 (40.0x, z=39.0)
    - Template: Payment declined by issuer code=<NUM> attempt=<NUM>
    - Example trace id: d3953524639fd7d539a7e35839bf1c4b
  hypotheses (ranked)
    1. A specific issuer or BIN range is degraded and declining valid authorisations.
    2. A rules or risk-model change is rejecting traffic it previously approved.
    3. An upstream tokenisation or 3DS step is failing, producing downstream declines.
    4. Genuine fraud pressure: the rise is correct and should not be suppressed.
  actions
    [auto]     observe     Break declines down by issuer, BIN, response code and region
    [auto]     notify      Notify payments operations with the decline breakdown
    [approval] remediate   Revert the correlated risk rule change
        rollback: Re-apply the rule once validated
```

**Playbooks first, model second.** Nine built-in playbooks cover the common JVM
and payments failure modes (pool exhaustion, OOM, downstream timeout, circuit
breaker, decline spike, NPE regression, error burst, plus two catch-alls). They
are pure predicate evaluation — free, reproducible, and explainable months
later. `--llm` adds a Claude planner for signals no playbook matches, which is
where cost is actually incurred: it scales with *unmatched* signals, not events.

Playbooks are ranked by specificity, so a rule naming an exception class beats a
catch-all on the same signal kind. Routing escalates to a page on its own when a
deviation exceeds 10x baseline, whatever the playbook said.

### Execution is gated three ways

`--execute` is required before anything runs at all, and even then:

1. **dry-run is the default.** Results record what *would* have happened.
2. **A risk ceiling** (`--max-risk`, default `notify`) blocks anything above it
   regardless of approval. Levels: observe, notify, mitigate, remediate,
   destructive.
3. **Approval.** Actions at `mitigate` and above need a human; the default
   approver denies everything.

On top of that, execution dispatches only to handlers you register by action
kind. There is no default handler and no shell evaluation — a playbook file
cannot cause execution of anything you have not explicitly wired up. An action's
`command` field is documentation for a human, not something the executor runs.

**Model-generated actions can never auto-execute.** Every action returned by the
planner has approval forced on regardless of the risk it claimed, and an
unrecognised risk level is treated as `destructive` rather than `observe` — it
fails closed. A model may propose a rollback; only a person may authorise one.

```python
from javalogai import ReactionEngine, ActionExecutor, ExecutorConfig, RiskLevel

executor = ActionExecutor(
    ExecutorConfig(dry_run=False, max_risk=RiskLevel.NOTIFY),
    approver=lambda action, plan: ask_oncall(action),
    handlers={"notify": page_via_pagerduty},   # only wired kinds can run
)
for plan in ReactionEngine().plan_all(signals):
    executor.execute(plan)
```

## Data sources

```python
from javalogai.sources import loghub
from javalogai.sources.aws import S3LogSource, CloudWatchLogsSource

pipeline.run(loghub.load("hadoop"))
pipeline.run(S3LogSource(bucket="my-logs", prefix="payments/2024/01/15/"))
pipeline.run(CloudWatchLogsSource(log_group="/aws/ecs/payments", start=yesterday))
```

**loghub** (`pip install` nothing — stdlib download) provides real production
logs from four JVM systems, and they are a genuine test: three of the four
layouts broke the header patterns that were written against Spring Boot and
Logback defaults. All four now parse at 100%, including ZooKeeper's habit of
packing the logger inside the thread bracket
(`[QuorumPeer[myid=1]/...:FastLeaderElection@774]`).

One limitation, stated plainly: **the published 2k samples contain no stack
traces.** They exercise header parsing, template mining and baselining against
real data, but not multiline assembly, exception chains or fingerprinting. The
synthetic `fixtures/payment-service.log` remains the fixture for those.

**AWS** sources cover the two shapes Centralized Logging with OpenSearch
(formerly "Log Hub") leaves logs in — S3 objects and CloudWatch Logs streams.
Both yield plain lines, so multiline assembly still happens on our side, because
neither source preserves the notion of a logical event. Requires
`pip install "javalogai[aws]"`; boto3 is imported lazily.

## Why this exists rather than a generic log-AI library

Generic log tooling assumes one line is one event. That assumption is false on
the JVM and it fails loudly: a 40-line stack trace becomes 40 "events", every
distinct frame combination mints its own template, and the real signal is buried
under template explosion. Everything below follows from fixing that.

### Design decisions worth knowing

**Multiline assembly is header-driven.** A new event begins at a line with a
leading timestamp; everything after it belongs to that event. This survives
arbitrary junk inside a trace — multi-line exception messages, `Caused by:`
chains, interleaved framework noise — where shape-matching heuristics do not.
The heuristic fallback is used only before the first header match.

**Fingerprints group by throw site, not by call path.** Frames run
innermost-first, so frame 0 is where the exception was raised and later frames
are the path that reached it. The same defect hit from a REST controller, a
Kafka consumer and a nightly job produces three different traces; hashing the
throwable chain plus frame 0 collapses them to one failure. Raise
`fingerprint_top_n` if you would rather group path-sensitively.

**Framework frames are excluded.** A 60-frame trace is typically 4 frames of
your code and 56 of Tomcat, Spring and Hibernate. Pass `app_packages=("com.lily.",)`
to make frame classification an exact allow-list — it is the single
highest-value piece of configuration here. Without it, a deny-list of known
framework prefixes is used, which misclassifies vendor code.

**Line numbers are excluded from fingerprints by default.** Otherwise editing an
import above the throw site changes the fingerprint and breaks exactly the
cross-time correlation the fingerprint exists to provide.

**Card numbers are Luhn-validated, not just shape-matched.** Shape alone is
unusable: a 16-digit order id, an epoch-nanos timestamp and a trace id all match
`\d{16}`, and over-redaction destroys the debuggability that justifies keeping
logs. Two related traps, both regression-tested:

- Digit runs *inside hex identifiers* pass Luhn about one time in ten. Matching
  them raises false PCI alarms **and corrupts the trace id** that correlation
  depends on, so the pattern guards against word characters, not just digits.
- Redaction counts report values actually redacted, not patterns matched — "we
  redacted N card numbers" has to be literally true for an audit.

**Rate breaches need a multiple, not just a z-score.** A z-score alone flags
ordinary jitter of 27 → 34 requests a minute as an incident. Requiring the
observation to be `min_ratio` times the baseline as well (default 2.0) is what
separates a real spike from noise. Each template is compared only against its
own EWMA history, so a template firing 10,000/min and one firing twice an hour
both get sensible thresholds with no hand-tuning.

**Two masking layers stack, doing different jobs.** `javalogai.scrub` removes
what must not be stored or transmitted. drain3's masking generalises what is
merely *variable* — ids, durations, counts — so `took 12ms` and `took 4300ms`
collapse to one template instead of two.

### On Drain

Template mining comes from upstream [drain3](https://github.com/logpai/Drain3)
(MIT), not from a vendored copy. drain3 is maintained and built for incremental
use: `add_log_message` consumes one message at a time and state snapshots
through a persistence handler, so templates survive restarts.

**State is restart-safe, and it has to be.** Pass `--state PATH` to persist
mined templates (`PATH`) alongside fingerprints and EWMA baselines
(`PATH.detector.json`). Novelty is defined as whether the *miner* ever saw a
template, not whether the current process did — a process-local set would
re-announce every template as new after every deploy, which is alert spam that
bills straight through to tier 3. Replaying known input against warm state
yields no novelty signals at all:

```
$ javalogai analyze app.log --state state/tpl.bin     # cold
  Signals      7 escalated to tier 2/3
$ javalogai analyze app.log --state state/tpl.bin     # warm
  Signals      1 escalated to tier 2/3                # only the real spike
```

## Layout

```
javalogai/
  schema.py            LogEvent, ExceptionInfo, StackFrame (OpenTelemetry-shaped)
  ingest/
    multiline.py       physical lines -> logical events
    java_format.py     Spring Boot / Logback / Log4j2 header layouts, trace context
    exceptions.py      throwable chain, frames, app-vs-framework classification
  scrub/scrubber.py    PAN (Luhn), CVV, JWT, secrets, email, SSN, IBAN
  sources/
    loghub.py          real JVM logs from the loghub collection
    aws.py             S3 and CloudWatch Logs (optional: javalogai[aws])
  react/
    playbook.py        match conditions -> response, 9 built in
    engine.py          playbook match, else model planner, else fallback
    plan.py            ReactionPlan, Routing
    actions.py         Action, RiskLevel, ActionResult
    execute.py         dry-run / risk ceiling / approval / registered handlers
    llm.py             Claude planner (optional: javalogai[llm])
  template/
    miner.py           drain3 wrapper with persistence
    fingerprint.py     stable failure identity
  baseline/
    counters.py        rolling time-bucketed counts
    detector.py        novelty / rate breach / severity burst -> Signal
  pipeline.py          the wiring
  cli.py
```

`Signal` is the seam. Tier 2 and tier 3 consume signals and never touch raw logs.

## Not yet built

- Tier 2 (embedding-based dedup and clustering of novel templates).
- Kafka and OTel-collector sources; Kinesis.
- GC and thread-dump parsing; correlation against deploys and traces — several
  playbooks recommend "correlate against recent deploys" but nothing wires that
  up yet, so that action is a human step today.
- Playbooks are code, not config. A YAML loader would let ops teams add rules
  without a deploy.

## Tests

```bash
python -m pytest -q       # 110 tests
```

# Validation record

What this code has actually been run against, what broke, and which test now
guards each finding.

The unit suite proves the code does what it was written to do. This file records
the separate question — whether what it was written to do survives contact with
logs nobody wrote it for. Every entry below came from running a real corpus, not
from review. Each one ends in a named test, so a regression is a failing test
rather than a lost memory.

Last run: 154 tests, all passing.

The test references below are themselves checked by
`test_validation_doc.py` — rename a cited test and this document fails, rather
than quietly becoming folklore.

---

## Corpora

| Corpus | Size | Shape | Exercises |
| --- | --- | --- | --- |
| `fixtures/payment-service.log` | 1,837 lines | Synthetic Spring Boot, `com.lily.` | Exceptions, fingerprints, PCI scrubbing, baselines |
| loghub 2k samples | 4 × 2,000 lines | Real Hadoop / ZooKeeper / Spark / HDFS | Header layouts only — **no stack traces** |
| loghub full Hadoop | 394k lines, 978 files | Real, injected faults | Real traces, `Caused by:` chains |
| loghub full Spark | 33.2M lines, 2.7 GB, 3,852 files | Real, Scala/PySpark | Scale, memory bound, Scala frames |

Reproduce:

```bash
javalogai analyze fixtures/payment-service.log --app-package com.lily.
javalogai analyze --loghub-full hadoop --app-package org.apache.hadoop.
javalogai analyze --loghub-full spark  --app-package org.apache.spark.
```

The full datasets download from Zenodo on first use and cache under
`~/.cache/javalogai/loghub/`.

---

## Results

### Synthetic fixture

```
Input        1,837 raw lines -> 1,810 logical events (100.0% parsed)
Templates    5  (367 raw lines per template)
Failures     1 distinct fingerprint(s) across 3 events with a stack trace
Redaction    1 events redacted  [cvv=1 email=1 pan=1]
Signals      7 escalated to tier 2/3
```

Three stack traces reached through three different entry paths collapse to one
fingerprint. Pinned by `test_pipeline.py::test_three_stack_traces_collapse_to_one_failure`.

### Full Hadoop — 394k lines

```
Input        394,310 raw lines -> 180,897 logical events (100.0% parsed)
Templates    259  (1,522 raw lines per template)
Failures     23 distinct fingerprint(s) across 6,233 events with a stack trace
Redaction    27 events redacted  [secret_kv=27]
```

- **6,233 exceptions → 23 failures (271:1).** Inspected rather than trusted: the
  top group is 5,303 `NoRouteToHostException` events arriving through 5 distinct
  call paths — one injected network fault, correctly merged. The disk-full
  (`FSError -> IOException`) and connection-reset failures stay separate.
- Messages whose *values* vary merge correctly (`firstBadLink as 10.86.169.121`
  vs `...165.66`); differing root-cause *classes* do not merge.
- ~26k lines/sec, single-threaded.

### Full Spark — 33.2M lines, 2.7 GB

```
Input        33,236,604 raw lines -> 27,410,255 logical events (100.0% parsed)
Templates    259  (128,327 raw lines per template)
Failures     55 distinct fingerprint(s) across 8,058 events with a stack trace
Redaction    7 events redacted  [pan=7]
Peak RSS     33.5 MB
Wall clock   3,152 s (~10.5k lines/sec, sharing a core with another run)
```

- **33.5 MB peak RSS against a 2.7 GB corpus** is the headline. Memory is bounded
  by distinct templates and failures, not by input size. This only held after the
  CLI was moved off the batch path — the earlier version would have tried to hold
  27.4M event objects.
- Chains up to five deep parsed correctly:
  `SparkException → YarnException → Error → SparkException → YarnException`.

> **259 templates for both Hadoop and Spark is a coincidence, not a cap.**
> It looked like a bug and was checked: drain3's cluster store is an unbounded
> `dict`, and on equal 400k-line slices Spark yields 170 against Hadoop's 259.

---

## Findings

Ordered by how badly each would have hurt in production.

### 1. PAN false positives on hex trace IDs

**Found on:** synthetic fixture (11 hits where 1 was expected).

Digit runs *inside* hex identifiers pass Luhn about one time in ten —
`c69589cd62e`**`07957166693998`**`c2eb4ef`. The lookbehind excluded digits and
dots but not hex letters.

Two harms, and the second is worse: false PCI alarms, and **corruption of the
trace ID that correlation depends on**. Guards now exclude word characters.

→ `test_scrub.py::test_digit_run_inside_hex_trace_id_is_not_a_pan`

### 2. Luhn alone is insufficient at volume

**Found on:** full Hadoop — **58 false PAN redactions**.

Every one a millisecond epoch timestamp such as `1445076437777`. Roughly one in
ten random digit runs satisfies Luhn, so any corpus dense with numeric IDs leaks
a steady trickle.

Fixed by validating issuer prefixes (IIN) and per-network lengths as well as the
checksum. No card network issues numbers beginning with 0, 1, 7, 8 or 9, which
removes the entire timestamp class. **58 → 0**, with no loss on real cards.

→ `test_scrub.py::test_epoch_millis_that_pass_luhn_are_not_cards`
→ `test_scrub.py::test_iin_and_luhn_are_both_required`
→ `test_scrub.py::test_non_issuable_prefixes_and_lengths_rejected`

### 3. Residual PAN false positives at 19 digits — *deliberately not fixed*

**Found on:** full Spark — 7 hits in 33.2M lines (~1 per 5M).

19-digit Spark RPC request IDs such as `4661816796531593848`. 19 **is** a
legitimate Visa length, the ID starts with 4, and it clears Luhn by chance.

Not silently narrowed away: dropping 19-digit support would under-redact real
cards, and in a PCI tool that is the wrong direction to fail. Instead this is an
explicit operator decision — `Scrubber(pan_lengths={16})` or `--pan-lengths 16`
removes the class for a shop that only handles 16-digit cards.

→ `test_scrub.py::test_nineteen_digit_ids_are_accepted_by_default_because_visa_issues_that_length`
→ `test_scrub.py::test_pan_lengths_narrows_away_the_residual`
→ `test_scrub.py::test_pan_lengths_only_ever_removes_matches`

### 4. Three of four real header layouts did not parse

**Found on:** loghub 2k samples.

Patterns had been written against Spring Boot and Logback defaults. Real logs
disagreed:

| Layout | Problem |
| --- | --- |
| Hadoop | `logger: msg` — separator required whitespace before the colon |
| ZooKeeper | `ts - LEVEL [thread:Logger@line] - msg`, logger packed inside the thread bracket |
| Spark | `yy/MM/dd` two-digit year |
| HDFS | `yymmdd HHMMSS pid LEVEL logger: msg` |

Spark was the dangerous one: its year format was not recognised as an **event
header** at all, so multiline assembly would have glued every line onto the
previous event — silently, with no parse error. All four now parse at 100%.

→ `test_sources.py::test_real_loghub_layouts_parse`
→ `test_sources.py::test_zookeeper_logger_is_unpacked_from_the_thread_bracket`
→ `test_sources.py::test_loghub_layouts_are_recognised_as_event_headers`

### 5. Reaction tier had no generic rate-breach playbook

**Found on:** full Spark — **83 of 183 signals matched nothing**, all rate breaches.

The only rate-breach playbook required a decline/issuer template, so *any
non-payments service* hit "manual triage required" for its commonest signal
kind. The payments framing had quietly become an assumption.

A generic playbook now covers them at deliberately low confidence (0.35) — a rate
breach alone says something *changed*, not that something *broke*. Coverage
183/183; the payments-specific playbook still wins on specificity.

→ `test_react.py::test_generic_rate_breach_has_a_catch_all`
→ `test_react.py::test_payments_decline_spike_still_beats_the_generic_rate_breach`

### 6. Redaction counts reported matches, not redactions

`re.subn` counts pattern matches, so a Luhn-rejected order ID was tallied as a
redacted card. "We redacted N card numbers" has to be literally true for an
audit, so callable replacers now count what actually changed.

→ `test_scrub.py::test_hit_counts_reflect_actual_redactions_not_matches`

### 7. Rate breach fired on ordinary jitter

A z-score alone flagged 27 → 34 requests/min as an incident. Breaches now require
a multiple of baseline (default 2.0×) as well as a z-score.

→ `test_baseline.py::test_ordinary_jitter_does_not_fire`

### 8. Novelty re-fired on every restart

drain3 persists its templates, but the detector kept a *separate* in-memory
`seen_templates` set — so every restart re-announced all templates as new. In
production that is an alert burst after every deploy, billing through to tier 3.
Novelty now derives from the miner's persisted state.

Verified on real data: full Hadoop cold run 99 signals → warm run 5.

### 9. CLI held every event in memory

`analyze` materialised every `LogEvent` to compute report aggregates. Fine at
Hadoop's 181k events, fatal at Spark's 27.4M. `ReportData` now accumulates only
per-template counts and per-fingerprint aggregates, so memory is bounded by
distinct templates and failures. Confirmed at 33.5 MB on 2.7 GB.

---

## Claims the data corrected

Two things stated confidently before measurement turned out to be wrong. Both are
recorded because the corrected version is less flattering than the original.

**`app_packages` is not "the single highest-value piece of configuration".**
Measured over 6,233 real Hadoop exceptions:

| `top_n` | with `app_packages` | deny-list default |
| --- | --- | --- |
| **1** (default) | **23** | 26 |
| 3 | 28 | 29 |
| 10 | 38 | 45 |

The `top_n=1` default is doing most of the work — 23 fingerprints against 38 at
`top_n=10` on identical input. `app_packages` is a refinement that mainly improves
the reported throw site. It also matters that this corpus is a forgiving case:
`org.apache.` sits in the framework deny-list, so nearly every Hadoop trace fell
back to all-frames scoring anyway.

**The `top_n=1` default survived a challenge it was not designed for.**
Scala numbers anonymous functions (`$$anonfun$1`) at compile time, so those names
shift between builds — a fingerprint anchored on them would break across a
recompile. In the Spark sample, **0% of throw sites were compiler-generated**;
frame 0 lands on real named methods and the unstable lambdas sit deeper in the
stack, where `top_n=1` ignores them.

→ `test_fingerprint.py::test_top_n_1_ignores_unstable_scala_lambda_frames`
   (asserts a lambda renumber leaves the fingerprint unchanged at `top_n=1`
   and changes it at `top_n=5`)

---

## Known limitations

Things that are true and unfixed, recorded so they are not rediscovered as bugs.

**The loghub 2k samples contain no stack traces.** They are single-line only, so
they validate header parsing and template mining but nothing in the exception
path. Pinned by `test_sources.py::test_no_published_sample_claims_stack_traces`,
which fails if that assumption ever changes.

**The scrubber over-redacts, on purpose.** Real Hadoop logs contain
`Token: Token { kind: ContainerToken ... }`, and the word after `Token:` is a
type name, not a credential — redacted anyway. Under-redacting a real secret is
far worse than redacting a harmless word, so the rule is not loosened.
→ `test_scrub.py::test_over_redaction_is_the_intended_failure_direction`

**Cold-start signal volume is high by construction.** Every template is novel on
first sight, so a cold run over a new corpus emits one signal per template
(Hadoop: 99). Warm state collapses this to real incidents (Hadoop: 5). Sparse
corpora also produce many zero-baseline rate breaches; raise `--min-count` for
those.

**Throughput is single-threaded**, ~10–26k lines/sec depending on trace density.
33.2M lines took 52 minutes. Nothing here is parallelised.

---

## Not validated

Stated plainly, because "tested" and "tested against this" are different claims.

- **The model planner has never made a live API call.** Its schema mapping and
  safety properties are covered offline (`test_react.py`), including that
  model-proposed actions can never auto-execute. The request itself is untested.
- **AWS sources have never run against real AWS.** Only the lazy-import path and
  constructor defaults are covered; `boto3` is not installed in CI.
- **Gated execution has never run a real handler against a real system.** Every
  gate is unit-tested; no production side effect has been performed.
- **The reaction tier has not been run against the Hadoop corpus** — those
  playbooks are payments- and JVM-service-shaped, and Hadoop's failures are
  infrastructure. Spark exercised it (finding 5).
- **No deploy correlation exists.** Several playbooks recommend "correlate
  against recent deploys"; that is a human step today.

---

## Test inventory

| File | Tests | Covers |
| --- | ---: | --- |
| `test_scrub.py` | 33 | PAN/IIN/Luhn, secrets, audit counts, deliberate over-redaction |
| `test_react.py` | 33 | Playbook matching and ranking, routing escalation, execution gates, planner safety |
| `test_ingest.py` | 16 | Header layouts, frame parsing (Java + Scala), exception chains |
| `test_sources.py` | 14 | loghub registry and real layouts, AWS lazy import |
| `test_pipeline.py` | 12 | End-to-end on the fixture, streaming/batch parity |
| `test_fingerprint.py` | 9 | Entry-path dedup, `top_n` semantics, line-number stability |
| `test_baseline.py` | 8 | Bucketing, novelty, rate breach, jitter suppression |
| `test_multiline.py` | 5 | Stack-trace assembly, orphan lines, truncation guard |
| `test_cli.py` | 3 | Report, JSON signals, JSON-lines events |
| `test_validation_doc.py` | 21 | Verifies every finding above still names a real test |
| **Total** | **154** | |

```bash
python -m pytest -q
```

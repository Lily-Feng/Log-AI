"""Command line entry point.

    javalogai analyze fixtures/payment-service.log --app-package com.visa.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable, Sequence

from .baseline.detector import DetectorConfig
from .pipeline import PipelineConfig, Tier1Pipeline
from .react.actions import RiskLevel
from .react.engine import ReactionEngine
from .react.execute import ActionExecutor, ExecutorConfig
from .schema import LogEvent
from .sources import loghub
from .template.fingerprint import describe_fingerprint
from .template.miner import MinerConfig


def _read_lines(path: str) -> Iterable[str]:
    if path == "-":
        yield from sys.stdin
        return
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        yield from fh


def _fmt(n: float) -> str:
    return f"{n:,.0f}" if n >= 1000 else f"{n:g}"


def _report(path: str, pipeline: Tier1Pipeline, events: list[LogEvent], signals: list, top: int) -> str:
    s = pipeline.stats
    out: list[str] = []
    w = out.append

    w(f"\n\033[1mTier-1 report\033[0m  {path}")
    w("=" * 72)

    parsed_pct = 100 * s.parsed_events / s.events if s.events else 0
    w(f"  Input        {_fmt(s.raw_lines)} raw lines -> {_fmt(s.events)} logical events "
      f"({parsed_pct:.1f}% parsed)")
    w(f"  Templates    {s.templates}  ({s.compression:,.0f} raw lines per template)")
    w(f"  Failures     {s.fingerprints} distinct fingerprint(s) across "
      f"{_fmt(s.events_with_exception)} events with a stack trace")
    hits = dict(pipeline.scrubber.totals)
    hit_str = " ".join(f"{k}={v}" for k, v in sorted(hits.items())) or "none"
    w(f"  Redaction    {_fmt(s.redacted_events)} events redacted  [{hit_str}]")
    w(f"  Signals      {len(signals)} escalated to tier 2/3")

    template_counts = Counter(e.template_id for e in events if e.template_id is not None)
    templates = pipeline.miner.templates()
    w(f"\n\033[1mTop templates by volume\033[0m")
    for tid, count in template_counts.most_common(top):
        share = 100 * count / s.events if s.events else 0
        w(f"  {count:>7,}  {share:5.1f}%  [{tid}] {templates.get(tid, '')[:90]}")

    groups: dict[str, list[LogEvent]] = defaultdict(list)
    for e in events:
        if e.fingerprint:
            groups[e.fingerprint].append(e)
    if groups:
        w(f"\n\033[1mDistinct failures\033[0m")
        for fp, evs in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            first = evs[0]
            chain = " -> ".join(c.rsplit(".", 1)[-1] for c in first.exception_chain)
            w(f"  {fp}  x{len(evs)}  {chain}")
            w(f"      {describe_fingerprint(first.exceptions)}")
            paths = {
                tuple(f.signature() for f in e.iter_frames() if f.is_application) for e in evs
            }
            if len(paths) > 1:
                w(f"      \033[2m{len(paths)} distinct call paths merged into this one failure\033[0m")

    if signals:
        w(f"\n\033[1mSignals\033[0m  \033[2m(the only records that would reach a model)\033[0m")
        for sig in signals[:top]:
            w(f"  [{sig.kind:<18}] {sig.key}")
            w(f"      {sig.detail}")
        if len(signals) > top:
            w(f"  \033[2m... {len(signals) - top} more\033[0m")

    w("")
    return "\n".join(out)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="javalogai", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    an = sub.add_parser("analyze", help="run the tier-1 pipeline over a log file")
    an.add_argument("path", nargs="?", default=None,
                    help="log file, or - for stdin (omit when using --loghub)")
    an.add_argument("--loghub-full", metavar="NAME",
                    help="analyze the FULL Zenodo dataset (Hadoop is 2.6MB and has real traces)")
    an.add_argument("--loghub", metavar="NAME",
                    help="analyze a loghub dataset instead of a file "
                         f"({', '.join(sorted(loghub.DATASETS))})")
    an.add_argument("--app-package", action="append", default=[], metavar="PREFIX",
                    help="your package prefix, e.g. com.visa. (repeatable, strongly recommended)")
    an.add_argument("--service", default=None, help="service name when logs do not carry one")
    an.add_argument("--bucket-seconds", type=int, default=60)
    an.add_argument("--z-threshold", type=float, default=3.0)
    an.add_argument("--min-count", type=int, default=10)
    an.add_argument("--min-ratio", type=float, default=2.0,
                    help="rate breach must also be this multiple of baseline")
    an.add_argument("--sim-th", type=float, default=0.4, help="drain similarity threshold")
    an.add_argument("--state", default=None, metavar="PATH",
                    help="persist templates and baselines here so they survive restarts")
    an.add_argument("--pan-keep-last4", action="store_true",
                    help="redact to [PAN:...1234] instead of [PAN]")
    an.add_argument("--scrub-optional", default="", metavar="NAMES",
                    help="comma-separated optional rules to enable: ipv4,phone,uuid")
    an.add_argument("--top", type=int, default=10)
    an.add_argument("--json", action="store_true", help="emit signals as JSON instead of a report")
    an.add_argument("--events-json", action="store_true", help="emit every event as JSON lines")
    an.add_argument("--react", action="store_true",
                    help="produce a reaction plan for every signal")
    an.add_argument("--llm", action="store_true",
                    help="use the model planner for signals no playbook matches "
                         "(requires: pip install \"javalogai[llm]\")")
    an.add_argument("--execute", action="store_true",
                    help="actually run plan actions (default is dry-run)")
    an.add_argument("--max-risk", default="notify",
                    choices=[r.label for r in RiskLevel],
                    help="ceiling on what may execute (default: notify)")
    an.add_argument("--approve-all", action="store_true",
                    help="auto-approve gated actions; requires --execute to have any effect")

    lh = sub.add_parser("loghub", help="list or fetch loghub demo datasets")
    lh.add_argument("loghub_command", choices=["list", "fetch"])
    lh.add_argument("name", nargs="?", help="dataset name (for fetch)")

    args = parser.parse_args(argv)
    if args.command == "loghub":
        return _loghub(args)
    if not args.path and not args.loghub and not args.loghub_full:
        parser.error("give a path, - for stdin, --loghub NAME, or --loghub-full NAME")

    config = PipelineConfig(
        app_packages=tuple(args.app_package),
        default_service=args.service,
        pan_keep_last4=args.pan_keep_last4,
        scrub_optional=tuple(x for x in args.scrub_optional.split(",") if x),
        miner=MinerConfig(sim_th=args.sim_th, persistence_path=args.state),
        detector=DetectorConfig(
            state_path=f"{args.state}.detector.json" if args.state else None,
            bucket_seconds=args.bucket_seconds,
            z_threshold=args.z_threshold,
            min_count=args.min_count,
            min_ratio=args.min_ratio,
        ),
    )
    pipeline = Tier1Pipeline(config)
    if args.loghub_full:
        label, lines = f"loghub-full:{args.loghub_full}", loghub.load_full(args.loghub_full)
    elif args.loghub:
        label, lines = f"loghub:{args.loghub}", loghub.load(args.loghub)
    else:
        label, lines = args.path, _read_lines(args.path)

    if args.events_json:
        for event in pipeline.events(lines):
            print(json.dumps(event.to_dict(), default=str))
        return 0

    events, signals = pipeline.run(lines)
    if args.state:
        pipeline.detector.save_state(f"{args.state}.detector.json")

    plans = _react(args, signals) if args.react else []

    if args.json:
        payload = ([p.to_dict() for p in plans] if args.react
                   else [s.to_dict(include_sample=False) for s in signals])
        print(json.dumps(payload, indent=2))
        return 0

    print(_report(label, pipeline, events, signals, args.top))
    for plan in plans:
        print(plan.render())
    if plans:
        print(_execution_report(args, plans))
    return 0


def _react(args, signals) -> list:
    planner = None
    if args.llm:
        from .react.llm import AnthropicPlanner
        planner = AnthropicPlanner()
    return ReactionEngine(planner=planner).plan_all(signals)


def _execution_report(args, plans) -> str:
    ceiling = RiskLevel[args.max_risk.upper()]
    executor = ActionExecutor(
        ExecutorConfig(dry_run=not args.execute, max_risk=ceiling),
        approver=(lambda a, p: True) if args.approve_all else None,
    )
    for plan in plans:
        executor.execute(plan)
    counts = Counter(r.status for r in executor.audit)
    mode = "EXECUTE" if args.execute else "dry-run"
    lines = [f"\n\033[1mAction execution\033[0m  mode={mode}  ceiling={ceiling.label}"]
    for status, n in counts.most_common():
        lines.append(f"  {n:>4}  {status}")
    if not args.execute:
        lines.append("  \033[2mnothing was run; pass --execute to enable, "
                     "and register handlers for the action kinds you want live\033[0m")
    return "\n".join(lines)


def _loghub(args) -> int:
    if args.loghub_command == "list":
        print(f"\n  {'dataset':<11}{'jvm':<6}{'full':>8}  {'traces':<8}layout")
        for d in loghub.DATASETS.values():
            size = f"{d.full_mb:.1f}MB" if d.full_mb else "-"
            print(f"  {d.name:<11}{'yes' if d.jvm else 'no':<6}{size:>8}  "
                  f"{'yes' if d.full_has_traces else 'no':<8}{d.layout}")
        print("\n  'traces' is for the FULL dataset; the 2k samples are single-line always.")
        print("  Hadoop full: 394k lines, 204k trace lines, 6,426 Caused-by chains.")
        print("  Try: javalogai analyze --loghub-full hadoop --app-package org.apache.hadoop.\n")
        return 0
    if not args.name:
        print("fetch needs a dataset name", file=sys.stderr)
        return 2
    print(loghub.fetch(args.name))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

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
from .schema import LogEvent
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
    an.add_argument("path", help="log file, or - for stdin")
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

    args = parser.parse_args(argv)

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

    if args.events_json:
        for event in pipeline.events(_read_lines(args.path)):
            print(json.dumps(event.to_dict(), default=str))
        return 0

    events, signals = pipeline.run(_read_lines(args.path))
    if args.state:
        pipeline.detector.save_state(f"{args.state}.detector.json")

    if args.json:
        print(json.dumps([s.to_dict(include_sample=False) for s in signals], indent=2))
        return 0

    print(_report(args.path, pipeline, events, signals, args.top))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

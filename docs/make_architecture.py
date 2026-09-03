"""Generates docs/architecture.excalidraw -- the tier design and data flow.

Written as a generator rather than hand-authored JSON so the geometry stays
consistent and the diagram can be regenerated when the design moves.

    python docs/make_architecture.py

Open the result at https://excalidraw.com (File -> Open) and edit freely.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

OUT = Path(__file__).parent / "architecture.excalidraw"
random.seed(7)

# Excalidraw's own palette, so edits in the app match what is generated here.
INK = "#1e1e1e"
BLUE = ("#1971c2", "#a5d8ff")
GREEN = ("#2f9e44", "#b2f2bb")
VIOLET = ("#6741d9", "#d0bfff")
YELLOW = ("#f08c00", "#ffec99")
RED = ("#e03131", "#ffc9c9")
GRAY = ("#495057", "#e9ecef")
WHITE = ("#495057", "#ffffff")

elements: list[dict] = []


def _base(kind: str, x: float, y: float, w: float, h: float, **kw) -> dict:
    el = {
        "id": f"{kind}-{len(elements)}-{random.randint(1000, 9999)}",
        "type": kind, "x": x, "y": y, "width": w, "height": h, "angle": 0,
        "strokeColor": INK, "backgroundColor": "transparent", "fillStyle": "solid",
        "strokeWidth": 2, "strokeStyle": "solid", "roughness": 1, "opacity": 100,
        "groupIds": [], "frameId": None, "roundness": None,
        "seed": random.randint(1, 2**31), "version": 1,
        "versionNonce": random.randint(1, 2**31), "isDeleted": False,
        "boundElements": [], "updated": 1, "link": None, "locked": False,
    }
    el.update(kw)
    return el


def text(x, y, s, size=16, color=INK, align="left", family=1, width=None):
    lines = s.split("\n")
    w = width if width is not None else max(len(l) for l in lines) * size * 0.55
    el = _base("text", x, y, w, len(lines) * size * 1.25,
               strokeColor=color, text=s, fontSize=size, fontFamily=family,
               textAlign=align, verticalAlign="top", containerId=None,
               originalText=s, lineHeight=1.25, autoResize=True)
    elements.append(el)
    return el


def box(x, y, w, h, label, colors=WHITE, size=15, family=1, dashed=False, radius=3):
    stroke, fill = colors
    rect = _base("rectangle", x, y, w, h, strokeColor=stroke, backgroundColor=fill,
                 roundness={"type": radius} if radius else None,
                 strokeStyle="dashed" if dashed else "solid")
    elements.append(rect)
    if label:
        t = _base("text", x + 8, y + h / 2 - size * 0.65, w - 16, size * 1.25,
                  text=label, fontSize=size, fontFamily=family, textAlign="center",
                  verticalAlign="middle", containerId=rect["id"], originalText=label,
                  lineHeight=1.25, strokeColor=INK, autoResize=False)
        elements.append(t)
        rect["boundElements"] = [{"id": t["id"], "type": "text"}]
    return rect


def arrow(x1, y1, x2, y2, color=INK, dashed=False, via=()):
    """`via` takes absolute waypoints, so long runs can be routed as elbows
    rather than diagonals that cut across other content."""
    pts = [[0, 0]] + [[vx - x1, vy - y1] for vx, vy in via] + [[x2 - x1, y2 - y1]]
    elements.append(_base(
        "arrow", x1, y1, x2 - x1, y2 - y1, strokeColor=color,
        roundness={"type": 2}, strokeStyle="dashed" if dashed else "solid",
        points=pts, lastCommittedPoint=None, startBinding=None, endBinding=None,
        startArrowhead=None, endArrowhead="arrow", elbowed=False))


# ---------------------------------------------------------------- title
text(60, 30, "logai — tier design and flow", size=30)
text(60, 72, "Cost at each tier is proportional to a different denominator. "
             "That is the whole design.", size=15, color="#5c5f66")

# ---------------------------------------------------------------- sources
text(60, 132, "SOURCES", size=13, color="#5c5f66")
srcs = [("files / stdin", False), ("S3 objects", False),
        ("CloudWatch Logs", False), ("Kafka / OTel", True)]
for i, (name, planned) in enumerate(srcs):
    box(60, 158 + i * 54, 190, 42, name, GRAY, size=14, dashed=planned)
text(60, 386, "dashed = not built yet", size=12, color="#868e96")

# ---------------------------------------------------------------- tier 1
T1X, T1Y, T1W, T1H = 300, 120, 1080, 250
box(T1X, T1Y, T1W, T1H, "", BLUE, radius=3)
text(T1X + 20, T1Y + 16, "TIER 1 — deterministic", size=19, color="#1971c2")
text(T1X + 20, T1Y + 44, "CPU only. No network, no model, no tokens.", size=13, color="#5c5f66")

stages = ["Multiline\nassembly", "Header\nparse", "Scrub\n(PAN/PII)",
          "Exception\nchain", "Fingerprint", "Template\nmine", "Baseline\ndetect"]
sw, gap = 128, 14
for i, s in enumerate(stages):
    bx = T1X + 22 + i * (sw + gap)
    jvm = s.startswith(("Exception", "Fingerprint"))
    box(bx, T1Y + 92, sw, 74, s, VIOLET if jvm else WHITE, size=13)
    if i < len(stages) - 1:
        arrow(bx + sw, T1Y + 129, bx + sw + gap, T1Y + 129)

text(T1X + 22, T1Y + 182, "purple = JVM enrichment; activates only when there are stack traces, "
                          "no-ops cleanly otherwise", size=12, color="#6741d9")
text(T1X + 22, T1Y + 206, "everything else is format-agnostic — 100% parse on Hadoop, ZooKeeper, "
                          "Spark, HDFS and OpenStack", size=12, color="#5c5f66")

for i in range(4):
    arrow(252, 179 + i * 54, T1X - 4, 200 + i * 8)

# ---------------------------------------------------------------- signal
SX, SY = 1424, 196
box(SX, SY, 210, 96, "", YELLOW)
text(SX + 18, SY + 16, "Signal", size=20)
text(SX + 18, SY + 46, "novelty · rate breach\nseverity burst", size=12, color="#5c5f66")
arrow(T1X + T1W, 244, SX - 4, 244)
text(SX + 6, SY + 104, "the only records\nthat travel further", size=12, color="#868e96")

# ---------------------------------------------------------------- reaction tier
RY = 470
box(300, RY, 520, 150, "", GREEN)
text(322, RY + 16, "TIER R — playbooks", size=19, color="#2f9e44")
text(322, RY + 44, "Pure predicate match. Free, reproducible,\n"
                   "explainable months later.", size=13, color="#5c5f66")
box(322, RY + 92, 230, 42, "10 built-in playbooks", WHITE, size=13)
box(566, RY + 92, 232, 42, "ranked by specificity", WHITE, size=13)
arrow(SX + 196, SY + 96, 560, RY - 6, via=[(1620, 412), (560, 412)])

box(900, RY, 480, 150, "", VIOLET)
text(922, RY + 16, "TIER 3 — model fallback", size=19, color="#6741d9")
text(922, RY + 44, "Only signals no playbook matched.\nThis is the only place tokens are spent.",
     size=13, color="#5c5f66")
box(922, RY + 92, 436, 42, "Claude · claude-opus-5", WHITE, size=13, family=3)
arrow(820, RY + 75, 896, RY + 75)
text(824, RY + 46, "no match", size=12, color="#868e96")

# ---------------------------------------------------------------- plan + gates
PY = 690
box(660, PY, 360, 56, "ReactionPlan", WHITE, size=17)
# Left of the box, not beneath it: the arrow down to the executor leaves from
# the centre and would otherwise run straight through this caption.
text(330, PY + 8, "hypotheses · evidence\nblast radius · routing\nactions",
     size=12, color="#868e96")
arrow(560, RY + 150, 800, PY - 4)
arrow(1140, RY + 150, 890, PY - 4)

GY = 810
box(300, GY, 1080, 128, "", YELLOW)
text(322, GY + 14, "ActionExecutor — four independent gates, all must open", size=18,
     color="#f08c00")
gates = ["dry-run\nby default", "risk ceiling\n(default: notify)",
         "human approval\n≥ mitigate", "registered handler\nfor that kind"]
for i, g in enumerate(gates):
    gx = 322 + i * 264
    box(gx, GY + 48, 228, 62, g, WHITE, size=13)
    if i < 3:
        # Centred in the 36px gap; a narrower gap clips into the next box.
        text(gx + 235, GY + 70, "AND", size=11, color="#f08c00")
arrow(840, PY + 56, 840, GY - 4)

AY = 978
acts = [("observe", GREEN), ("notify", GREEN), ("mitigate", RED),
        ("remediate", RED), ("destructive", RED)]
for i, (a, c) in enumerate(acts):
    box(322 + i * 216, AY, 198, 44, a, c, size=14)
arrow(840, GY + 128, 840, AY - 4)
text(322, AY + 54, "never auto-executes: model-proposed actions are approval-forced, "
                   "and an unknown risk parses as destructive", size=12, color="#e03131")

# ---------------------------------------------------------------- funnel panel
FX, FY = 1424, 470
box(FX, FY, 400, 496, "", GRAY)
text(FX + 20, FY + 16, "Measured", size=18)
text(FX + 20, FY + 44, "full Spark corpus, 2.7 GB", size=12, color="#868e96")

# Volume and failures are different axes -- signals are not downstream of
# failures -- so they are shown as separate reductions rather than one chain.
text(FX + 20, FY + 76, "VOLUME", size=11, color="#868e96")
vol = [("33,236,604", "raw lines"), ("27,410,255", "logical events"), ("259", "templates")]
for i, (n, label) in enumerate(vol):
    y = FY + 98 + i * 54
    box(FX + 20, y, 150, 40, n, BLUE, size=15)
    text(FX + 182, y + 11, label, size=13)
    if i < len(vol) - 1:
        arrow(FX + 95, y + 40, FX + 95, y + 54)

text(FX + 20, FY + 268, "FAILURES", size=11, color="#868e96")
fail = [("8,058", "events with a trace"), ("55", "distinct failures")]
for i, (n, label) in enumerate(fail):
    y = FY + 290 + i * 54
    box(FX + 20, y, 150, 40, n, YELLOW, size=15)
    text(FX + 182, y + 11, label, size=13)
    if i < len(fail) - 1:
        arrow(FX + 95, y + 40, FX + 95, y + 54)

text(FX + 20, FY + 404, "6,326 signals emitted on a cold run;\n"
                        "a warm run emits far fewer — every\n"
                        "template is novel exactly once.", size=12, color="#5c5f66")

# ---------------------------------------------------------------- cost legend
CY = 1070
text(FX + 20, FY + 470, "peak RSS 33.5 MB — bounded by templates, not input size",
     size=12, color="#5c5f66")

text(60, CY, "Cost model", size=18)
for i, (tier, denom, color) in enumerate([
        ("Tier 1", "lines/day — billions.  CPU only, $0 in tokens.", "#1971c2"),
        ("Tier R", "signals/day — dozens.  Deterministic, $0 in tokens.", "#2f9e44"),
        ("Tier 3", "unmatched signals/day — a handful.  The only paid path.", "#6741d9")]):
    text(60, CY + 34 + i * 26, f"{tier}   ∝  {denom}", size=14, color=color)

OUT.write_text(json.dumps({
    "type": "excalidraw", "version": 2, "source": "https://excalidraw.com",
    "elements": elements,
    "appState": {"gridSize": None, "viewBackgroundColor": "#ffffff"},
    "files": {},
}, indent=2))
print(f"wrote {OUT} ({len(elements)} elements)")

"""The reaction plan: what we think happened, and what to do about it."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..baseline.detector import Signal
from .actions import Action, RiskLevel

PLAYBOOK = "playbook"
LLM = "llm"
FALLBACK = "fallback"


@dataclass(slots=True)
class Routing:
    """Who hears about this, and how loudly."""

    team: str = "unassigned"
    channel: str = "#alerts"
    page: bool = False
    ticket_priority: str = "P4"

    def to_dict(self) -> dict[str, Any]:
        return {
            "team": self.team,
            "channel": self.channel,
            "page": self.page,
            "ticket_priority": self.ticket_priority,
        }


@dataclass(slots=True)
class ReactionPlan:
    signal: Signal
    title: str
    hypotheses: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)
    routing: Routing = field(default_factory=Routing)
    blast_radius: str = "unknown"
    #: playbook | llm | fallback -- recorded so an audit can tell a deterministic
    #: decision from a generated one without re-running anything.
    generated_by: str = FALLBACK
    playbook_id: str | None = None
    confidence: float = 0.0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def max_risk(self) -> RiskLevel:
        return max((a.risk for a in self.actions), default=RiskLevel.OBSERVE)

    @property
    def auto_actions(self) -> list[Action]:
        return [a for a in self.actions if not a.needs_approval()]

    @property
    def gated_actions(self) -> list[Action]:
        return [a for a in self.actions if a.needs_approval()]

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "generated_by": self.generated_by,
            "playbook_id": self.playbook_id,
            "confidence": round(self.confidence, 2),
            "created_at": self.created_at.isoformat(),
            "signal": self.signal.to_dict(include_sample=False),
            "hypotheses": self.hypotheses,
            "evidence": self.evidence,
            "blast_radius": self.blast_radius,
            "routing": self.routing.to_dict(),
            "actions": [a.to_dict() for a in self.actions],
        }

    def render(self, color: bool = True) -> str:
        def c(code: str, text: str) -> str:
            return f"\033[{code}m{text}\033[0m" if color else text

        out = [
            c("1", f"\n{self.title}"),
            f"  signal      {self.signal.kind}  {self.signal.key}",
            f"  source      {self.generated_by}"
            + (f" ({self.playbook_id})" if self.playbook_id else "")
            + f"   confidence {self.confidence:.0%}",
            f"  routing     {self.routing.team} -> {self.routing.channel}"
            + ("  " + c("31;1", "PAGE") if self.routing.page else "")
            + f"  [{self.routing.ticket_priority}]",
            f"  blast       {self.blast_radius}",
        ]
        if self.evidence:
            out.append(c("1", "  evidence"))
            out += [f"    - {e}" for e in self.evidence]
        if self.hypotheses:
            out.append(c("1", "  hypotheses (ranked)"))
            out += [f"    {i}. {h}" for i, h in enumerate(self.hypotheses, 1)]
        if self.actions:
            out.append(c("1", "  actions"))
            for a in self.actions:
                gate = c("33", "[approval]") if a.needs_approval() else c("32", "[auto]")
                out.append(f"    {gate} {c('2', a.risk.label):<12} {a.description}")
                if a.command:
                    out.append(f"        $ {a.command}")
                if a.rollback:
                    out.append(f"        {c('2', 'rollback: ' + a.rollback)}")
        return "\n".join(out)

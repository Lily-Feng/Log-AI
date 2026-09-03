"""Turns signals into reaction plans: playbooks first, model second."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Protocol, Sequence, runtime_checkable

from ..baseline.detector import Signal
from .actions import Action, RiskLevel
from .plan import FALLBACK, LLM, PLAYBOOK, ReactionPlan, Routing
from .playbook import BUILTIN_PLAYBOOKS, Playbook


@runtime_checkable
class Planner(Protocol):
    """A model-backed planner, used only when no playbook matches."""

    def plan(self, signal: Signal, evidence: Sequence[str]) -> ReactionPlan | None: ...


def build_evidence(signal: Signal) -> list[str]:
    """Facts drawn from the signal itself. No inference, no generation."""
    ev: list[str] = []
    if signal.bucket_start:
        ev.append(f"First observed at {signal.bucket_start.isoformat()}")
    if signal.service:
        ev.append(f"Service: {signal.service}")
    ev.append(signal.detail)
    if signal.expected is not None:
        ev.append(f"Observed {signal.observed:.0f} against a baseline of {signal.expected:.1f}")
    if signal.template:
        ev.append(f"Template: {signal.template}")

    sample = signal.sample
    if sample is not None:
        if sample.exception_chain:
            ev.append("Throwable chain: " + " -> ".join(sample.exception_chain))
        if (root := sample.root_cause) is not None and root.message:
            ev.append(f"Root cause message: {root.message.splitlines()[0][:200]}")
        app_frames = [f for f in sample.iter_frames() if f.is_application]
        if app_frames:
            ev.append(f"Throw site: {app_frames[0]}")
        if sample.trace_id:
            ev.append(f"Example trace id: {sample.trace_id}")
        if sample.logger:
            ev.append(f"Logger: {sample.logger}")
    if signal.fingerprint:
        ev.append(f"Failure fingerprint: {signal.fingerprint}")
    return ev


@dataclass(slots=True)
class EngineConfig:
    #: Plans below this confidence are still produced, but marked for review.
    review_below: float = 0.5
    #: Escalate routing to a page when a rate breach exceeds this multiple.
    page_on_ratio: float = 10.0


class ReactionEngine:
    def __init__(
        self,
        playbooks: Sequence[Playbook] | None = None,
        planner: Planner | None = None,
        config: EngineConfig | None = None,
    ) -> None:
        # Most specific first, so a rule naming an exception class beats a
        # catch-all on the same signal kind.
        self.playbooks = sorted(
            playbooks if playbooks is not None else BUILTIN_PLAYBOOKS,
            key=lambda p: (p.match.specificity, p.confidence),
            reverse=True,
        )
        self.planner = planner
        self.config = config or EngineConfig()

    def match(self, signal: Signal) -> Playbook | None:
        for playbook in self.playbooks:
            if playbook.match.matches(signal):
                return playbook
        return None

    def plan(self, signal: Signal) -> ReactionPlan:
        evidence = build_evidence(signal)

        if (playbook := self.match(signal)) is not None:
            plan = ReactionPlan(
                signal=signal,
                title=playbook.title,
                hypotheses=list(playbook.hypotheses),
                evidence=evidence,
                actions=list(playbook.actions),
                # Copy, never share: _escalate mutates routing per plan.
                routing=replace(playbook.routing),
                blast_radius=playbook.blast_radius,
                generated_by=PLAYBOOK,
                playbook_id=playbook.id,
                confidence=playbook.confidence,
            )
            self._escalate(plan)
            return plan

        if self.planner is not None:
            if (generated := self.planner.plan(signal, evidence)) is not None:
                generated.generated_by = LLM
                generated.evidence = generated.evidence or evidence
                self._escalate(generated)
                return generated

        return ReactionPlan(
            signal=signal,
            title=f"Unclassified signal: {signal.kind}",
            hypotheses=["No playbook matched and no model planner is configured."],
            evidence=evidence,
            actions=[
                Action("triage", "observe", "Manual triage required: no playbook covers this signal",
                       RiskLevel.OBSERVE),
            ],
            routing=Routing(team="service-owner", channel="#alerts", ticket_priority="P3"),
            generated_by=FALLBACK,
            confidence=0.2,
        )

    def _escalate(self, plan: ReactionPlan) -> None:
        """A large enough deviation pages regardless of what the playbook said."""
        signal = plan.signal
        if signal.expected and signal.expected > 0:
            ratio = signal.observed / signal.expected
            if ratio >= self.config.page_on_ratio and not plan.routing.page:
                plan.routing.page = True
                plan.routing.ticket_priority = "P1"
                plan.evidence.append(
                    f"Routing escalated to page: {ratio:.0f}x baseline exceeds "
                    f"the {self.config.page_on_ratio:.0f}x threshold"
                )

    def plan_all(self, signals: Sequence[Signal]) -> list[ReactionPlan]:
        return [self.plan(s) for s in signals]

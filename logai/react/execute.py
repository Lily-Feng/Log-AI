"""Gated execution of reaction plans.

Three independent gates, all of which must open before anything runs:

1. **dry_run** -- on by default. Nothing executes; results record what would have.
2. **risk ceiling** -- actions above `max_risk` are skipped regardless of approval.
3. **approval** -- actions that need a human get one, via the `approver` callback.

On top of that, execution dispatches only to handlers you register by action
kind. There is no default handler and no shell evaluation: a playbook cannot
cause execution of anything the operator has not explicitly wired up. An
unregistered kind is reported, not run.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .actions import (
    DENIED, DRY_RUN, EXECUTED, FAILED, NO_HANDLER, SKIPPED_RISK,
    Action, ActionResult, RiskLevel,
)
from .plan import ReactionPlan

Handler = Callable[[Action, ReactionPlan], str]
Approver = Callable[[Action, ReactionPlan], bool]


def deny_all(action: Action, plan: ReactionPlan) -> bool:
    return False


@dataclass(slots=True)
class ExecutorConfig:
    #: Nothing runs unless this is explicitly turned off.
    dry_run: bool = True
    #: Ceiling on what may execute even with approval. NOTIFY is a safe default:
    #: it permits telling humans and gathering data, and nothing else.
    max_risk: RiskLevel = RiskLevel.NOTIFY


class ActionExecutor:
    def __init__(
        self,
        config: ExecutorConfig | None = None,
        approver: Approver | None = None,
        handlers: dict[str, Handler] | None = None,
    ) -> None:
        self.config = config or ExecutorConfig()
        self.approver = approver or deny_all
        self.handlers: dict[str, Handler] = dict(handlers or {})
        self.audit: list[ActionResult] = []

    def register(self, kind: str, handler: Handler) -> None:
        self.handlers[kind] = handler

    def execute(self, plan: ReactionPlan) -> list[ActionResult]:
        results = [self._execute_one(action, plan) for action in plan.actions]
        self.audit.extend(results)
        return results

    def _execute_one(self, action: Action, plan: ReactionPlan) -> ActionResult:
        if action.risk > self.config.max_risk:
            return ActionResult(
                action, SKIPPED_RISK,
                f"risk {action.risk.label} exceeds ceiling {self.config.max_risk.label}",
            )
        if action.needs_approval() and not self.approver(action, plan):
            return ActionResult(action, DENIED, "approval not granted")
        if self.config.dry_run:
            return ActionResult(action, DRY_RUN, f"would run handler for kind {action.kind!r}")

        handler = self.handlers.get(action.kind)
        if handler is None:
            return ActionResult(
                action, NO_HANDLER,
                f"no handler registered for kind {action.kind!r}; nothing executed",
            )
        try:
            return ActionResult(action, EXECUTED, handler(action, plan))
        except Exception as exc:  # handlers touch real systems; never abort the plan
            return ActionResult(action, FAILED, "handler raised", error=f"{type(exc).__name__}: {exc}")

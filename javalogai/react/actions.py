"""Typed actions and the risk model that gates them.

An action never carries executable shell by default. `command` is a documented
suggestion for a human or for a handler you register deliberately; the executor
dispatches on `kind` to handlers you have explicitly wired. A playbook file that
could inject a shell string straight into production would be a remote code
execution path dressed up as configuration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class RiskLevel(IntEnum):
    """Ordered so a ceiling can be expressed as `risk <= max_risk`."""

    OBSERVE = 0      # gather more data; changes nothing
    NOTIFY = 1       # tell a human; changes nothing in the system under fault
    MITIGATE = 2     # reversible relief: raise a limit, shed load, open a breaker
    REMEDIATE = 3    # restart, scale, fail over, roll back
    DESTRUCTIVE = 4  # data loss or irreversible; never auto-executes

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(slots=True)
class Action:
    id: str
    kind: str
    description: str
    risk: RiskLevel = RiskLevel.OBSERVE
    command: str | None = None
    params: dict[str, Any] = field(default_factory=dict)
    rollback: str | None = None
    #: None means "derive from risk": anything above NOTIFY needs a human.
    requires_approval: bool | None = None

    def needs_approval(self) -> bool:
        if self.requires_approval is not None:
            return self.requires_approval
        return self.risk >= RiskLevel.MITIGATE

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "description": self.description,
            "risk": self.risk.label,
            "command": self.command,
            "params": self.params,
            "rollback": self.rollback,
            "requires_approval": self.needs_approval(),
        }


class ActionStatus(str):
    pass


EXECUTED = "executed"
DRY_RUN = "dry_run"
SKIPPED_RISK = "skipped_risk_ceiling"
DENIED = "approval_denied"
NO_HANDLER = "no_handler"
FAILED = "failed"


@dataclass(slots=True)
class ActionResult:
    action: Action
    status: str
    detail: str = ""
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status in (EXECUTED, DRY_RUN)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action.id,
            "kind": self.action.kind,
            "risk": self.action.risk.label,
            "status": self.status,
            "detail": self.detail,
            "error": self.error,
        }

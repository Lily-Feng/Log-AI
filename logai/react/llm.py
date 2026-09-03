"""Model-backed planner for signals no playbook covers.

This is the explain stage, and it is deliberately the last resort. Playbooks handle known
failure modes for free and reproducibly; the model exists for the long tail,
where writing a rule in advance was not possible. Cost therefore scales with
*unmatched* signals, which in a healthy system is a small number per day.

Two safety properties are enforced here in code rather than in the prompt,
because a prompt is not a control:

* **A generated action can never auto-execute.** Every action returned by the
  model has `requires_approval=True` forced on, regardless of the risk level it
  claimed. A model may propose a rollback; only a human may authorise one.
* **Risk levels are parsed against a fixed vocabulary**, and anything
  unrecognised is treated as the most dangerous level rather than the safest,
  so a novel or malformed value fails closed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Sequence

from ..baseline.detector import Signal
from .actions import Action, RiskLevel
from .plan import LLM, ReactionPlan, Routing

DEFAULT_MODEL = "claude-opus-5"
DEFAULT_MAX_TOKENS = 16000

ACTION_KINDS = (
    "observe", "notify", "ticket", "config", "traffic", "restart", "deploy", "scale",
)

SYSTEM_PROMPT = """\
You are an incident-response planner for JVM services in a payments environment.

You receive one anomaly signal and the evidence extracted from it, and produce a \
reaction plan. Work only from the evidence given. If the evidence is thin, say so \
in the hypotheses and lower your confidence; do not invent metrics, deploy \
history, dashboards, or service names that were not provided.

Rank hypotheses most-likely first, and make them specific enough to test. Prefer \
observation actions that would discriminate between your hypotheses over generic \
advice.

Assign risk honestly:
  observe    - gathers data, changes nothing
  notify     - tells a human, changes nothing
  mitigate   - reversible relief (raise a limit, shed load, open a breaker)
  remediate  - restart, scale, fail over, roll back
  destructive - irreversible or data-affecting

Every action you propose will be reviewed by a human before it can run, so \
propose what is genuinely useful rather than only what is safe. This is a \
payments system: a plan that quietly suppresses a symptom without identifying \
the cause is worse than one that says the cause is not yet known."""

_PLAN_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "title": {"type": "string", "description": "Short incident title"},
        "hypotheses": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Ranked, most likely first",
        },
        "blast_radius": {"type": "string"},
        "confidence": {"type": "number", "description": "0.0 to 1.0"},
        "routing": {
            "type": "object",
            "properties": {
                "team": {"type": "string"},
                "channel": {"type": "string"},
                "page": {"type": "boolean"},
                "ticket_priority": {"type": "string", "enum": ["P1", "P2", "P3", "P4"]},
            },
            "required": ["team", "channel", "page", "ticket_priority"],
            "additionalProperties": False,
        },
        "actions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "kind": {"type": "string", "enum": list(ACTION_KINDS)},
                    "description": {"type": "string"},
                    "risk": {
                        "type": "string",
                        "enum": ["observe", "notify", "mitigate", "remediate", "destructive"],
                    },
                    "command": {"type": ["string", "null"]},
                    "rollback": {"type": ["string", "null"]},
                },
                "required": ["id", "kind", "description", "risk", "command", "rollback"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["title", "hypotheses", "blast_radius", "confidence", "routing", "actions"],
    "additionalProperties": False,
}

_RISK_BY_NAME = {r.label: r for r in RiskLevel}


def parse_risk(value: str | None) -> RiskLevel:
    """Fail closed: an unrecognised risk is treated as the most dangerous."""
    return _RISK_BY_NAME.get((value or "").strip().lower(), RiskLevel.DESTRUCTIVE)


@dataclass(slots=True)
class AnthropicPlanner:
    """Plans unmatched signals with Claude.

    Requires the optional dependency: `pip install "logai[llm]"`.
    """

    model: str = DEFAULT_MODEL
    max_tokens: int = DEFAULT_MAX_TOKENS
    effort: str | None = None
    client: Any = None

    def _get_client(self) -> Any:
        if self.client is not None:
            return self.client
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise ImportError(
                'anthropic is required for the LLM planner. '
                'Install it with: pip install "logai[llm]"'
            ) from exc
        self.client = anthropic.Anthropic()
        return self.client

    def _prompt(self, signal: Signal, evidence: Sequence[str]) -> str:
        lines = [
            f"Signal kind: {signal.kind}",
            f"Signal key: {signal.key}",
            f"Service: {signal.service or 'unknown'}",
            "",
            "Evidence:",
            *(f"- {e}" for e in evidence),
        ]
        if (sample := signal.sample) is not None and sample.raw:
            excerpt = "\n".join(sample.raw.splitlines()[:40])
            lines += ["", "Example event (already redacted):", "```", excerpt, "```"]
        return "\n".join(lines)

    def plan(self, signal: Signal, evidence: Sequence[str]) -> ReactionPlan | None:
        client = self._get_client()
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": SYSTEM_PROMPT,
            "thinking": {"type": "adaptive"},
            "messages": [{"role": "user", "content": self._prompt(signal, evidence)}],
            "output_config": {"format": {"type": "json_schema", "schema": _PLAN_SCHEMA}},
        }
        if self.effort:
            kwargs["output_config"]["effort"] = self.effort

        response = client.messages.create(**kwargs)
        if getattr(response, "stop_reason", None) == "refusal":
            return None

        text = next((b.text for b in response.content if b.type == "text"), None)
        if not text:
            return None
        return self.to_plan(signal, list(evidence), json.loads(text))

    @staticmethod
    def to_plan(signal: Signal, evidence: list[str], data: dict[str, Any]) -> ReactionPlan:
        actions = []
        for i, raw in enumerate(data.get("actions", [])):
            kind = raw.get("kind", "observe")
            actions.append(
                Action(
                    id=raw.get("id") or f"llm-{i}",
                    kind=kind if kind in ACTION_KINDS else "observe",
                    description=raw.get("description", ""),
                    risk=parse_risk(raw.get("risk")),
                    command=raw.get("command") or None,
                    rollback=raw.get("rollback") or None,
                    # Non-negotiable: nothing a model proposed runs unattended.
                    requires_approval=True,
                )
            )

        r = data.get("routing") or {}
        return ReactionPlan(
            signal=signal,
            title=data.get("title") or f"Generated plan: {signal.kind}",
            hypotheses=list(data.get("hypotheses") or []),
            evidence=evidence,
            actions=actions,
            routing=Routing(
                team=r.get("team", "service-owner"),
                channel=r.get("channel", "#alerts"),
                page=bool(r.get("page", False)),
                ticket_priority=r.get("ticket_priority", "P3"),
            ),
            blast_radius=data.get("blast_radius", "unknown"),
            generated_by=LLM,
            confidence=float(data.get("confidence") or 0.5),
        )

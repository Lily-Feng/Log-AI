"""logai -- tiered log intelligence.

Format-agnostic through template mining and baselining; strongest on JVM
logs, where stack traces are reassembled into single events and failures are
fingerprinted by throw site. Non-JVM logs skip the exception layer and use
the rest of the pipeline unchanged.
"""

from .baseline.detector import BaselineDetector, DetectorConfig, Signal
from .pipeline import PipelineConfig, PipelineStats, Tier1Pipeline
from .react.actions import Action, ActionResult, RiskLevel
from .react.engine import EngineConfig, Planner, ReactionEngine
from .react.execute import ActionExecutor, ExecutorConfig
from .react.plan import ReactionPlan, Routing
from .react.playbook import BUILTIN_PLAYBOOKS, Match, Playbook
from .schema import ExceptionInfo, LogEvent, Severity, StackFrame

__version__ = "0.2.0"
__all__ = [
    # tier 1
    "Tier1Pipeline", "PipelineConfig", "PipelineStats",
    "BaselineDetector", "DetectorConfig", "Signal",
    "LogEvent", "ExceptionInfo", "StackFrame", "Severity",
    # reaction tier
    "ReactionEngine", "EngineConfig", "Planner", "ReactionPlan", "Routing",
    "Playbook", "Match", "BUILTIN_PLAYBOOKS",
    "Action", "ActionResult", "RiskLevel", "ActionExecutor", "ExecutorConfig",
]

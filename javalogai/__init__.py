"""javalogai -- deterministic tier-1 log intelligence for JVM applications."""

from .baseline.detector import BaselineDetector, DetectorConfig, Signal
from .pipeline import PipelineConfig, PipelineStats, Tier1Pipeline
from .schema import ExceptionInfo, LogEvent, Severity, StackFrame

__version__ = "0.1.0"
__all__ = [
    "Tier1Pipeline", "PipelineConfig", "PipelineStats",
    "BaselineDetector", "DetectorConfig", "Signal",
    "LogEvent", "ExceptionInfo", "StackFrame", "Severity",
]

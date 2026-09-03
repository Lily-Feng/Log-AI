"""Template mining over event messages.

Wraps upstream drain3 rather than reimplementing Drain. drain3 is maintained,
MIT-licensed, and -- importantly -- built for incremental use: `add_log_message`
consumes one message at a time and state is snapshotted through a persistence
handler, so a long-running process keeps its learned templates across restarts.

Two masking layers stack here and do different jobs:

* :mod:`javalogai.scrub` removes values that must not be stored or transmitted.
* drain3 masking (below) generalises values that are merely *variable* -- ids,
  durations, counts -- so that "took 12ms" and "took 4300ms" collapse to one
  template instead of two. Without it template counts drift upward forever.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple

from drain3 import TemplateMiner as _Drain3TemplateMiner
from drain3.file_persistence import FilePersistence
from drain3.masking import MaskingInstruction
from drain3.template_miner_config import TemplateMinerConfig

#: Applied to the message *before* Drain builds its tree.
DEFAULT_MASKING = (
    (r"(?<=\bid[=: ])[\w-]+", "ID"),
    (r"\b\d+(\.\d+)?\s?(ms|s|sec|secs|seconds|m|min|mins|h|hr|hrs)\b", "DURATION"),
    (r"\b0x[0-9a-fA-F]+\b", "HEX"),
    (r"\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b", "UUID"),
    (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "IP"),
    (r"(/[\w.-]+){2,}", "PATH"),
    (r"\b\d+\b", "NUM"),
)


class MinedTemplate(NamedTuple):
    template_id: int
    template: str
    is_new: bool
    cluster_size: int


@dataclass(slots=True)
class MinerConfig:
    """Drain tuning.

    `sim_th` is the knob that matters. Too low and unrelated messages merge into
    a useless `<*> <*> <*>`; too high and every parameter value spawns its own
    template. 0.4 is a reasonable default for application logs; re-check it per
    log source by watching the template count stabilise (or not).
    """

    sim_th: float = 0.4
    depth: int = 4
    max_children: int = 100
    max_clusters: int | None = None
    parametrize_numeric_tokens: bool = True
    persistence_path: str | Path | None = None
    snapshot_interval_minutes: int = 5


class TemplateMiner:
    def __init__(self, config: MinerConfig | None = None) -> None:
        self.config = config or MinerConfig()
        drain_config = TemplateMinerConfig()
        drain_config.drain_sim_th = self.config.sim_th
        drain_config.drain_depth = self.config.depth
        drain_config.drain_max_children = self.config.max_children
        drain_config.drain_max_clusters = self.config.max_clusters
        drain_config.parametrize_numeric_tokens = self.config.parametrize_numeric_tokens
        drain_config.snapshot_interval_minutes = self.config.snapshot_interval_minutes
        drain_config.masking_instructions = [
            MaskingInstruction(pattern, mask) for pattern, mask in DEFAULT_MASKING
        ]

        persistence = None
        if self.config.persistence_path is not None:
            path = Path(self.config.persistence_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            persistence = FilePersistence(str(path))

        self._miner = _Drain3TemplateMiner(persistence_handler=persistence, config=drain_config)

    def mine(self, message: str) -> MinedTemplate | None:
        if not message or not message.strip():
            return None
        result = self._miner.add_log_message(message.strip())
        return MinedTemplate(
            template_id=result["cluster_id"],
            template=result["template_mined"],
            is_new=result["change_type"] == "cluster_created",
            cluster_size=result["cluster_size"],
        )

    @property
    def template_count(self) -> int:
        return len(self._miner.drain.clusters)

    def templates(self) -> dict[int, str]:
        return {c.cluster_id: c.get_template() for c in self._miner.drain.clusters}

"""Demo and validation data from the loghub collection.

loghub (https://github.com/logpai/loghub) publishes real production logs from a
number of systems. Four of them are JVM applications, which makes them the best
freely available check that header parsing survives contact with formats nobody
designed for us.

One caveat worth stating plainly: the 2k samples published in the repository are
**single-line only -- they contain no stack traces**. They exercise header
parsing, template mining and baselining against real data, but they do not
exercise multiline assembly, exception chains or fingerprinting. Keep the
synthetic `fixtures/payment-service.log` for those.
"""

from __future__ import annotations

import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

BASE_URL = "https://raw.githubusercontent.com/logpai/loghub/master"
DEFAULT_CACHE = Path.home() / ".cache" / "javalogai" / "loghub"


@dataclass(frozen=True, slots=True)
class Dataset:
    name: str
    system: str
    layout: str
    jvm: bool
    has_stack_traces: bool
    note: str

    @property
    def url(self) -> str:
        return f"{BASE_URL}/{self.name}/{self.name}_2k.log"


DATASETS: dict[str, Dataset] = {
    d.name.lower(): d
    for d in (
        Dataset("Hadoop", "Apache Hadoop MapReduce", "ts LEVEL [thread] logger: msg",
                True, False, "Closest to a modern Logback layout."),
        Dataset("Zookeeper", "Apache ZooKeeper", "ts - LEVEL [thread:Logger@line] - msg",
                True, False, "Logger is packed inside the thread bracket."),
        Dataset("Spark", "Apache Spark on YARN", "yy/MM/dd HH:mm:ss LEVEL logger: msg",
                True, False, "Two-digit year; no thread field."),
        Dataset("HDFS", "Hadoop HDFS", "yymmdd HHMMSS pid LEVEL logger: msg",
                True, False, "Legacy layout, 2008-era."),
        Dataset("OpenStack", "OpenStack (Python)", "non-JVM control case",
                False, False, "Useful only to confirm graceful degradation."),
    )
}


def resolve(name: str) -> Dataset:
    key = name.lower()
    if key not in DATASETS:
        raise KeyError(f"unknown dataset {name!r}; choose from {sorted(DATASETS)}")
    return DATASETS[key]


def fetch(name: str, cache_dir: Path | str = DEFAULT_CACHE, force: bool = False) -> Path:
    """Download a dataset sample, caching it. Returns the local path."""
    dataset = resolve(name)
    cache = Path(cache_dir)
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / f"{dataset.name}_2k.log"
    if target.exists() and not force:
        return target
    with urllib.request.urlopen(dataset.url, timeout=60) as response:
        target.write_bytes(response.read())
    return target


def load(name: str, cache_dir: Path | str = DEFAULT_CACHE) -> Iterator[str]:
    path = fetch(name, cache_dir)
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        yield from fh

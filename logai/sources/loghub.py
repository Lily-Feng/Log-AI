"""Demo and validation data from the loghub collection.

loghub (https://github.com/logpai/loghub) publishes real production logs from a
number of systems. Four of them are JVM applications, which makes them the best
freely available check that header parsing survives contact with formats nobody
designed for us.

Two tiers of data, and the difference matters:

* The **2k samples** in the GitHub repo are single-line only -- they contain no
  stack traces at all. Good for header parsing and template mining, useless for
  multiline assembly, exception chains and fingerprinting.
* The **full datasets** on Zenodo do carry real traces. Hadoop is the one to
  reach for: 2.6 MB compressed, 394k lines, of which 204k are stack-trace
  continuations across 6,426 `Caused by:` chains, from a cluster with injected
  faults (machine down, network disconnect, disk full).

`fetch(name)` gets the sample; `fetch_full(name)` gets the Zenodo archive.
"""

from __future__ import annotations

import shutil
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

BASE_URL = "https://raw.githubusercontent.com/logpai/loghub/master"
ZENODO_RECORD = "3227177"
ZENODO_URL = f"https://zenodo.org/records/{ZENODO_RECORD}/files"
DEFAULT_CACHE = Path.home() / ".cache" / "logai" / "loghub"


@dataclass(frozen=True, slots=True)
class Dataset:
    name: str
    system: str
    layout: str
    jvm: bool
    has_stack_traces: bool
    note: str
    #: Size of the full Zenodo archive in MB; None if not published there.
    full_mb: float | None = None
    #: Whether the *full* dataset carries stack traces (the 2k samples never do).
    full_has_traces: bool = False

    @property
    def url(self) -> str:
        return f"{BASE_URL}/{self.name}/{self.name}_2k.log"

    @property
    def full_url(self) -> str:
        return f"{ZENODO_URL}/{self.name}.tar.gz?download=1"


DATASETS: dict[str, Dataset] = {
    d.name.lower(): d
    for d in (
        Dataset("Hadoop", "Apache Hadoop MapReduce", "ts LEVEL [thread] logger: msg",
                True, False, "Full dataset has real traces; the best validation set.",
                full_mb=2.6, full_has_traces=True),
        Dataset("Zookeeper", "Apache ZooKeeper", "ts - LEVEL [thread:Logger@line] - msg",
                True, False, "Logger is packed inside the thread bracket.", full_mb=0.5),
        Dataset("Spark", "Apache Spark on YARN", "yy/MM/dd HH:mm:ss LEVEL logger: msg",
                True, False, "Two-digit year; no thread field.", full_mb=183.5),
        Dataset("HDFS", "Hadoop HDFS", "yymmdd HHMMSS pid LEVEL logger: msg",
                True, False, "Legacy layout, 2008-era.", full_mb=161.9),
        Dataset("OpenStack", "OpenStack (Python)", "non-JVM control case",
                False, False, "Useful only to confirm graceful degradation.", full_mb=5.4),
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


def fetch_full(name: str, cache_dir: Path | str = DEFAULT_CACHE, force: bool = False) -> Path:
    """Download and extract the full Zenodo dataset. Returns the extracted directory.

    Sizes range from 0.5 MB (ZooKeeper) to 2 GB (Thunderbird) -- check
    `Dataset.full_mb` before pulling one on a metered connection.
    """
    import tarfile

    dataset = resolve(name)
    if dataset.full_mb is None:
        raise ValueError(f"{dataset.name} has no full archive on Zenodo")

    cache = Path(cache_dir) / "full"
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / dataset.name
    if target.exists() and not force:
        return target

    archive = cache / f"{dataset.name}.tar.gz"
    if not archive.exists() or force:
        # Copy in chunks rather than response.read(): these archives run to 2 GB
        # (Thunderbird), and buffering one wholly in memory to write it straight
        # back out is avoidable. Download to a temp name so an interrupted
        # transfer cannot be mistaken for a complete cached archive.
        partial = archive.with_suffix(".part")
        with urllib.request.urlopen(dataset.full_url, timeout=600) as response:
            with open(partial, "wb") as fh:
                shutil.copyfileobj(response, fh, length=1 << 20)
        partial.replace(archive)

    # Extract into a per-dataset directory. These archives disagree about their
    # internal layout -- Hadoop unpacks a pile of application_* directories with
    # no common root -- so imposing one here keeps the return value predictable.
    target.mkdir(parents=True, exist_ok=True)
    root = target.resolve()
    with tarfile.open(archive) as tf:
        # Refuse absolute paths and traversal before extracting a remote archive.
        for member in tf.getmembers():
            if not str((target / member.name).resolve()).startswith(str(root)):
                raise ValueError(f"unsafe path in archive: {member.name}")
        tf.extractall(target)
    return target


def load_full(name: str, cache_dir: Path | str = DEFAULT_CACHE) -> Iterator[str]:
    """Stream every .log line from a full dataset, file by file."""
    root = fetch_full(name, cache_dir)
    paths = sorted(root.rglob("*.log")) if root.is_dir() else [root]
    for path in paths:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            yield from fh

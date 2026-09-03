"""Time-bucketed counting over a rolling window.

Counts are kept per (service, template) rather than per raw line, which is the
whole economic point of the detect stage: the number of distinct keys tracks the
*templates* a system emits (hundreds to low thousands) rather than the number of
lines it emits (billions). Memory is bounded by keys x window, not by volume.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Hashable, Iterator

DEFAULT_BUCKET_SECONDS = 60
DEFAULT_WINDOW = 60


@dataclass(slots=True)
class Bucket:
    start: datetime
    counts: dict[Hashable, int] = field(default_factory=lambda: defaultdict(int))

    def add(self, key: Hashable, n: int = 1) -> None:
        self.counts[key] += n

    @property
    def total(self) -> int:
        return sum(self.counts.values())


class TimeBucketCounter:
    """Assigns events to fixed-width buckets and closes them in order.

    Events are expected roughly in timestamp order, as they are on a real
    stream. An event older than the current bucket is folded into the current
    bucket rather than reopening a closed one -- late data should not silently
    rewrite a baseline that has already fired.
    """

    def __init__(
        self,
        bucket_seconds: int = DEFAULT_BUCKET_SECONDS,
        window: int = DEFAULT_WINDOW,
    ) -> None:
        self.bucket_seconds = bucket_seconds
        self.width = timedelta(seconds=bucket_seconds)
        self.window = window
        self.closed: deque[Bucket] = deque(maxlen=window)
        self.current: Bucket | None = None

    def _floor(self, ts: datetime) -> datetime:
        epoch = int(ts.timestamp())
        return datetime.fromtimestamp(epoch - (epoch % self.bucket_seconds), tz=ts.tzinfo)

    def add(self, ts: datetime, key: Hashable, n: int = 1) -> Iterator[Bucket]:
        """Record an observation; yields each bucket that closed as a result."""
        start = self._floor(ts)
        if self.current is None:
            self.current = Bucket(start)
        elif start > self.current.start:
            while self.current is not None and start > self.current.start:
                closed = self.current
                self.closed.append(closed)
                yield closed
                next_start = closed.start + self.width
                self.current = Bucket(next_start if next_start <= start else start)
        self.current.add(key, n)

    def flush(self) -> Iterator[Bucket]:
        """Close the in-flight bucket at end of input."""
        if self.current is not None:
            self.closed.append(self.current)
            yield self.current
            self.current = None

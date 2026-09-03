"""AWS log sources.

Covers the two shapes that AWS Centralized Logging with OpenSearch (formerly
"Log Hub") actually leaves logs in: objects on S3, and CloudWatch Logs streams.
Both yield plain lines, so the tier-1 pipeline consumes them exactly like a file
-- multiline assembly still happens here, on our side, because neither source
preserves the notion of a logical event.

boto3 is an optional dependency: `pip install "logai[aws]"`. It is imported
lazily so the core package stays dependency-light.
"""

from __future__ import annotations

import gzip
import io
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterator

_BOTO_HINT = (
    "boto3 is required for AWS sources. Install it with: pip install \"logai[aws]\""
)


def _client(service: str, region: str | None = None, profile: str | None = None) -> Any:
    try:
        import boto3
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise ImportError(_BOTO_HINT) from exc
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    return session.client(service, region_name=region)


@dataclass(slots=True)
class S3LogSource:
    """Streams lines from every object under a prefix, newest-last.

    Objects are read and decoded one at a time rather than downloaded wholesale,
    so a prefix holding far more data than local disk is still consumable.
    Gzipped objects are decompressed transparently.
    """

    bucket: str
    prefix: str = ""
    region: str | None = None
    profile: str | None = None
    max_objects: int | None = None

    def keys(self) -> Iterator[str]:
        s3 = _client("s3", self.region, self.profile)
        paginator = s3.get_paginator("list_objects_v2")
        seen = 0
        for page in paginator.paginate(Bucket=self.bucket, Prefix=self.prefix):
            for obj in sorted(page.get("Contents", []), key=lambda o: o["LastModified"]):
                if obj["Key"].endswith("/"):
                    continue
                yield obj["Key"]
                seen += 1
                if self.max_objects is not None and seen >= self.max_objects:
                    return

    def __iter__(self) -> Iterator[str]:
        s3 = _client("s3", self.region, self.profile)
        for key in self.keys():
            body = s3.get_object(Bucket=self.bucket, Key=key)["Body"].read()
            if key.endswith(".gz") or body[:2] == b"\x1f\x8b":
                body = gzip.decompress(body)
            for line in io.StringIO(body.decode("utf-8", errors="replace")):
                yield line.rstrip("\n")


@dataclass(slots=True)
class CloudWatchLogsSource:
    """Streams events from a CloudWatch Logs group in timestamp order.

    CloudWatch splits a stack trace across one event per line unless the agent
    was configured with a multi_line_start_pattern, and even then it is not
    guaranteed. Ordering by timestamp and letting our own assembler regroup is
    the reliable path.
    """

    log_group: str
    start: datetime | None = None
    end: datetime | None = None
    filter_pattern: str = ""
    region: str | None = None
    profile: str | None = None
    limit: int | None = None

    def __iter__(self) -> Iterator[str]:
        logs = _client("logs", self.region, self.profile)
        kwargs: dict[str, Any] = {"logGroupName": self.log_group}
        if self.start:
            kwargs["startTime"] = int(self.start.timestamp() * 1000)
        if self.end:
            kwargs["endTime"] = int(self.end.timestamp() * 1000)
        if self.filter_pattern:
            kwargs["filterPattern"] = self.filter_pattern

        emitted = 0
        paginator = logs.get_paginator("filter_log_events")
        for page in paginator.paginate(**kwargs):
            for event in page.get("events", []):
                yield event["message"].rstrip("\n")
                emitted += 1
                if self.limit is not None and emitted >= self.limit:
                    return

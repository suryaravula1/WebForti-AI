from __future__ import annotations

import json
from dataclasses import asdict, dataclass


QUEUE_KEY = "webforti:jobs"


@dataclass(slots=True)
class QueuedJob:
    job_id: str
    cve_id: str
    submitted_by: str
    prefer_seed: bool = False

    @classmethod
    def from_json(cls, payload: str) -> "QueuedJob":
        return cls(**json.loads(payload))

    def to_json(self) -> str:
        return json.dumps(asdict(self))


class RedisJobQueue:
    def __init__(self, redis_url: str) -> None:
        try:
            import redis
        except ImportError as exc:
            raise RuntimeError("redis package is required for Redis queue backend") from exc
        self._client = redis.Redis.from_url(redis_url, decode_responses=True)

    def enqueue(self, job: QueuedJob) -> None:
        self._client.rpush(QUEUE_KEY, job.to_json())

    def dequeue(self, timeout_seconds: int = 5) -> QueuedJob | None:
        item = self._client.blpop(QUEUE_KEY, timeout=timeout_seconds)
        if not item:
            return None
        _, payload = item
        return QueuedJob.from_json(payload)

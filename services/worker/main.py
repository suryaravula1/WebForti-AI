from __future__ import annotations

import time

from services.gateway.pipeline import run_job
from services.gateway.queue import RedisJobQueue
from services.gateway.state import InMemoryJobStore
from webforti_common.settings import load_settings


def run_once() -> bool:
    settings = load_settings()
    queue = RedisJobQueue(settings.redis_url)
    queued = queue.dequeue(timeout_seconds=1)
    if queued is None:
        return False

    store = InMemoryJobStore()
    record = store.create(queued.cve_id, submitted_by=queued.submitted_by, job_id=queued.job_id)
    run_job(record.job.job_id, store, settings, prefer_seed=queued.prefer_seed)
    return True


def main() -> int:
    while True:
        processed = run_once()
        if not processed:
            time.sleep(1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

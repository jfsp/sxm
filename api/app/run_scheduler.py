"""Standalone scheduler for POC / no-Docker mode (replaces Celery beat + worker).

Runs the same job functions the API exposes, on fixed intervals, in one process.
No broker, no worker pool. Designed to run under systemd (Type=simple); it handles
SIGTERM/SIGINT for clean shutdown and logs to stdout (journald).

    python -m app.run_scheduler

Cadence is configured via SXM_SCHEDULER_* settings (see config.py). For a POC you can
set short intervals; for production-like behavior use the daily/weekly defaults.
"""
from __future__ import annotations

import logging
import signal
import time
from dataclasses import dataclass
from typing import Callable

from .config import get_settings
from .db import SessionLocal
from .seed_data import bootstrap
from .tasks import jobs

settings = get_settings()
log = logging.getLogger("sxm.scheduler")

_stop = False


def _handle_signal(signum, _frame):  # noqa: ANN001
    global _stop
    _stop = True
    log.info("received signal %s — shutting down after current job", signum)


def is_due(now: float, last: float, interval: int) -> bool:
    """Pure helper (unit-tested)."""
    return (now - last) >= interval


@dataclass
class Job:
    name: str
    interval: int
    fn: Callable
    last: float = 0.0


def build_jobs() -> list[Job]:
    return [
        Job("full_cycle", settings.scheduler_full_cycle_seconds,
            lambda db: jobs.run_full_cycle(db)),
        Job("snapshot", settings.scheduler_snapshot_seconds,
            lambda db: jobs.take_snapshot(db, settings.scheduler_snapshot_granularity)),
        Job("purge", settings.scheduler_purge_seconds,
            lambda db: {"purged": jobs.purge_observations(db)}),
    ]


def run_job(job: Job) -> None:
    t0 = time.time()
    try:
        with SessionLocal() as db:
            result = job.fn(db)
        log.info("job %s ok in %.1fs — %s", job.name, time.time() - t0, result)
    except Exception:  # noqa: BLE001 — one bad run must not kill the loop
        log.exception("job %s FAILED", job.name)


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    bootstrap()  # idempotent; ensures schema+seed even if the scheduler starts first
    joblist = build_jobs()
    now = time.time()
    for j in joblist:
        j.last = now  # next run one interval out by default

    if settings.scheduler_run_on_start:
        fc = next(j for j in joblist if j.name == "full_cycle")
        log.info("run-on-start: executing full_cycle")
        run_job(fc)
        fc.last = time.time()

    log.info("scheduler started — intervals(s): %s",
             {j.name: j.interval for j in joblist})

    while not _stop:
        now = time.time()
        for j in joblist:
            if _stop:
                break
            if is_due(now, j.last, j.interval):
                run_job(j)
                j.last = time.time()
        # short tick so shutdown is responsive
        for _ in range(10):
            if _stop:
                break
            time.sleep(0.5)

    log.info("scheduler stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

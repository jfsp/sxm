from __future__ import annotations

from celery import Celery
from celery.schedules import crontab

from ..config import get_settings
from ..db import SessionLocal
from . import jobs

settings = get_settings()

celery = Celery("sxm", broker=settings.redis_url, backend=settings.redis_url)
celery.conf.timezone = "UTC"


@celery.task(name="sxm.full_cycle")
def full_cycle():
    with SessionLocal() as db:
        return jobs.run_full_cycle(db)


@celery.task(name="sxm.snapshot")
def snapshot(granularity: str = "weekly"):
    with SessionLocal() as db:
        return jobs.take_snapshot(db, granularity)


@celery.task(name="sxm.purge_observations")
def purge_observations():
    with SessionLocal() as db:
        return jobs.purge_observations(db)


@celery.on_after_configure.connect
def setup_periodic(sender, **_):
    # Tenable cadence is weekly (C10); run the pull+reconcile cycle daily so
    # daily sources (Shadowserver) corroborate disappearances sooner (section 7).
    sender.add_periodic_task(crontab(minute=0, hour=6), full_cycle.s(), name="daily-cycle")
    # Weekly trend snapshot (Mondays 06:30). Daily snapshot is an admin toggle (C12).
    sender.add_periodic_task(
        crontab(minute=30, hour=6, day_of_week=1), snapshot.s("weekly"), name="weekly-snapshot"
    )
    if settings.daily_snapshots:
        sender.add_periodic_task(
            crontab(minute=45, hour=6), snapshot.s("daily"), name="daily-snapshot"
        )
    # Retention: purge aged raw observation payloads weekly (Sundays 03:00).
    sender.add_periodic_task(
        crontab(minute=0, hour=3, day_of_week=0), purge_observations.s(), name="retention-purge"
    )

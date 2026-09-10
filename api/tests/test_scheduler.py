"""Standalone scheduler: due-timing + job wiring (no Celery/Redis)."""
from app.run_scheduler import is_due, build_jobs


def test_is_due():
    assert is_due(now=100.0, last=0.0, interval=60) is True
    assert is_due(now=59.0, last=0.0, interval=60) is False
    assert is_due(now=60.0, last=0.0, interval=60) is True


def test_build_jobs_covers_cycle_snapshot_purge():
    names = {j.name for j in build_jobs()}
    assert names == {"full_cycle", "snapshot", "purge"}
    assert all(j.interval > 0 for j in build_jobs())

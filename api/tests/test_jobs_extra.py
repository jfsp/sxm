"""Throttle, retention, and auto-probe-on-doubt integration tests."""
from datetime import timedelta

from sqlalchemy import select, func


def test_retention_purge(db, monkeypatch):
    from app.tasks import jobs
    from app.models import Observation, utcnow
    with db() as s:
        jobs.run_full_cycle(s)
        total = s.scalar(select(func.count()).select_from(Observation))
        assert total > 0
        # age half the observations beyond the window
        obs = list(s.scalars(select(Observation)))
        for o in obs[: len(obs) // 2]:
            o.observed_at = utcnow() - timedelta(days=999)
        s.commit()
        import app.tasks.jobs as J
        monkeypatch.setattr(J.settings, "observation_retention_days", 90)
        removed = jobs.purge_observations(s)
        assert removed == len(obs) // 2


def test_auto_probe_on_doubt_toggle(db, monkeypatch):
    from app.tasks import jobs
    from app.models import Service, Host, Observation, Source
    with db() as s:
        # enable the toggle
        monkeypatch.setattr(jobs.settings, "auto_probe_on_doubt", True)
        monkeypatch.setattr(jobs.settings, "connector_mode", "fixtures")
        jobs.run_ingest_cycle(s)
        jobs.run_reconcile(s)
        # 198.51.100.10:22 owned, Tenable-only (score 5) -> doubt -> should be auto-probed
        host = s.scalar(select(Host).where(Host.ip == "198.51.100.10"))
        svc = s.scalar(select(Service).where(Service.host_id == host.id, Service.port == 22))
        assert svc.confidence_score == 5
        res = jobs.auto_probe_doubt(s)
        assert res["probed"] >= 1
        # a probe observation now exists for that service
        probe_src = s.scalar(select(Source).where(Source.name == "nmap_probe"))
        n = s.scalar(select(func.count()).select_from(Observation)
                     .where(Observation.service_id == svc.id, Observation.source_id == probe_src.id))
        assert n >= 1


def test_throttle_blocks_second_send(db):
    from app.alerting import router
    from app.models import (
        Service, Host, Protocol, ExposureEvent, ExposureEventType, AlertRule,
    )
    with db() as s:
        # tighten the seeded 'appeared' rule to throttle within an hour
        rule = s.scalar(select(AlertRule).where(AlertRule.event_type == ExposureEventType.appeared))
        rule.dedup_window_seconds = 0
        rule.throttle_seconds = 3600
        host = Host(ip="9.9.9.9"); s.add(host); s.flush()
        svc = Service(host_id=host.id, port=443, protocol=Protocol.tcp); s.add(svc); s.flush()
        e1 = ExposureEvent(service_id=svc.id, type=ExposureEventType.appeared, confidence_score=8)
        e2 = ExposureEvent(service_id=svc.id, type=ExposureEventType.appeared, confidence_score=8)
        s.add_all([e1, e2]); s.flush()
        d1 = router.dispatch_event(s, e1)
        d2 = router.dispatch_event(s, e2)   # throttled
        assert len(d1) == 1 and d1[0].status == "sent"
        assert len(d2) == 0

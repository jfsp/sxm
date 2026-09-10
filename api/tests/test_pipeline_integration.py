"""End-to-end pipeline test on sqlite (uses shared `db` fixture from conftest)."""
from sqlalchemy import select


def test_full_cycle(db):
    from app.tasks import jobs
    from app.models import Service, Host, ExposureEvent, DnsName, Attribution, ExposureState

    with db() as s:
        summary = jobs.run_full_cycle(s)
        assert summary["ingested"]["tenable"] == 4

        # 198.51.100.10:443 -> tenable(5)+shadowserver(3)=8 -> exposed + appeared
        host = s.scalar(select(Host).where(Host.ip == "198.51.100.10"))
        svc = s.scalar(select(Service).where(Service.host_id == host.id, Service.port == 443))
        assert svc.confidence_score == 8
        assert svc.exposure_state == ExposureState.exposed
        assert svc.attribution == Attribution.owned

        # off-range 192.0.2.30 -> shodan(2) only -> candidate, doubt
        cand_host = s.scalar(select(Host).where(Host.ip == "192.0.2.30"))
        cand = s.scalar(select(Service).where(Service.host_id == cand_host.id))
        assert cand.attribution == Attribution.candidate
        assert cand.confidence_score == 2
        assert cand.exposure_state == ExposureState.first_seen

        # appeared event fired for the confirmed service
        appeared = s.scalars(
            select(ExposureEvent).where(ExposureEvent.type == "appeared")
        ).all()
        assert any(e.service_id == svc.id for e in appeared)

        # DNS name with nothing behind it
        dangling = s.scalars(
            select(DnsName).where(DnsName.resolves_to_host_id.is_(None))
        ).all()
        assert any(d.fqdn == "old.example.org" for d in dangling)


def test_probe_breaks_and_reconciles(db):
    from app.tasks import jobs
    from app.models import Service, Host

    with db() as s:
        jobs.run_full_cycle(s)
        # 198.51.100.10:22 has Tenable only (score 5, doubt band).
        # Probe stub returns present for even ports -> adds weight 4 -> 9 (confirmed).
        host = s.scalar(select(Host).where(Host.ip == "198.51.100.10"))
        svc = s.scalar(select(Service).where(Service.host_id == host.id, Service.port == 22))
        before = svc.confidence_score
        assert before == 5
        jobs.run_probe(s, "198.51.100.10", 22, "tcp")
        s.refresh(svc)
        assert svc.confidence_score == before + 4  # tenable(5) + probe(4) = 9

"""CSV inventory import: parsing + seeding semantics + idempotency."""
import textwrap

from sqlalchemy import select, func

CSV = textwrap.dedent("""\
    IP,DNS name,Port number,Port type (TCP/udp),Organisational unit responsible,Notes
    198.51.100.10,www.example.org,443,TCP,Web Team,Public site
    198.51.100.10,,22,tcp,Web Team,SSH mgmt
    203.0.113.5,api.example.org,8443,TCP,API Team,
    ,old.example.org,,,Web Team,Decommissioned name
    192.0.2.9,udptest.example.org,53,UDP,Infra,DNS resolver
""")


def _rows(tmp_path):
    from app.import_csv import parse_rows
    p = tmp_path / "inv.csv"
    p.write_text(CSV)
    return parse_rows(str(p)), p


def test_parse_headers_and_positional(tmp_path):
    rows, _ = _rows(tmp_path)
    assert len(rows) == 5
    assert rows[0] == {"ip": "198.51.100.10", "dns": "www.example.org", "port": "443",
                       "ptype": "TCP", "ou": "Web Team", "notes": "Public site"}
    assert rows[3]["ip"] == "" and rows[3]["dns"] == "old.example.org"


def test_import_seeds_exposed_owned_in_production(db, tmp_path):
    from app.import_csv import parse_rows, import_rows
    from app.models import (Service, Host, DnsName, OrgUnit, Source, Attribution,
                            ExposureState, LifecycleStatus, Protocol, Observation)
    rows, _ = _rows(tmp_path)
    with db() as s:
        summ = import_rows(s, rows, actor_user_id=None, weight=7, staleness=30)
        assert summ.services_created == 4        # two on .10, one .5, one udp .9
        assert summ.dns_created == 4
        assert summ.dns_nothing_behind == 1      # old.example.org, no IP
        assert summ.ou_created == 3              # Web Team, API Team, Infra
        assert summ.annotations_added == 3       # three service rows had notes (row4 has no svc)
        assert summ.notes_skipped_no_service == 1

        host = s.scalar(select(Host).where(Host.ip == "198.51.100.10"))
        svc = s.scalar(select(Service).where(Service.host_id == host.id, Service.port == 443))
        assert svc.exposure_state == ExposureState.exposed
        assert svc.lifecycle_status == LifecycleStatus.in_production
        assert svc.attribution == Attribution.owned
        assert svc.confidence_score == 7
        assert svc.org_unit_id == s.scalar(select(OrgUnit.id).where(OrgUnit.name == "Web Team"))

        udp = s.scalar(select(Service).where(Service.protocol == Protocol.udp))
        assert udp.port == 53

        # dns linked to host vs nothing-behind
        dangling = s.scalar(select(DnsName).where(DnsName.fqdn == "old.example.org"))
        assert dangling.resolves_to_host_id is None
        linked = s.scalar(select(DnsName).where(DnsName.fqdn == "www.example.org"))
        assert linked.resolves_to_host_id == host.id

        # manual_import source + evidence exist
        src = s.scalar(select(Source).where(Source.name == "manual_import"))
        assert src.weight == 7
        nobs = s.scalar(select(func.count()).select_from(Observation)
                        .where(Observation.source_id == src.id))
        assert nobs == 4


def test_import_is_idempotent(db, tmp_path):
    from app.import_csv import import_rows
    from app.models import Service, Annotation, Observation
    rows, _ = _rows(tmp_path)
    with db() as s:
        import_rows(s, rows, actor_user_id=None, weight=7, staleness=30)
        n1 = s.scalar(select(func.count()).select_from(Service))
        a1 = s.scalar(select(func.count()).select_from(Annotation))
        o1 = s.scalar(select(func.count()).select_from(Observation))
        import_rows(s, rows, actor_user_id=None, weight=7, staleness=30)  # re-run
        assert s.scalar(select(func.count()).select_from(Service)) == n1
        assert s.scalar(select(func.count()).select_from(Annotation)) == a1
        assert s.scalar(select(func.count()).select_from(Observation)) == o1


def test_dry_run_writes_nothing(db, tmp_path):
    from app.import_csv import import_rows
    from app.models import Service
    rows, _ = _rows(tmp_path)
    with db() as s:
        import_rows(s, rows, actor_user_id=None, weight=7, staleness=30, dry_run=True)
        assert s.scalar(select(func.count()).select_from(Service)) == 0

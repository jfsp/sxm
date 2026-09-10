from datetime import datetime, timezone, timedelta

from app.engine.confidence import Evidence, compute_score, classify

NOW = datetime(2026, 8, 4, tzinfo=timezone.utc)


def ev(name, weight, present=True, age_days=0, staleness=14, sid=None):
    return Evidence(
        source_id=sid if sid is not None else hash(name) & 0xFFFF,
        source_name=name,
        weight=weight,
        asserts_present=present,
        observed_at=NOW - timedelta(days=age_days),
        staleness_days=staleness,
    )


def test_tenable_alone_is_doubt():
    r = compute_score([ev("tenable", 5)], NOW)
    assert r.score == 5
    assert classify(r, 7) == "doubt"
    assert r.tenable_present and not r.external_present
    assert not r.coverage_gap


def test_tenable_plus_external_confirms():
    r = compute_score([ev("tenable", 5), ev("shodan", 2)], NOW)
    assert r.score == 7
    assert classify(r, 7) == "confirmed"


def test_coverage_gap_when_tenable_missing():
    r = compute_score([ev("shadowserver", 3), ev("shodan", 2)], NOW)
    assert r.score == 5
    assert r.coverage_gap is True
    assert classify(r, 7) == "doubt"


def test_stale_observation_does_not_count():
    r = compute_score([ev("tenable", 5, age_days=30, staleness=14)], NOW)
    assert r.score == 0
    assert classify(r, 7) == "absent"


def test_latest_observation_wins_per_source():
    # same source: recent 'absent' overrides older 'present'
    e_old = ev("tenable", 5, present=True, age_days=10, sid=1)
    e_new = ev("tenable", 5, present=False, age_days=1, sid=1)
    r = compute_score([e_old, e_new], NOW)
    assert r.score == 0


def test_probe_not_treated_as_external():
    r = compute_score([ev("nmap_probe", 4)], NOW)
    assert r.external_present is False
    assert r.score == 4

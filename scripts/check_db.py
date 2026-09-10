#!/usr/bin/env python3
"""SXM data-consistency auditor.

Goes beyond "schema is valid" to check the data actually makes sense:
referential integrity, service provenance (every service backed by evidence from a
known source — manual import / probe / scanners), status coherence (exposure vs
lifecycle), attribution vs ownership seeds, confidence/exposure drift vs what the engine
would compute, and scheduling readiness (enabled sources, alert rules/channels wired).

    SXM_DATABASE_URL="sqlite+pysqlite:////opt/sxm/data/sxm.db" python3 scripts/check_db.py
    python3 scripts/check_db.py --strict     # exit non-zero on warnings too

Exit code: 1 if any FAIL (or any WARN with --strict), else 0.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# make the app package importable when run from the repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from sqlalchemy import select, func  # noqa: E402
from app.db import SessionLocal  # noqa: E402
from app.config import get_settings  # noqa: E402
from app.models import (  # noqa: E402
    Host, Service, DnsName, OrgUnit, Source, OwnershipSeed, Observation, Annotation,
    Role, User, RoleName, AlertChannel, AlertRule, ExposureEventType, SnapshotMetric,
    ExposureState, LifecycleStatus, Attribution, utcnow,
)
from app.engine.pipeline import _evidence_for  # noqa: E402
from app.engine.confidence import compute_score, classify  # noqa: E402
from app.engine.correlation import attribute  # noqa: E402

settings = get_settings()
KNOWN_SOURCES = {"tenable", "shadowserver", "shodan", "dnsdumpster", "nmap_probe",
                 "manual_import", "elsa", "socradar"}

OK, WARN, FAIL = "OK", "WARN", "FAIL"


class Report:
    def __init__(self):
        self.rows: list[tuple[str, str, str]] = []

    def add(self, level, section, msg):
        self.rows.append((level, section, msg))

    def counts(self):
        c = {OK: 0, WARN: 0, FAIL: 0}
        for lvl, _, _ in self.rows:
            c[lvl] += 1
        return c

    def dump(self):
        section = None
        for lvl, sec, msg in self.rows:
            if sec != section:
                print(f"\n== {sec} ==")
                section = sec
            print(f"  [{lvl}] {msg}")
        c = self.counts()
        print(f"\n{c[OK]} ok, {c[WARN]} warn, {c[FAIL]} fail")


def _n(db, model, *where):
    q = select(func.count()).select_from(model)
    for w in where:
        q = q.where(w)
    return db.scalar(q) or 0


# --------------------------- checks -------------------------------------- #
def check_referential(db, r):
    sec = "referential integrity"
    host_ids = set(db.scalars(select(Host.id)))
    svc_ids = set(db.scalars(select(Service.id)))
    src_ids = set(db.scalars(select(Source.id)))
    ou_ids = set(db.scalars(select(OrgUnit.id)))

    orphan_svc = [s.id for s in db.scalars(select(Service)) if s.host_id not in host_ids]
    r.add(FAIL if orphan_svc else OK, sec,
          f"services with missing host: {len(orphan_svc)}" +
          (f" (ids {orphan_svc[:10]})" if orphan_svc else ""))

    bad_obs_src = _n(db, Observation, ~Observation.source_id.in_(src_ids)) if src_ids else 0
    r.add(FAIL if bad_obs_src else OK, sec, f"observations with unknown source: {bad_obs_src}")

    bad_obs_svc = [o.id for o in db.scalars(
        select(Observation).where(Observation.service_id.is_not(None)))
        if o.service_id not in svc_ids]
    r.add(FAIL if bad_obs_svc else OK, sec, f"service-observations with missing service: {len(bad_obs_svc)}")

    bad_ann = _n(db, Annotation, ~Annotation.service_id.in_(svc_ids)) if svc_ids else _n(db, Annotation)
    r.add(FAIL if bad_ann else OK, sec, f"annotations with missing service: {bad_ann}")

    bad_dns = [d.id for d in db.scalars(
        select(DnsName).where(DnsName.resolves_to_host_id.is_not(None)))
        if d.resolves_to_host_id not in host_ids]
    r.add(FAIL if bad_dns else OK, sec, f"dns names resolving to missing host: {len(bad_dns)}")

    bad_ou = [s.id for s in db.scalars(
        select(Service).where(Service.org_unit_id.is_not(None)))
        if s.org_unit_id not in ou_ids]
    r.add(FAIL if bad_ou else OK, sec, f"services pointing to missing OU: {len(bad_ou)}")

    dupes = db.execute(
        select(Service.host_id, Service.port, Service.protocol, func.count().label("c"))
        .group_by(Service.host_id, Service.port, Service.protocol).having(func.count() > 1)
    ).all()
    r.add(FAIL if dupes else OK, sec, f"duplicate service identities (host,port,proto): {len(dupes)}")


def check_provenance(db, r):
    sec = "service provenance & status"
    services = list(db.scalars(select(Service)))
    total = len(services)
    r.add(OK, sec, f"services total: {total}")
    if total == 0:
        r.add(WARN, sec, "no services present — has a cycle run / inventory been imported?")
        return

    no_evidence = []
    src_by_svc: dict[int, set[str]] = {}
    for s in services:
        ev = _evidence_for(db, s)
        names = {e.source_name for e in ev}
        src_by_svc[s.id] = names
        if not names:
            no_evidence.append(s.id)
    r.add(FAIL if no_evidence else OK, sec,
          f"services with NO observation/evidence: {len(no_evidence)}" +
          (f" (ids {no_evidence[:10]})" if no_evidence else ""))

    # every service must carry a status (enum guarantees non-null; guard anyway)
    missing_status = [s.id for s in services if s.exposure_state is None or s.lifecycle_status is None]
    r.add(FAIL if missing_status else OK, sec, f"services missing exposure/lifecycle status: {len(missing_status)}")

    # provenance breakdown
    def frac(name):
        return sum(1 for n in src_by_svc.values() if name in n)
    r.add(OK, sec, "evidence by source — " + ", ".join(
        f"{name}:{frac(name)}" for name in sorted(KNOWN_SOURCES) if frac(name)))

    unknown_only = [sid for sid, names in src_by_svc.items()
                    if names and not (names & KNOWN_SOURCES)]
    r.add(WARN if unknown_only else OK, sec,
          f"services whose evidence is only from unregistered sources: {len(unknown_only)}")

    manual_only = [sid for sid, names in src_by_svc.items() if names == {"manual_import"}]
    r.add(OK, sec, f"services seeded by manual import and not yet corroborated by a scanner: {len(manual_only)}")


def check_status_coherence(db, r):
    sec = "status coherence"
    services = list(db.scalars(select(Service)))
    gone_live = [s.id for s in services
                 if s.exposure_state == ExposureState.gone
                 and s.lifecycle_status in (LifecycleStatus.new, LifecycleStatus.approved,
                                            LifecycleStatus.in_production)]
    r.add(WARN if gone_live else OK, sec,
          f"exposure=gone but lifecycle still active (should be obsolete): {len(gone_live)}")

    removed_exposed = [s.id for s in services
                       if s.lifecycle_status == LifecycleStatus.removed
                       and s.exposure_state == ExposureState.exposed]
    r.add(WARN if removed_exposed else OK, sec,
          f"lifecycle=removed but exposure=exposed: {len(removed_exposed)}")

    exposed_no_ts = [s.id for s in services
                     if s.exposure_state == ExposureState.exposed and s.last_present_at is None]
    r.add(WARN if exposed_no_ts else OK, sec,
          f"exposed services with no last_present_at: {len(exposed_no_ts)}")


def check_drift(db, r):
    sec = "confidence / exposure drift (vs engine)"
    now = utcnow()
    T = settings.confirm_threshold
    score_drift, exposure_drift = [], []
    for s in db.scalars(select(Service)):
        res = compute_score(_evidence_for(db, s), now)
        if res.score != s.confidence_score:
            score_drift.append((s.id, s.confidence_score, res.score))
        cls = classify(res, T)
        # what exposure the engine would consider consistent
        if cls == "confirmed" and s.exposure_state in (ExposureState.not_observed, ExposureState.gone):
            exposure_drift.append((s.id, s.exposure_state.value, "confirmed"))
        if cls == "absent" and s.exposure_state == ExposureState.exposed:
            exposure_drift.append((s.id, s.exposure_state.value, "absent"))
    r.add(WARN if score_drift else OK, sec,
          f"services whose stored score != recomputed score: {len(score_drift)}" +
          (f" e.g. {score_drift[:5]}" if score_drift else "") +
          (" — is the scheduler/reconcile running?" if score_drift else ""))
    r.add(WARN if exposure_drift else OK, sec,
          f"services whose exposure contradicts current evidence: {len(exposure_drift)}" +
          (f" e.g. {exposure_drift[:5]}" if exposure_drift else ""))


def check_attribution_and_ou(db, r):
    sec = "attribution & OU assignment"
    seeds = list(db.scalars(select(OwnershipSeed)))
    hosts = {h.id: h for h in db.scalars(select(Host))}
    owned_offbook, cand_inbook = [], []
    for s in db.scalars(select(Service)):
        h = hosts.get(s.host_id)
        if not h:
            continue
        verdict = attribute(h.ip, h.asn, None, seeds)
        ev_names = {e.source_name for e in _evidence_for(db, s)}
        if s.attribution == Attribution.owned and verdict == Attribution.candidate \
                and "manual_import" not in ev_names:
            owned_offbook.append(s.id)
        if s.attribution == Attribution.candidate and verdict == Attribution.owned:
            cand_inbook.append(s.id)
    r.add(WARN if owned_offbook else OK, sec,
          f"owned services whose IP/ASN is not in any seed (excl. manual imports): {len(owned_offbook)}")
    r.add(WARN if cand_inbook else OK, sec,
          f"candidate services that ARE in owned space (should be owned): {len(cand_inbook)}")

    owned_no_ou = _n(db, Service, Service.attribution == Attribution.owned,
                     Service.org_unit_id.is_(None))
    r.add(WARN if owned_no_ou else OK, sec,
          f"owned services with no OU assigned (manual assignment pending): {owned_no_ou}")


def check_dns(db, r):
    sec = "dns names"
    nothing_behind = _n(db, DnsName, DnsName.resolves_to_host_id.is_(None))
    r.add(OK, sec, f"dns names with nothing behind them: {nothing_behind}")
    linked = _n(db, DnsName, DnsName.resolves_to_host_id.is_not(None))
    r.add(OK, sec, f"dns names resolving to a host: {linked}")


def check_scheduling_readiness(db, r):
    sec = "scheduling & alerting readiness"
    enabled_sources = list(db.scalars(select(Source).where(Source.enabled.is_(True))))
    r.add(FAIL if not enabled_sources else OK, sec,
          f"enabled sources: {[s.name for s in enabled_sources]}")

    all_names = set(db.scalars(select(Source.name)))
    missing = {"tenable", "shadowserver", "shodan", "dnsdumpster", "nmap_probe"} - all_names
    r.add(WARN if missing else OK, sec, f"core sources missing from registry: {sorted(missing) or 'none'}")

    manual_src = db.scalar(select(Source).where(Source.name == "manual_import"))
    manual_obs = _n(db, Observation, Observation.source_id == manual_src.id) if manual_src else 0
    r.add(OK, sec, f"manual_import evidence rows: {manual_obs}")

    channels = list(db.scalars(select(AlertChannel).where(AlertChannel.enabled.is_(True))))
    r.add(WARN if not channels else OK, sec, f"enabled alert channels: {len(channels)}")
    rules = list(db.scalars(select(AlertRule)))
    have_types = {ru.event_type for ru in rules}
    for et in (ExposureEventType.appeared, ExposureEventType.disappeared):
        r.add(WARN if et not in have_types else OK, sec, f"alert rule for '{et.value}': "
              f"{'present' if et in have_types else 'MISSING'}")
    ch_ids = set(db.scalars(select(AlertChannel.id)))
    dangling = [ru.id for ru in rules if ru.channel_id not in ch_ids]
    r.add(FAIL if dangling else OK, sec, f"alert rules referencing missing channel: {len(dangling)}")

    snaps = _n(db, SnapshotMetric)
    r.add(WARN if snaps == 0 else OK, sec,
          f"snapshot metrics rows: {snaps}" + (" — trends empty until first snapshot" if snaps == 0 else ""))

    r.add(OK, sec, f"scheduler cadence(s): full_cycle={settings.scheduler_full_cycle_seconds}, "
          f"snapshot={settings.scheduler_snapshot_seconds}, purge={settings.scheduler_purge_seconds}")


def check_rbac(db, r):
    sec = "auth / RBAC"
    for name in (RoleName.admin, RoleName.analyst, RoleName.manager):
        exists = db.scalar(select(Role).where(Role.name == name)) is not None
        r.add(FAIL if not exists else OK, sec, f"role '{name.value}': {'present' if exists else 'MISSING'}")
    admins = _n(db, User, User.enabled.is_(True),
                User.role_id.in_(select(Role.id).where(Role.name == RoleName.admin)))
    r.add(FAIL if admins == 0 else OK, sec, f"enabled admin users: {admins}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict", action="store_true", help="exit non-zero on warnings too")
    args = ap.parse_args()

    r = Report()
    print(f"auditing {settings.database_url}")
    with SessionLocal() as db:
        for fn in (check_referential, check_provenance, check_status_coherence, check_drift,
                   check_attribution_and_ou, check_dns, check_scheduling_readiness, check_rbac):
            try:
                fn(db, r)
            except Exception as exc:  # noqa: BLE001
                r.add(FAIL, fn.__name__, f"check crashed: {exc!r}")
    r.dump()
    c = r.counts()
    return 1 if (c[FAIL] or (args.strict and c[WARN])) else 0


if __name__ == "__main__":
    sys.exit(main())

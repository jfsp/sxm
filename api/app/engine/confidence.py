"""Weighted confidence model (design doc section 6).

Pure functions: no DB, fully unit-testable. The DB wrapper in pipeline.py
builds ``Evidence`` items from the latest observation per source.

Scoring rule
------------
For each source that has observed a service, take its *most recent* observation.
If that observation asserts the service is present AND it is still fresh
(observed within the source's staleness window), the source's weight counts
toward the score. The score is the sum of counting weights.

Freshness models real-world disappearance: when Tenable stops seeing a service,
its weight drops out once the weekly export ages past the staleness window,
pulling the score below T (C10/C14).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


def ensure_aware(dt: datetime) -> datetime:
    """Treat naive timestamps (e.g. from sqlite) as UTC so comparisons never mix
    naive/aware. Postgres TIMESTAMPTZ columns are already aware."""
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


@dataclass(frozen=True)
class Evidence:
    source_id: int
    source_name: str
    weight: int
    asserts_present: bool
    observed_at: datetime
    staleness_days: int


@dataclass(frozen=True)
class ScoreResult:
    score: int
    contributing: list[str]           # source names that counted toward the score
    present_sources: list[str]        # fresh sources asserting present
    tenable_present: bool
    external_present: bool            # any non-Tenable, non-probe source present
    coverage_gap: bool                # externals present but Tenable missed it


def _latest_per_source(evidence: list[Evidence]) -> dict[int, Evidence]:
    latest: dict[int, Evidence] = {}
    for e in evidence:
        cur = latest.get(e.source_id)
        if cur is None or ensure_aware(e.observed_at) > ensure_aware(cur.observed_at):
            latest[e.source_id] = e
    return latest


def compute_score(evidence: list[Evidence], now: datetime) -> ScoreResult:
    latest = _latest_per_source(evidence)
    score = 0
    contributing: list[str] = []
    present: list[str] = []
    tenable_present = False
    external_present = False

    now = ensure_aware(now)
    for e in latest.values():
        fresh = ensure_aware(e.observed_at) >= now - timedelta(days=e.staleness_days)
        if e.asserts_present and fresh:
            score += e.weight
            contributing.append(e.source_name)
            present.append(e.source_name)
            name = e.source_name.lower()
            if name == "tenable":
                tenable_present = True
            elif name != "nmap_probe":
                external_present = True

    coverage_gap = external_present and not tenable_present
    return ScoreResult(
        score=score,
        contributing=sorted(contributing),
        present_sources=sorted(present),
        tenable_present=tenable_present,
        external_present=external_present,
        coverage_gap=coverage_gap,
    )


def classify(result: ScoreResult, threshold: int) -> str:
    """Return 'confirmed' | 'doubt' | 'absent'."""
    if result.score >= threshold:
        return "confirmed"
    if result.score > 0:
        return "doubt"
    return "absent"

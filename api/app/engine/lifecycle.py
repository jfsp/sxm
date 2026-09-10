"""Exposure and lifecycle state machines (design doc section 7).

Pure decision functions. They return the *next* state plus any exposure event
that the transition should emit. pipeline.py applies these to ORM rows and
persists history/events.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from ..models import ExposureState, LifecycleStatus, ExposureEventType


@dataclass(frozen=True)
class ExposureDecision:
    state: ExposureState
    event: ExposureEventType | None  # emitted only on appear/disappear transitions


def decide_exposure(
    current: ExposureState,
    score: int,
    threshold: int,
    days_since_present: float | None,
    gone_after_days: int,
    probe_confirms_absent: bool = False,
) -> ExposureDecision:
    """Drive the exposure state machine.

        first_seen --confirmed--> exposed
        exposed --score<T--> not_observed
        not_observed --re-confirmed--> exposed
        not_observed --absent>=N days OR probe--> gone
        gone --re-confirmed--> exposed
    """
    confirmed = score >= threshold

    # Re-confirmation from any non-exposed state -> exposed (+appeared if it had gone away)
    if confirmed:
        if current in (ExposureState.first_seen,):
            return ExposureDecision(ExposureState.exposed, ExposureEventType.appeared)
        if current in (ExposureState.not_observed, ExposureState.gone):
            # reappearance after having been considered gone counts as an appear
            event = ExposureEventType.appeared if current == ExposureState.gone else None
            return ExposureDecision(ExposureState.exposed, event)
        return ExposureDecision(ExposureState.exposed, None)

    # Not confirmed
    if current == ExposureState.exposed:
        return ExposureDecision(ExposureState.not_observed, None)

    if current == ExposureState.not_observed:
        aged_out = days_since_present is not None and days_since_present >= gone_after_days
        if probe_confirms_absent or aged_out:
            return ExposureDecision(ExposureState.gone, ExposureEventType.disappeared)
        return ExposureDecision(ExposureState.not_observed, None)

    if current == ExposureState.first_seen:
        # discovered but never confirmed; probe can bury it immediately
        if probe_confirms_absent:
            return ExposureDecision(ExposureState.gone, None)
        return ExposureDecision(ExposureState.first_seen, None)

    # already gone and still not confirmed
    return ExposureDecision(ExposureState.gone, None)


def auto_obsolete_transition(
    lifecycle: LifecycleStatus, exposure: ExposureState
) -> LifecycleStatus | None:
    """Governance side-effect: exposure=gone auto-obsoletes live lifecycle states.

    Returns the new lifecycle status if an automatic transition applies, else None.
    Manual-only transitions (new->approved, obsolete->removed, ...) are not here.
    """
    if exposure == ExposureState.gone and lifecycle in (
        LifecycleStatus.new,
        LifecycleStatus.approved,
        LifecycleStatus.in_production,
    ):
        return LifecycleStatus.obsolete
    return None


# Allowed manual lifecycle transitions (enforced by the API layer).
MANUAL_LIFECYCLE_TRANSITIONS: dict[LifecycleStatus, set[LifecycleStatus]] = {
    LifecycleStatus.new: {LifecycleStatus.approved, LifecycleStatus.obsolete},
    LifecycleStatus.approved: {LifecycleStatus.in_production, LifecycleStatus.obsolete},
    LifecycleStatus.in_production: {LifecycleStatus.obsolete},
    LifecycleStatus.obsolete: {LifecycleStatus.in_production, LifecycleStatus.removed},
    LifecycleStatus.removed: set(),
}


def is_manual_transition_allowed(src: LifecycleStatus, dst: LifecycleStatus) -> bool:
    return dst in MANUAL_LIFECYCLE_TRANSITIONS.get(src, set())

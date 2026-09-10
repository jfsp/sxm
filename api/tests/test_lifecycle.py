from app.engine.lifecycle import (
    decide_exposure, auto_obsolete_transition, is_manual_transition_allowed,
)
from app.models import ExposureState as E, LifecycleStatus as L, ExposureEventType as EV

T = 7
GONE = 14


def test_first_confirmation_appears():
    d = decide_exposure(E.first_seen, 7, T, None, GONE)
    assert d.state == E.exposed and d.event == EV.appeared


def test_drop_below_threshold_goes_not_observed_no_event():
    d = decide_exposure(E.exposed, 5, T, 1, GONE)
    assert d.state == E.not_observed and d.event is None


def test_absent_two_weeks_disappears():
    d = decide_exposure(E.not_observed, 0, T, 14, GONE)
    assert d.state == E.gone and d.event == EV.disappeared


def test_not_yet_two_weeks_stays_not_observed():
    d = decide_exposure(E.not_observed, 0, T, 6, GONE)
    assert d.state == E.not_observed and d.event is None


def test_probe_confirms_absent_immediately():
    d = decide_exposure(E.not_observed, 0, T, 1, GONE, probe_confirms_absent=True)
    assert d.state == E.gone and d.event == EV.disappeared


def test_reappear_after_gone_emits_appeared():
    d = decide_exposure(E.gone, 8, T, None, GONE)
    assert d.state == E.exposed and d.event == EV.appeared


def test_reconfirm_from_not_observed_no_duplicate_appear():
    d = decide_exposure(E.not_observed, 8, T, 1, GONE)
    assert d.state == E.exposed and d.event is None


def test_auto_obsolete_on_gone():
    assert auto_obsolete_transition(L.in_production, E.gone) == L.obsolete
    assert auto_obsolete_transition(L.new, E.gone) == L.obsolete
    assert auto_obsolete_transition(L.obsolete, E.gone) is None
    assert auto_obsolete_transition(L.in_production, E.exposed) is None


def test_manual_transition_matrix():
    assert is_manual_transition_allowed(L.new, L.approved)
    assert is_manual_transition_allowed(L.approved, L.in_production)
    assert is_manual_transition_allowed(L.obsolete, L.removed)
    assert not is_manual_transition_allowed(L.new, L.in_production)
    assert not is_manual_transition_allowed(L.removed, L.approved)

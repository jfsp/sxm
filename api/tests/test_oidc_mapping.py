from app.oidc import map_claims_to_role
from app.models import RoleName

MAP = {"soc-admins": "admin", "soc-analysts": "analyst", "viewers": "manager"}


def test_highest_privilege_wins():
    claims = {"groups": ["viewers", "soc-analysts", "soc-admins"]}
    assert map_claims_to_role(claims, "groups", MAP, "manager") == RoleName.admin


def test_single_string_claim():
    assert map_claims_to_role({"groups": "soc-analysts"}, "groups", MAP, "manager") == RoleName.analyst


def test_default_when_no_match():
    assert map_claims_to_role({"groups": ["unknown"]}, "groups", MAP, "manager") == RoleName.manager


def test_default_when_claim_missing():
    assert map_claims_to_role({}, "groups", MAP, "analyst") == RoleName.analyst

"""OIDC seam (C6). Local accounts remain primary; this drops in an IdP
(Keycloak/Azure AD/Okta/Google) via standard discovery + Authorization Code flow.

Pure helpers (role mapping) are unit-tested; network bits use httpx/pyjwt.
"""
from __future__ import annotations

import json
import time

import httpx
import jwt
from jwt import PyJWKClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .models import User, Role, RoleName
from .security import create_access_token

settings = get_settings()

_ROLE_PRIORITY = {RoleName.admin: 3, RoleName.analyst: 2, RoleName.manager: 1}
_disc_cache: dict[str, tuple[float, dict]] = {}


def role_map() -> dict[str, str]:
    if not settings.oidc_role_map:
        return {}
    try:
        return json.loads(settings.oidc_role_map)
    except json.JSONDecodeError:
        return {}


def map_claims_to_role(claims: dict, role_claim: str, mapping: dict[str, str],
                       default: str) -> RoleName:
    """Pure: choose the highest-privilege role among the user's mapped claim values."""
    values = claims.get(role_claim, [])
    if isinstance(values, str):
        values = [values]
    best: RoleName | None = None
    for v in values:
        name = mapping.get(v)
        if not name:
            continue
        try:
            candidate = RoleName(name)
        except ValueError:
            continue
        if best is None or _ROLE_PRIORITY[candidate] > _ROLE_PRIORITY[best]:
            best = candidate
    if best is not None:
        return best
    return RoleName(default)


def discovery() -> dict:
    key = settings.oidc_issuer
    now = time.time()
    if key in _disc_cache and _disc_cache[key][0] > now:
        return _disc_cache[key][1]
    url = settings.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration"
    doc = httpx.get(url, timeout=15).raise_for_status().json()
    _disc_cache[key] = (now + 3600, doc)
    return doc


def authorization_url(state: str) -> str:
    doc = discovery()
    from urllib.parse import urlencode
    params = {
        "response_type": "code",
        "client_id": settings.oidc_client_id,
        "redirect_uri": settings.oidc_redirect_uri,
        "scope": settings.oidc_scopes,
        "state": state,
    }
    return doc["authorization_endpoint"] + "?" + urlencode(params)


def exchange_code(code: str) -> dict:
    doc = discovery()
    resp = httpx.post(doc["token_endpoint"], data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.oidc_redirect_uri,
        "client_id": settings.oidc_client_id,
        "client_secret": settings.oidc_client_secret,
    }, timeout=15)
    resp.raise_for_status()
    return resp.json()


def validate_id_token(id_token: str) -> dict:
    doc = discovery()
    signing_key = PyJWKClient(doc["jwks_uri"]).get_signing_key_from_jwt(id_token)
    return jwt.decode(
        id_token, signing_key.key, algorithms=["RS256"],
        audience=settings.oidc_client_id, issuer=doc.get("issuer", settings.oidc_issuer),
    )


def provision_user(db: Session, claims: dict) -> User:
    sub = claims["sub"]
    username = claims.get("preferred_username") or claims.get("email") or sub
    email = claims.get("email")
    role_name = map_claims_to_role(claims, settings.oidc_role_claim, role_map(),
                                   settings.oidc_default_role)
    role = db.scalar(select(Role).where(Role.name == role_name))
    user = db.scalar(select(User).where(User.oidc_sub == sub))
    if user is None:
        # link by username if a local account already exists, else create
        user = db.scalar(select(User).where(User.username == username))
        if user is None:
            user = User(username=username, oidc_sub=sub, email=email, role_id=role.id)
            db.add(user)
        else:
            user.oidc_sub = sub
    user.email = email or user.email
    user.role_id = role.id            # IdP is source of truth for role each login
    db.commit()
    db.refresh(user)
    return user


def issue_local_jwt(user: User) -> str:
    return create_access_token(sub=user.username, role=user.role.name.value, uid=user.id)

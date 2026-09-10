"""OIDC login/callback routes. Active only when SXM_OIDC_ENABLED=true."""
from __future__ import annotations

import secrets
import time

import jwt
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from .. import oidc

router = APIRouter(prefix="/api/auth/oidc", tags=["auth"])
settings = get_settings()


def _sign_state() -> str:
    return jwt.encode({"n": secrets.token_urlsafe(8), "exp": int(time.time()) + 300},
                      settings.secret_key, algorithm="HS256")


def _verify_state(state: str) -> None:
    try:
        jwt.decode(state, settings.secret_key, algorithms=["HS256"])
    except Exception:
        raise HTTPException(400, "invalid or expired state")


def _require_enabled():
    if not settings.oidc_enabled:
        raise HTTPException(404, "OIDC disabled")


@router.get("/login")
def login(_: None = Depends(_require_enabled)):
    return RedirectResponse(oidc.authorization_url(_sign_state()))


@router.get("/callback")
def callback(code: str, state: str, db: Session = Depends(get_db),
             _: None = Depends(_require_enabled)):
    _verify_state(state)
    tokens = oidc.exchange_code(code)
    claims = oidc.validate_id_token(tokens["id_token"])
    user = oidc.provision_user(db, claims)
    if not user.enabled:
        raise HTTPException(403, "user disabled")
    local = oidc.issue_local_jwt(user)
    # hand the SPA its token via URL fragment (not sent to server, not logged)
    return RedirectResponse(f"/#access_token={local}&role={user.role.name.value}")

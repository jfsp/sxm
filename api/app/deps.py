from __future__ import annotations

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from .db import get_db
from .models import User, RoleName
from .security import decode_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> User:
    cred_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_token(token)
        uid = int(payload["uid"])
    except Exception:
        raise cred_exc
    user = db.get(User, uid)
    if user is None or not user.enabled:
        raise cred_exc
    return user


def require_roles(*roles: RoleName):
    allowed = {r.value for r in roles}

    def guard(user: User = Depends(get_current_user)) -> User:
        if user.role.name.value not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {sorted(allowed)}",
            )
        return user

    return guard


# Convenience guards
require_admin = require_roles(RoleName.admin)
require_analyst = require_roles(RoleName.admin, RoleName.analyst)  # analyst or admin
require_viewer = require_roles(RoleName.admin, RoleName.analyst, RoleName.manager)

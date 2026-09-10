from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import get_current_user
from ..models import User
from ..schemas import Token, UserOut
from ..security import verify_password, create_access_token

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/token", response_model=Token)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == form.username))
    if (not user or not user.enabled or not user.password_hash
            or not verify_password(form.password, user.password_hash)):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bad credentials")
    role = user.role.name.value
    token = create_access_token(sub=user.username, role=role, uid=user.id)
    return Token(access_token=token, role=role)


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_admin
from ..models import User, Role, RoleName
from ..schemas import UserCreate, UserUpdate, UserAdminOut
from ..security import hash_password
from ..audit import record

router = APIRouter(prefix="/api/admin/users", tags=["users"])


def _role(db: Session, name: str) -> Role:
    try:
        rn = RoleName(name)
    except ValueError:
        raise HTTPException(422, f"invalid role '{name}'")
    return db.scalar(select(Role).where(Role.name == rn))


@router.get("", response_model=list[UserAdminOut])
def list_users(db: Session = Depends(get_db), _: User = Depends(require_admin)):
    return list(db.scalars(select(User)))


@router.post("", response_model=UserAdminOut)
def create_user(body: UserCreate, db: Session = Depends(get_db),
                actor: User = Depends(require_admin)):
    if db.scalar(select(User).where(User.username == body.username)):
        raise HTTPException(409, "username exists")
    u = User(username=body.username, password_hash=hash_password(body.password),
             role_id=_role(db, body.role).id)
    db.add(u)
    db.flush()
    record(db, actor, "create_user", f"user:{u.id}", after={"username": u.username, "role": body.role})
    db.commit()
    db.refresh(u)
    return u


@router.patch("/{user_id}", response_model=UserAdminOut)
def update_user(user_id: int, body: UserUpdate, db: Session = Depends(get_db),
                actor: User = Depends(require_admin)):
    u = db.get(User, user_id)
    if not u:
        raise HTTPException(404, "user not found")
    before = {"role": u.role.name.value, "enabled": u.enabled}
    if body.role is not None:
        u.role_id = _role(db, body.role).id
    if body.enabled is not None:
        u.enabled = body.enabled
    if body.password is not None:
        u.password_hash = hash_password(body.password)
    record(db, actor, "update_user", f"user:{u.id}", before=before,
           after={"role": body.role, "enabled": body.enabled})
    db.commit()
    db.refresh(u)
    return u

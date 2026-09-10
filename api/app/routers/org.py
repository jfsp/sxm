from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_admin, require_viewer
from ..models import OrgUnit, OwnershipSeed, User
from ..schemas import OrgUnitIn, OrgUnitOut, SeedIn, SeedOut
from ..audit import record

router = APIRouter(prefix="/api", tags=["org"])


@router.get("/org-units", response_model=list[OrgUnitOut])
def list_org_units(db: Session = Depends(get_db), _: User = Depends(require_viewer)):
    return list(db.scalars(select(OrgUnit)))


@router.post("/org-units", response_model=OrgUnitOut)
def create_org_unit(body: OrgUnitIn, db: Session = Depends(get_db),
                    user: User = Depends(require_admin)):
    ou = OrgUnit(name=body.name, parent_id=body.parent_id)
    db.add(ou)
    db.flush()
    record(db, user, "create_org_unit", f"org_unit:{ou.id}", after={"name": ou.name})
    db.commit()
    return ou


@router.get("/seeds", response_model=list[SeedOut])
def list_seeds(db: Session = Depends(get_db), _: User = Depends(require_viewer)):
    return list(db.scalars(select(OwnershipSeed)))


@router.post("/seeds", response_model=SeedOut)
def create_seed(body: SeedIn, db: Session = Depends(get_db),
                user: User = Depends(require_admin)):
    seed = OwnershipSeed(type=body.type, value=body.value, org_unit_id=body.org_unit_id)
    db.add(seed)
    db.flush()
    record(db, user, "create_seed", f"seed:{seed.id}", after={"value": seed.value})
    db.commit()
    return seed

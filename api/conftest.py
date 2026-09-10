import os
import sys

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.dirname(__file__))


@pytest.fixture()
def db(monkeypatch):
    """In-memory sqlite bound + bootstrapped app session factory."""
    import app.db as dbmod
    import app.seed_data as seed

    eng = create_engine("sqlite+pysqlite:///:memory:", future=True)
    TestSession = sessionmaker(bind=eng, future=True)
    monkeypatch.setattr(dbmod, "engine", eng)
    monkeypatch.setattr(dbmod, "SessionLocal", TestSession)
    monkeypatch.setattr(seed, "engine", eng)
    monkeypatch.setattr(seed, "SessionLocal", TestSession)

    seed.Base.metadata.create_all(bind=eng)
    with TestSession() as s:
        roles = seed.seed_roles(s)
        seed.ensure_admin(s, roles)
        seed.seed_sources(s)
        seed.seed_ownership(s)
        seed.seed_default_alerts(s)
        s.commit()
    yield TestSession

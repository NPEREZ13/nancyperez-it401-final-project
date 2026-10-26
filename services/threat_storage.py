"""Save identical threat submissions once per owner, including concurrent requests."""

import hashlib
from contextlib import contextmanager

from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from models import UserThreat, db
from services.records import owned_query


@contextmanager
def owner_write_lock(owner):
    if db.engine.dialect.name != "mysql":
        yield
        return
    name = "threat-save:" + hashlib.sha256(owner.encode()).hexdigest()[:48]
    # Hold a dedicated connection so commit cannot return the lock to the pool.
    with db.engine.connect() as connection:
        acquired = connection.scalar(text("SELECT GET_LOCK(:name, 10)"), {"name": name}) == 1
        connection.commit()
        if not acquired:
            raise OperationalError("Threat save lock unavailable", None, None)
        try:
            yield
        finally:
            connection.execute(text("SELECT RELEASE_LOCK(:name)"), {"name": name})
            connection.commit()


def create_threat_once(owner, values):
    with owner_write_lock(owner):
        candidates = db.session.scalars(owned_query(UserThreat, owner).where(
            UserThreat.name == values["name"]
        ).order_by(UserThreat.id)).all()
        # Compare full text exactly, independent of MySQL's case-insensitive collation.
        for record in candidates:
            if all(getattr(record, field) == value for field, value in values.items()):
                return record, False
        record = UserThreat(owner_sub=owner, **values)
        db.session.add(record)
        db.session.commit()
        return record, True

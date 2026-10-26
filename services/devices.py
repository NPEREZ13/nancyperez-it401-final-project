"""SQLAlchemy persistence for the restored profile device features."""

from datetime import datetime, timezone

from models import ProfileDevice, db
from services.records import owned_query


def list_devices(owner):
    return [row.to_dict() for row in db.session.scalars(
        owned_query(ProfileDevice, owner).order_by(ProfileDevice.id.desc())
    )]


def get_device(owner, device_id):
    row = db.session.scalar(owned_query(ProfileDevice, owner).where(ProfileDevice.id == device_id))
    return row.to_dict() if row else None


def create_device(owner, name, ip):
    db.session.add(ProfileDevice(owner_sub=owner, name=name, ip_address=ip))
    db.session.commit()


def update_device(owner, device_id, name, ip):
    # MySQL evaluates assignments left to right: compare the old IP before changing it.
    db.session.execute(db.update(ProfileDevice).where(
        ProfileDevice.owner_sub == owner, ProfileDevice.id == device_id
    ).ordered_values(
        (ProfileDevice.result_json, db.case((ProfileDevice.ip_address == ip, ProfileDevice.result_json), else_=None)),
        (ProfileDevice.checked_at, db.case((ProfileDevice.ip_address == ip, ProfileDevice.checked_at), else_=None)),
        (ProfileDevice.name, name), (ProfileDevice.ip_address, ip),
    ))
    db.session.commit()


def delete_device(owner, device_id):
    db.session.execute(db.delete(ProfileDevice).where(
        ProfileDevice.owner_sub == owner, ProfileDevice.id == device_id
    ))
    db.session.commit()


def save_result(owner, device_id, ip, result):
    updated = db.session.execute(db.update(ProfileDevice).where(
        ProfileDevice.owner_sub == owner, ProfileDevice.id == device_id,
        ProfileDevice.ip_address == ip,
    ).values(result_json=result, checked_at=datetime.now(timezone.utc).replace(tzinfo=None)))
    db.session.commit()
    return updated.rowcount == 1

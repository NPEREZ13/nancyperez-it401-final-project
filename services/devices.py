"""Owner-scoped device persistence. Schema is installed with flask init-devices."""
import json

from database import get_db


def list_devices(owner):
    with get_db().cursor() as cursor:
        cursor.execute("SELECT * FROM profile_devices WHERE owner_sub=%s ORDER BY id DESC", (owner,))
        return cursor.fetchall()


def get_device(owner, device_id):
    with get_db().cursor() as cursor:
        cursor.execute("SELECT * FROM profile_devices WHERE owner_sub=%s AND id=%s", (owner, device_id))
        return cursor.fetchone()


def write(query, args):
    db = get_db()
    try:
        with db.cursor() as cursor:
            cursor.execute(query, args)
        db.commit()
    except Exception:
        db.rollback()
        raise


def create_device(owner, name, ip):
    write("INSERT INTO profile_devices (owner_sub, name, ip_address) VALUES (%s, %s, %s)", (owner, name, ip))


def update_device(owner, device_id, name, ip):
    # Clear results whenever the address changes; a score belongs to one IP.
    write("""UPDATE profile_devices SET
        result_json=IF(ip_address=%s, result_json, NULL),
        checked_at=IF(ip_address=%s, checked_at, NULL),
        name=%s, ip_address=%s WHERE owner_sub=%s AND id=%s""",
        (ip, ip, name, ip, owner, device_id))


def delete_device(owner, device_id):
    write("DELETE FROM profile_devices WHERE owner_sub=%s AND id=%s", (owner, device_id))


def save_result(owner, device_id, ip, result):
    # Do not attach an in-flight lookup to an address edited in another tab.
    write("""UPDATE profile_devices SET result_json=%s, checked_at=UTC_TIMESTAMP()
        WHERE owner_sub=%s AND id=%s AND ip_address=%s""",
        (json.dumps(result), owner, device_id, ip))

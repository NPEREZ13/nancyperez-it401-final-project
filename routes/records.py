"""JSON CRUD API. Identity comes exclusively from the verified login session."""

from flask import Blueprint, abort, request
from werkzeug.exceptions import HTTPException

from models import ProfileDevice, UserThreat, db
from services.records import current_owner, owned_query, validate_record
from services.threat_storage import create_threat_once

records = Blueprint("records", __name__, url_prefix="/api")
MODELS = {"threats": UserThreat, "devices": ProfileDevice}


@records.before_request
def require_identity():
    if not current_owner():
        return {"error": "Authentication required."}, 401
    # Mutations require JSON; ordinary cross-site forms cannot send this type.
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if not request.is_json:
            return {"error": "Content-Type must be application/json."}, 415
        if request.headers.get("Sec-Fetch-Site") == "cross-site":
            return {"error": "Cross-site writes are not allowed."}, 403


@records.errorhandler(404)
def not_found(error):
    return {"error": "Record not found."}, 404


@records.errorhandler(HTTPException)
def invalid_request(error):
    return {"error": error.description}, error.code


def model_for(kind):
    if kind not in MODELS:
        abort(404)
    return MODELS[kind]


def find_record(kind, record_id):
    model = model_for(kind)
    record = db.session.scalar(owned_query(model, current_owner()).where(model.id == record_id))
    if record is None:
        abort(404)
    return record


@records.route("/<kind>", methods=["GET", "POST"])
def collection(kind):
    model = model_for(kind)
    if request.method == "GET":
        rows = db.session.scalars(owned_query(model, current_owner()).order_by(model.id)).all()
        return {"items": [row.to_dict() for row in rows]}
    try:
        values = validate_record(kind, request.get_json())
    except ValueError as error:
        return {"error": str(error)}, 400
    if kind == "threats":
        record, created = create_threat_once(current_owner(), values)
        return record.to_dict(), 201 if created else 200
    record = model(owner_sub=current_owner(), **values)
    db.session.add(record)
    db.session.commit()
    return record.to_dict(), 201


@records.route("/<kind>/<int:record_id>", methods=["GET", "PUT", "PATCH", "DELETE"])
def item(kind, record_id):
    record = find_record(kind, record_id)
    if request.method == "GET":
        return record.to_dict()
    if request.method == "DELETE":
        db.session.delete(record)
        db.session.commit()
        return "", 204
    try:
        values = validate_record(kind, request.get_json(), partial=request.method == "PATCH")
    except ValueError as error:
        return {"error": str(error)}, 400
    for key, value in values.items():
        setattr(record, key, value)
    db.session.commit()
    return record.to_dict()

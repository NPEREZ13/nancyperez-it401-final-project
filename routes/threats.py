"""Restored Google-account threat management, backed by SQLAlchemy."""

import secrets

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, session, url_for
from sqlalchemy.exc import SQLAlchemyError

from models import UserThreat, db
from services.mitigation import selected_mitigation
from services.threat_names import selected_threat_name
from services.categories import selected_category
from services.threat_storage import create_threat_once
from services.records import account_owner, owned_query, validate_record

threats = Blueprint("threats", __name__)


@threats.before_request
def protect():
    if not account_owner():
        return redirect(url_for("auth.login"))
    session.setdefault("records_csrf", secrets.token_urlsafe(32))
    if request.method == "POST":
        token = request.form.get("csrf_token", "")
        if not token.isascii() or not secrets.compare_digest(session["records_csrf"], token):
            abort(400)


@threats.errorhandler(SQLAlchemyError)
def unavailable(error):
    db.session.rollback()
    current_app.logger.error("Account threat operation failed (%s)", type(error).__name__)
    return render_template("threat_records.html", records=[],
                           error="Threat records are temporarily unavailable. Please try again shortly.", unavailable=True), 503


def owned(record_id):
    record = db.session.scalar(owned_query(UserThreat, account_owner()).where(UserThreat.id == record_id))
    if record is None:
        abort(404)
    return record


@threats.route("/my-threats")
def index():
    records = db.session.scalars(owned_query(UserThreat, account_owner()).order_by(UserThreat.id.desc())).all()
    return render_template("threat_records.html", records=records)


@threats.route("/my-threats/new", methods=["GET", "POST"])
@threats.route("/my-threats/<int:record_id>/edit", methods=["GET", "POST"])
def edit(record_id=None):
    existing = owned(record_id) if record_id is not None else None
    record = existing.to_dict() if existing else {}
    error = None
    if request.method == "POST":
        record = {key: request.form.get(key, "") for key in (
            "name", "severity", "category", "description", "mitigation"
        )}
        try:
            record["name"] = selected_threat_name(request.form)
            record["category"] = selected_category(request.form)
            record["mitigation"] = selected_mitigation(request.form)
            values = validate_record("threats", record)
        except ValueError as validation_error:
            error = str(validation_error)
        else:
            if existing:
                for key, value in values.items():
                    setattr(existing, key, value)
                db.session.commit()
                created = True
            else:
                _, created = create_threat_once(account_owner(), values)
            flash("Threat record saved." if created else "This threat is already saved. No duplicate was added.")
            return redirect(url_for("threats.index"))
    return render_template("threat_form.html", record=record, editing=record_id is not None, error=error,
                           name_choice=request.form.get("name_choice") if request.method == "POST" else None,
                           category_choice=request.form.get("category_choice") if request.method == "POST" else None,
                           mitigation_choice=request.form.get("mitigation_choice") if request.method == "POST" else None), (400 if error else 200)


@threats.route("/my-threats/<int:record_id>/delete", methods=["POST"])
def delete(record_id):
    db.session.delete(owned(record_id))
    db.session.commit()
    flash("Threat record deleted.")
    return redirect(url_for("threats.index"))

"""Restored A3 Google profile and devices, using the existing SQLAlchemy models."""

import json
import secrets

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, session, url_for
from sqlalchemy.exc import SQLAlchemyError

from models import ProfileDevice, UserThreat, db
from services import devices
from services.ip_threat import IPThreatError, analyze_ip, normalize_ip
from services.records import account_owner, browser_owner, validate_record

profile = Blueprint("profile", __name__)


@profile.before_request
def require_login_and_csrf():
    if not account_owner():
        return redirect(url_for("auth.login"))
    session.setdefault("profile_csrf", secrets.token_urlsafe(32))
    if request.method == "POST":
        supplied = request.form.get("csrf_token", "")
        if not supplied.isascii() or not secrets.compare_digest(session["profile_csrf"], supplied):
            abort(400)


@profile.errorhandler(SQLAlchemyError)
def database_error(error):
    db.session.rollback()
    current_app.logger.error("Profile database operation failed (%s)", type(error).__name__)
    return render_template("profile.html", devices=[], selected=None, result=None,
                           error="Your saved devices are temporarily unavailable. Please try again shortly.",
                           database_unavailable=True), 503


def owned_device(device_id):
    device = devices.get_device(account_owner(), device_id)
    if device is None:
        abort(404)
    return device


@profile.route("/profile")
def index():
    records = devices.list_devices(account_owner())
    selected_id = request.args.get("device", type=int)
    selected = owned_device(selected_id) if selected_id is not None else (records[0] if records else None)
    result = selected["result_json"] if selected else None
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except ValueError:
            result = None
    if not isinstance(result, dict):
        result = None
    workspace = browser_owner()
    workspace_count = 0
    if workspace:
        for model in (UserThreat, ProfileDevice):
            workspace_count += db.session.scalar(db.select(db.func.count()).select_from(model).where(model.owner_sub == workspace))
    return render_template("profile.html", devices=records, selected=selected, result=result,
                           workspace_count=workspace_count)


@profile.route("/profile/devices", methods=["POST"])
def create():
    return save()


@profile.route("/profile/devices/<int:device_id>/edit", methods=["POST"])
def edit(device_id):
    owned_device(device_id)
    return save(device_id)


def save(device_id=None):
    try:
        values = validate_record("devices", {
            "name": request.form.get("name", ""),
            "ip_address": request.form.get("ip_address", ""),
        })
        ip = normalize_ip(values["ip_address"])
        if device_id is None:
            devices.create_device(account_owner(), values["name"], ip)
        else:
            devices.update_device(account_owner(), device_id, values["name"], ip)
        flash("Device saved.")
    except ValueError as error:
        flash(str(error))
    return redirect(url_for("profile.index", **({"device": device_id} if device_id else {})))


@profile.route("/profile/devices/<int:device_id>/delete", methods=["POST"])
def delete(device_id):
    owned_device(device_id)
    devices.delete_device(account_owner(), device_id)
    flash("Device deleted.")
    return redirect(url_for("profile.index"))


@profile.route("/profile/devices/<int:device_id>/check", methods=["POST"])
def check(device_id):
    device = owned_device(device_id)
    try:
        result = analyze_ip(device["ip_address"], current_app.config.get("APIFREAKS_API_KEY"))
        if devices.save_result(account_owner(), device_id, device["ip_address"], result):
            flash("IP threat status updated.")
        else:
            flash("The device changed during the lookup. Please check its current address again.")
    except (ValueError, IPThreatError) as error:
        flash(f"Status check failed: {error} Any displayed result is from the previous check.")
    return redirect(url_for("profile.index", device=device_id))


@profile.route("/profile/import-workspace", methods=["POST"])
def import_workspace():
    """Move only the workspace proven by this signed browser session."""
    workspace = browser_owner()
    if workspace:
        for model in (UserThreat, ProfileDevice):
            db.session.execute(db.update(model).where(model.owner_sub == workspace).values(owner_sub=account_owner()))
        db.session.commit()
        session.pop("workspace_owner_sub", None)
        flash("Your browser workspace records are now saved to your Google account.")
    return redirect(url_for("profile.index"))

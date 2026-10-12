import json
import secrets

import pymysql
from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, session, url_for

from services import devices
from services.ip_threat import IPThreatError, analyze_ip, normalize_ip

profile = Blueprint("profile", __name__)


@profile.before_request
def require_login_and_csrf():
    if not session.get("user"):
        return redirect(url_for("auth.login"))
    session.setdefault("profile_csrf", secrets.token_urlsafe(32))
    if request.method == "POST":
        if not secrets.compare_digest(session["profile_csrf"], request.form.get("csrf_token", "")):
            abort(400)


@profile.errorhandler(pymysql.MySQLError)
def database_error(error):
    return render_template("profile.html", devices=[], selected=None, result=None,
                           error="Your saved devices are temporarily unavailable. Please try again shortly.",
                           database_unavailable=True), 503


def owned_device(device_id):
    device = devices.get_device(session["user"]["sub"], device_id)
    if device is None:
        abort(404)
    return device


@profile.route("/profile")
def index():
    records = devices.list_devices(session["user"]["sub"])
    selected_id = request.args.get("device", type=int)
    selected = owned_device(selected_id) if selected_id is not None else (records[0] if records else None)
    result = json.loads(selected["result_json"]) if selected and selected["result_json"] else None
    return render_template("profile.html", devices=records, selected=selected, result=result)


@profile.route("/profile/devices", methods=["POST"])
def create():
    return save()


@profile.route("/profile/devices/<int:device_id>/edit", methods=["POST"])
def edit(device_id):
    owned_device(device_id)
    return save(device_id)


def save(device_id=None):
    try:
        name = request.form.get("name", "").strip()
        if not name or len(name) > 80:
            raise ValueError("Enter a device name between 1 and 80 characters.")
        ip = normalize_ip(request.form.get("ip_address", ""))
        owner = session["user"]["sub"]
        if device_id is None:
            devices.create_device(owner, name, ip)
        else:
            devices.update_device(owner, device_id, name, ip)
        flash("Device saved.")
    except ValueError as exc:
        flash(str(exc))
    return redirect(url_for("profile.index", **({"device": device_id} if device_id else {})))


@profile.route("/profile/devices/<int:device_id>/delete", methods=["POST"])
def delete(device_id):
    owned_device(device_id)
    devices.delete_device(session["user"]["sub"], device_id)
    flash("Device deleted.")
    return redirect(url_for("profile.index"))


@profile.route("/profile/devices/<int:device_id>/check", methods=["POST"])
def check(device_id):
    device = owned_device(device_id)
    try:
        result = analyze_ip(device["ip_address"], current_app.config.get("APIFREAKS_API_KEY"))
        devices.save_result(session["user"]["sub"], device_id, device["ip_address"], result)
        flash("IP threat status updated.")
    except (ValueError, IPThreatError) as exc:
        flash(f"Status check failed: {exc} Any displayed result is from the previous check.")
    return redirect(url_for("profile.index", device=device_id))

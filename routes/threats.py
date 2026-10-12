import secrets

import pymysql
from flask import Blueprint, abort, flash, redirect, render_template, request, session, url_for

from database import get_db
from services.devices import write

threats = Blueprint("threats", __name__)


@threats.before_request
def protect():
    if not session.get("user"):
        return redirect(url_for("auth.login"))
    session.setdefault("records_csrf", secrets.token_urlsafe(32))
    if request.method == "POST" and not secrets.compare_digest(
        session["records_csrf"], request.form.get("csrf_token", "")
    ):
        abort(400)


@threats.errorhandler(pymysql.MySQLError)
def unavailable(error):
    return render_template("threat_records.html", records=[], error="Threat records are temporarily unavailable. Please try again shortly.", unavailable=True), 503


def owned(record_id):
    with get_db().cursor() as cursor:
        cursor.execute("SELECT * FROM user_threats WHERE owner_sub=%s AND id=%s", (session["user"]["sub"], record_id))
        record = cursor.fetchone()
    if record is None:
        abort(404)
    return record


@threats.route("/my-threats")
def index():
    with get_db().cursor() as cursor:
        cursor.execute("SELECT * FROM user_threats WHERE owner_sub=%s ORDER BY id DESC", (session["user"]["sub"],))
        records = cursor.fetchall()
    return render_template("threat_records.html", records=records)


@threats.route("/my-threats/new", methods=["GET", "POST"])
@threats.route("/my-threats/<int:record_id>/edit", methods=["GET", "POST"])
def edit(record_id=None):
    record = owned(record_id) if record_id is not None else {}
    error = None
    if request.method == "POST":
        record = {field: request.form.get(field, "").strip() for field in ("name", "severity", "category", "description", "mitigation")}
        if not all(record.values()):
            error = "Complete all fields."
        elif record["severity"] not in ("Low", "Medium", "High", "Critical"):
            error = "Choose a valid severity."
        elif any(len(record[field]) > limit for field, limit in (("name", 120), ("category", 80), ("description", 5000), ("mitigation", 5000))):
            error = "One or more fields exceed the allowed length."
        else:
            values = tuple(record[field] for field in ("name", "severity", "category", "description", "mitigation"))
            if record_id is None:
                write("INSERT INTO user_threats (name,severity,category,description,mitigation,owner_sub) VALUES (%s,%s,%s,%s,%s,%s)", values + (session["user"]["sub"],))
            else:
                write("UPDATE user_threats SET name=%s,severity=%s,category=%s,description=%s,mitigation=%s WHERE owner_sub=%s AND id=%s", values + (session["user"]["sub"], record_id))
            flash("Threat record saved.")
            return redirect(url_for("threats.index"))
    return render_template("threat_form.html", record=record, editing=record_id is not None, error=error), (400 if error else 200)


@threats.route("/my-threats/<int:record_id>/delete", methods=["POST"])
def delete(record_id):
    owned(record_id)
    write("DELETE FROM user_threats WHERE owner_sub=%s AND id=%s", (session["user"]["sub"], record_id))
    flash("Threat record deleted.")
    return redirect(url_for("threats.index"))

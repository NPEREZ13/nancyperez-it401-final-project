import hmac
import hashlib
import secrets

from flask import flash, redirect, render_template, request, session, url_for
from sqlalchemy.exc import SQLAlchemyError

from models import UserThreat, db
from services.mitigation import selected_mitigation
from services.threat_names import selected_threat_name
from services.categories import selected_category
from services.threat_storage import create_threat_once
from services.records import account_owner, current_owner, validate_record


def register_routes(app):
    @app.route("/threats/new", methods=["GET", "POST"])
    def add_threat():
        fields = ("name", "severity", "category", "description", "mitigation")
        values = {key: "" for key in fields}
        error = None
        status = 200
        csrf_token = session.get("threat_form_token")
        if not isinstance(csrf_token, str):
            csrf_token = secrets.token_urlsafe(32)
            session["threat_form_token"] = csrf_token
        if request.method == "POST":
            values = {key: request.form.get(key, "") for key in fields}
            submitted_token = request.form.get("csrf_token", "")
            if not submitted_token.isascii() or not hmac.compare_digest(csrf_token, submitted_token):
                error = "This form expired. Review your entries and save again."
                status = 400
            elif set(request.form) - set(fields) - {"csrf_token", "mitigation_choice", "name_choice", "category_choice"}:
                error = "Unexpected form fields supplied."
                status = 400
            else:
                try:
                    values["name"] = selected_threat_name(request.form)
                    values["category"] = selected_category(request.form)
                    values["mitigation"] = selected_mitigation(request.form)
                    cleaned = validate_record("threats", values)
                except ValueError as validation_error:
                    error = str(validation_error)
                    status = 400
                else:
                    owner = current_owner()
                    if not owner:
                        # Duplicate submissions of the same first form share one owner.
                        owner = "browser:" + hashlib.sha256(csrf_token.encode()).hexdigest()[:32]
                        session["workspace_owner_sub"] = owner
                    try:
                        _, created = create_threat_once(owner, cleaned)
                    except SQLAlchemyError as database_error:
                        db.session.rollback()
                        app.logger.error("Threat save failed (%s)", type(database_error).__name__)
                        error = "We couldn't save your threat. Your entries are still here; please try again."
                        status = 503
                    else:
                        session.pop("threat_form_token", None)
                        flash("Threat saved successfully." if created else "This threat is already saved. No duplicate was added.", "success")
                        return redirect(url_for("explore"), code=303)
        return render_template("add_threat.html", values=values, error=error,
                               name_choice=request.form.get("name_choice") if request.method == "POST" else None,
                               category_choice=request.form.get("category_choice") if request.method == "POST" else None,
                               mitigation_choice=request.form.get("mitigation_choice") if request.method == "POST" else None,
                               csrf_token=csrf_token,
                               account_owner=bool(account_owner())), status

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/menu")
    def menu():
        return render_template("menu.html")

    @app.route("/about")
    def about():
        return render_template("about.html")

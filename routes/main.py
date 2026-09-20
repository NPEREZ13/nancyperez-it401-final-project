import json
from pathlib import Path

from flask import current_app, render_template, request

from services.data_breaches import BreachScrapeError, get_breach_records
from services.ip_threat import IPThreatError, analyze_ip


BREACH_DISPLAY_LIMIT = 15


def register_routes(app):
    @app.route("/")
    def index():
        breach_query = request.args.get("breach_q", "").strip()
        selected_year = request.args.get("breach_year", "").strip()
        selected_type = request.args.get("breach_type", "").strip()
        breach_error = None

        try:
            all_breaches = get_breach_records()
        except BreachScrapeError as exc:
            all_breaches = []
            breach_error = str(exc)

        breach_years = sorted(
            {record["year"] for record in all_breaches if record["year"] != "Unknown"},
            reverse=True,
        )
        type_labels = {}
        for record in all_breaches:
            organization_type = record["organization_type"]
            if organization_type != "Unknown":
                type_labels.setdefault(organization_type.casefold(), organization_type)
        breach_types = sorted(type_labels.values(), key=str.casefold)

        filtered_breaches = all_breaches
        if breach_query:
            query = breach_query.casefold()
            filtered_breaches = [
                record
                for record in filtered_breaches
                if query in record["entity"].casefold()
            ]
        if selected_year:
            filtered_breaches = [
                record for record in filtered_breaches if record["year"] == selected_year
            ]
        if selected_type:
            filtered_breaches = [
                record
                for record in filtered_breaches
                if record["organization_type"].casefold() == selected_type.casefold()
            ]

        return render_template(
            "index.html",
            breaches=filtered_breaches[:BREACH_DISPLAY_LIMIT],
            breach_match_count=len(filtered_breaches),
            breach_total_count=len(all_breaches),
            breach_years=breach_years,
            breach_types=breach_types,
            breach_query=breach_query,
            selected_breach_year=selected_year,
            selected_breach_type=selected_type,
            breach_error=breach_error,
            breach_display_limit=BREACH_DISPLAY_LIMIT,
        )

    @app.route("/menu")
    def menu():
        return render_template("menu.html")

    @app.route("/about")
    def about():
        return render_template("about.html")

    @app.route("/analyze-ip", methods=["GET", "POST"])
    def analyze_ip_address():
        submitted_ip = ""
        result = None
        error = None

        if request.method == "POST":
            submitted_ip = request.form.get("ip_address", "").strip()
            try:
                # Validation, the API call, response extraction, and service-level
                # error handling are encapsulated in services/ip_threat.py.
                result = analyze_ip(
                    submitted_ip,
                    current_app.config.get("APIFREAKS_API_KEY"),
                )
                submitted_ip = result["ip"]
            except (ValueError, IPThreatError) as exc:
                error = str(exc)

        return render_template(
            "analyze_ip.html",
            submitted_ip=submitted_ip,
            result=result,
            error=error,
        )

    @app.route("/explore")
    def explore():
        data_file = Path(current_app.root_path) / "data" / "threats.json"

        with data_file.open(encoding="utf-8") as file:
            all_threats = json.load(file)

        search_query = request.args.get("q", "").strip()
        selected_severity = request.args.get("severity", "").strip()
        selected_category = request.args.get("category", "").strip()

        severities = sorted({threat["severity"] for threat in all_threats})
        categories = sorted({threat["category"] for threat in all_threats})

        threats = all_threats

        if search_query:
            query = search_query.casefold()
            searchable_fields = ("id", "name", "category", "target", "description", "mitigation")
            threats = [
                threat
                for threat in threats
                if any(query in str(threat.get(field, "")).casefold() for field in searchable_fields)
            ]

        if selected_severity:
            threats = [
                threat
                for threat in threats
                if threat["severity"].casefold() == selected_severity.casefold()
            ]

        if selected_category:
            threats = [
                threat
                for threat in threats
                if threat["category"].casefold() == selected_category.casefold()
            ]

        return render_template(
            "explore.html",
            threats=threats,
            total_threats=len(all_threats),
            severities=severities,
            categories=categories,
            search_query=search_query,
            selected_severity=selected_severity,
            selected_category=selected_category,
        )

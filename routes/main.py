import json
from pathlib import Path

from flask import current_app, render_template, request


def register_routes(app):
    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/menu")
    def menu():
        return render_template("menu.html")

    @app.route("/about")
    def about():
        return render_template("about.html")

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

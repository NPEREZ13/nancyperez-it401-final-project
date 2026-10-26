"""HTTP entry point for Explore; search behavior lives in the service layer."""

from flask import render_template, request, url_for

from services.records import current_owner
from services.search_service import prepare_explore


def register_search_routes(app):
    # Preserve the established endpoint name and all existing /explore links.
    app.add_url_rule("/explore", endpoint="explore", view_func=explore, methods=["GET"])


def explore():
    context = prepare_explore(request.args, current_owner())
    pagination = context["pagination"]
    parameters = context.pop("page_parameters")
    context["previous_url"] = url_for("explore", **parameters, page=pagination.page - 1) if pagination.page > 1 else None
    context["next_url"] = url_for("explore", **parameters, page=pagination.page + 1) if pagination.page < pagination.pages else None
    return render_template("explore.html", **context)

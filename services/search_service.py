"""Process display/search values separately and match owner-scoped threat records."""

from dataclasses import dataclass

from models import UserThreat, db
from services.records import PUBLIC_DEMO_OWNER, owned_query

SORT_OPTIONS = {
    "relevance": "Relevance",
    "alphabetical": "Alphabetical (A–Z)",
}


@dataclass(frozen=True)
class SearchQuery:
    original: str
    normalized: str

    @property
    def is_empty(self):
        return not self.normalized


def process_query(value):
    """Keep the submitted text for display; trim and casefold only for matching."""
    return SearchQuery(original=value, normalized=value.strip().casefold())


def search_threats(threats, query):
    if query.is_empty:
        return []
    fields = ("id", "name", "category", "description", "mitigation")
    # The query is literal text, never SQL. Ownership is enforced by the ORM
    # before these records are passed here.
    return [threat for threat in threats if any(
        query.normalized in str(threat.get(field, "")).casefold() for field in fields
    )]


def relevance_score(threat, query):
    if query.is_empty:
        return 0
    title = str(threat.get("name", "")).strip().casefold()
    score = 100 if title == query.normalized else (50 if query.normalized in title else 0)
    for field, weight in (("category", 10), ("description", 5), ("mitigation", 2), ("id", 1)):
        if query.normalized in str(threat.get(field, "")).casefold():
            score += weight
    return score


def sort_results(threats, query, order="relevance"):
    def alphabetical_key(threat):
        return (str(threat.get("name", "")).casefold(), threat["id"])

    if order == "alphabetical":
        return sorted(threats, key=alphabetical_key)
    # Tie-breaking makes repeated searches stable even when scores are equal.
    return sorted(threats, key=lambda threat: (-relevance_score(threat, query), *alphabetical_key(threat)))


PAGE_SIZE = 10
SCAN_BATCH_SIZE = 100


@dataclass
class SearchPage:
    items: list
    total: int
    page: int
    pages: int
    total_owned: int
    severities: list
    categories: list

    @property
    def first(self):
        return (self.page - 1) * PAGE_SIZE + 1 if self.total else 0

    @property
    def last(self):
        return min(self.page * PAGE_SIZE, self.total)


def paginated_threats(owner, query, order, severity, category, requested_page, searching=True):
    """Retrieve batches → filter → rank compact keys → paginate → fetch page.

    Python matching preserves full Unicode casefold semantics. Keyset batches
    bound each read; only rank keys and IDs survive a batch, not full records.
    """
    keys = []
    severities, categories = set(), set()
    total_owned = last_id = 0
    while owner:
        rows = db.session.execute(
            owned_query(UserThreat, owner).with_only_columns(
                UserThreat.id, UserThreat.name, UserThreat.severity,
                UserThreat.category, UserThreat.description, UserThreat.mitigation,
            ).where(UserThreat.id > last_id).order_by(UserThreat.id).limit(SCAN_BATCH_SIZE)
        ).mappings().all()
        if not rows:
            break
        for row in rows:
            total_owned += 1
            severities.add(row["severity"])
            categories.add(row["category"])
            if severity and row["severity"].casefold() != severity.casefold():
                continue
            if category and row["category"].casefold() != category.casefold():
                continue
            if searching and not search_threats([row], query):
                continue
            title = row["name"].casefold()
            if searching and order == "relevance":
                key = (-relevance_score(row, query), title, row["id"])
            elif searching:
                key = (title, row["id"])
            else:
                key = (row["id"],)
            keys.append(key)
        last_id = rows[-1]["id"]
        if len(rows) < SCAN_BATCH_SIZE:
            break
    keys.sort()
    total = len(keys)
    pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    page = min(max(1, requested_page), pages)
    ids = [key[-1] for key in keys[(page - 1) * PAGE_SIZE:page * PAGE_SIZE]]
    displayed = {}
    if ids:
        displayed = {row.id: row.to_dict() for row in db.session.scalars(
            owned_query(UserThreat, owner).where(UserThreat.id.in_(ids)).limit(PAGE_SIZE)
        )}
    return SearchPage([displayed[record_id] for record_id in ids if record_id in displayed],
                      total, page, pages, total_owned, sorted(severities), sorted(categories))


def prepare_explore(parameters, owner):
    """Coordinate query processing, scope, retrieval, ranking, and pagination.

    Accept a parameter mapping and trusted owner rather than Flask request or
    session globals. HTTP handling and URL construction belong to the route.
    """
    active_tab = parameters.get("tab", "search" if "q" in parameters else "browse")
    if active_tab not in ("browse", "search"):
        active_tab = "browse"
    query = process_query(parameters.get("q", ""))
    order = parameters.get("sort", "relevance")
    if order not in SORT_OPTIONS:
        order = "relevance"
    error = None
    if active_tab == "search" and "q" in parameters and query.is_empty:
        error = "Enter a keyword or phrase before searching."
    showing_demo = active_tab == "browse" and (not owner or parameters.get("collection") == "demo")
    severity = parameters.get("severity", "").strip()
    category = parameters.get("category", "").strip()
    try:
        requested_page = int(parameters.get("page", 1))
    except (ValueError, TypeError):
        requested_page = 1
    pagination = paginated_threats(
        PUBLIC_DEMO_OWNER if showing_demo else owner, query, order,
        severity, category, requested_page,
        searching=active_tab == "search" or not query.is_empty,
    )
    page_parameters = {"tab": active_tab, "severity": severity, "category": category}
    if active_tab == "search" or "q" in parameters:
        page_parameters.update(q=query.original, sort=order)
    if showing_demo and owner:
        page_parameters["collection"] = "demo"
    return {
        "threats": pagination.items, "total_threats": pagination.total_owned,
        "severities": pagination.severities, "categories": pagination.categories,
        "pagination": pagination, "page_parameters": page_parameters,
        "search_query": query.original, "has_search_query": not query.is_empty,
        "search_error": error, "selected_sort": order, "sort_options": SORT_OPTIONS,
        "selected_severity": severity, "selected_category": category,
        "authenticated": bool(owner) and not showing_demo,
        "has_workspace": bool(owner), "showing_demo": showing_demo,
        "active_tab": active_tab,
    }

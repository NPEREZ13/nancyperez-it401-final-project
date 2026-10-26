"""Reproduce README search evaluation and optional genuine UI screenshots.

Uses an isolated in-memory SQLite database. Never connects to or alters Aiven.
Run from the repository root: python docs/evaluate_search.py [--screenshots]
"""

import argparse
import json
import secrets
import sys
from pathlib import Path
from threading import Thread

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from flask import session
from werkzeug.serving import make_server

from app import create_app
from models import UserThreat, db
from services.migration import import_threats
from services.search_service import prepare_explore, relevance_score, process_query

OWNER = "documentation-evaluation-user"


def build_fixture():
    app = create_app(test_config={
        "TESTING": True, "SECRET_KEY": secrets.token_hex(32), "DEBUG": False,
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "SQLALCHEMY_ENGINE_OPTIONS": {},
        "GOOGLE_CLIENT_ID": None, "GOOGLE_CLIENT_SECRET": None,
        "APIFREAKS_API_KEY": None,
    })
    with app.app_context():
        db.create_all()  # Only this isolated, in-memory database.
        import_threats(db.session, OWNER, ROOT / "data/threats.json")
        examples = [
            {"name": "Phishing", "severity": "High", "category": "Phishing",
             "description": "Synthetic email incident for evaluating exact name matches."},
            {"name": "Payroll Phishing Exercise", "severity": "Medium", "category": "Phishing",
             "description": "Synthetic payroll incident for evaluating partial name matches."},
        ]
        examples.extend({
            "name": f"Endpoint Review {number:02}", "severity": "High", "category": "Training",
            "description": "Synthetic phishing exercise used only for pagination evaluation.",
        } for number in range(1, 12))
        for example in examples:
            db.session.add(UserThreat(owner_sub=OWNER, mitigation="Review the training exercise.", **example))
        db.session.commit()

    @app.before_request
    def evaluation_identity():
        # This callback exists ONLY in this temporary documentation application.
        session["user"] = {"sub": OWNER, "name": "Synthetic Evaluation User", "email": "evaluation@example.test"}

    return app


def evaluate(app):
    phishing = ["Phishing", "Payroll Phishing Exercise", "Cloud Credential Phishing"] + [
        f"Endpoint Review {number:02}" for number in range(1, 12)
    ]
    cases = [
        {"query": "  PHISHING  ", "expected": phishing},
        {"query": "cloud", "severity": "High", "category": "Credential Theft", "expected": ["Cloud Credential Phishing"]},
        {"query": "MFA", "expected": ["BlackCat Ransomware", "Cloud Credential Phishing"]},
        {"query": "BlackCat Ransomware", "expected": ["BlackCat Ransomware"]},
        {"query": "quantum banana", "expected": []},
    ]
    report = {"fixture": "Isolated SQLite; 4 migrated demo threats + 13 synthetic records; simulated account session",
              "record_count": 17, "evaluation_type": "Offline documentation evaluation, not production search telemetry",
              "model_tables": sorted(db.metadata.tables), "search_telemetry_implemented": False, "queries": []}
    with app.app_context():
        for case in cases:
            args = {"tab": "search", "q": case["query"], "sort": "relevance",
                    "severity": case.get("severity", ""), "category": case.get("category", "")}
            first = prepare_explore(args, OWNER)
            rows = list(first["threats"])
            for page in range(2, first["pagination"].pages + 1):
                rows.extend(prepare_explore({**args, "page": str(page)}, OWNER)["threats"])
            actual = [row["name"] for row in rows]
            relevant = set(case["expected"])
            hits = len(set(actual) & relevant)
            report["queries"].append({
                **case, "actual": actual, "result_count": len(actual),
                "precision": hits / len(actual) if actual else None,
                "recall": hits / len(relevant) if relevant else None,
                "scores": [relevance_score(row, process_query(case["query"])) for row in rows],
            })
        report["pagination"] = {"query": "phishing", "page_sizes": [
            len(prepare_explore({"tab": "search", "q": "phishing", "page": str(page)}, OWNER)["threats"])
            for page in (1, 2)
        ]}
    (ROOT / "docs/search-evaluation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def screenshots(app):
    from playwright.sync_api import sync_playwright

    server = make_server("127.0.0.1", 0, app, threaded=False)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    cases = {
        "a4-search-form.png": "tab=search",
        "a4-search-results.png": "tab=search&q=phishing",
        "a4-search-filtered.png": "tab=search&q=cloud&severity=High&category=Credential+Theft",
        "a4-search-sorted.png": "tab=search&q=phishing&sort=alphabetical",
        "a4-search-pagination.png": "tab=search&q=phishing&sort=relevance&page=2",
        "a4-search-no-results.png": "tab=search&q=quantum+banana",
    }
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(channel="msedge", headless=True)
            try:
                page = browser.new_page(viewport={"width": 1440, "height": 1000}, device_scale_factor=1, reduced_motion="reduce")
                for name, query in cases.items():
                    response = page.goto(f"http://127.0.0.1:{server.server_port}/explore?{query}", wait_until="networkidle")
                    assert response.status == 200
                    page.screenshot(path=str(ROOT / "docs/screenshots" / name), full_page=True)
            finally:
                browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--screenshots", action="store_true")
    options = parser.parse_args()
    app = build_fixture()
    try:
        report = evaluate(app)
        for case in report["queries"]:
            print(f"{case['query']!r}: {case['result_count']} results; precision={case['precision']}; recall={case['recall']}")
        if options.screenshots:
            screenshots(app)
            print("Captured six real browser screenshots using isolated evaluation data.")
    finally:
        with app.app_context():
            db.session.remove()
            db.engine.dispose()


if __name__ == "__main__":
    main()

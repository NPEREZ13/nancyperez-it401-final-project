"""Explicit, transactional import. The web application never reads JSON storage."""

import hashlib
import json
from pathlib import Path

import click
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from models import UserThreat, db
from services.records import PUBLIC_DEMO_OWNER, owned_query, validate_record


def import_threats(session, owner, source):
    data = json.loads(Path(source).read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("The source must be a JSON array.")
    validated = []
    for item in data:
        if not isinstance(item, dict) or set(item) - {
            "id", "name", "category", "severity", "target", "description", "mitigation"
        }:
            raise ValueError("Unexpected legacy record format; no records imported.")
        values = {key: item[key] for key in (
            "name", "category", "severity", "description", "mitigation"
        ) if key in item}
        description = values.get("description")
        if not isinstance(description, str):
            raise ValueError("Legacy description must be a string.")
        for key, label in (("target", "Primary target"), ("id", "Legacy ID")):
            if key in item:
                if not isinstance(item[key], str):
                    raise ValueError(f"Legacy {key} must be a string.")
                description += f"\n\n{label}: {item[key]}"
        values["description"] = description
        validated.append(validate_record("threats", values))
    inserted = skipped = 0
    for values in validated:
        # Python equality avoids case/accent-insensitive MySQL text comparisons.
        candidates = session.scalars(owned_query(UserThreat, owner).where(
            UserThreat.name == values["name"]
        )).all()
        if any(all(getattr(row, key) == value for key, value in values.items()) for row in candidates):
            skipped += 1
        else:
            session.add(UserThreat(owner_sub=owner, **values))
            session.flush()
            inserted += 1
    return inserted, skipped


def register_migration_command(app):
    @app.cli.command("import-json")
    @click.option("--owner-sub", help="Verified identity subject to own the imported records.")
    @click.option("--public-demo", is_flag=True, help="Import unowned demo JSON for the public Explore page.")
    @click.option("--file", "source", type=click.Path(exists=True, dir_okay=False), default="data/threats.json", show_default=True)
    @click.option("--apply", is_flag=True, help="Commit the import; otherwise preview and roll back.")
    def import_json(owner_sub, public_demo, source, apply):
        """Import legacy threats for one owner without altering tables or source files."""
        if bool(owner_sub) == public_demo:
            raise click.ClickException("Choose exactly one of --owner-sub or --public-demo.")
        if not public_demo and owner_sub == PUBLIC_DEMO_OWNER:
            raise click.ClickException("The public demo owner is reserved; use --public-demo explicitly.")
        if public_demo:
            owner_sub = PUBLIC_DEMO_OWNER
        if (not owner_sub or len(owner_sub) > 255 or not owner_sub.isascii()
                or not owner_sub.isprintable() or owner_sub != owner_sub.strip()):
            raise click.ClickException("Owner subject must be 1–255 printable ASCII characters without outer whitespace.")
        # Serialize imports for this owner so simultaneous reruns cannot duplicate rows.
        lock = "threatlense-import:" + hashlib.sha256(owner_sub.encode()).hexdigest()[:40]
        try:
            with db.engine.connect() as connection:
                is_mysql = connection.dialect.name == "mysql"
                acquired = False
                try:
                    if is_mysql:
                        acquired = connection.scalar(text("SELECT GET_LOCK(:name, 10)"), {"name": lock}) == 1
                        connection.commit()
                        if not acquired:
                            raise click.ClickException("Another import is in progress for this owner.")
                    with Session(bind=connection) as import_session:
                        try:
                            inserted, skipped = import_threats(import_session, owner_sub, source)
                            if apply:
                                import_session.commit()
                            else:
                                import_session.rollback()
                        except Exception:
                            import_session.rollback()
                            raise
                finally:
                    if acquired:
                        connection.execute(text("SELECT RELEASE_LOCK(:name)"), {"name": lock})
                        connection.commit()
        except SQLAlchemyError:
            raise click.ClickException("Database import failed; changes rolled back.") from None
        except (OSError, ValueError):
            raise click.ClickException("Invalid or unreadable import file; changes rolled back.") from None
        click.echo(f"{'Imported' if apply else 'Preview (rolled back)'}: {inserted}; skipped duplicates: {skipped}.")

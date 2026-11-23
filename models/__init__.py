"""Mappings for the existing Aiven tables. No startup DDL is performed."""

from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects import mysql

db = SQLAlchemy()

record_id = db.BigInteger().with_variant(mysql.BIGINT(unsigned=True), "mysql").with_variant(db.Integer(), "sqlite")
owner_type = db.String(255).with_variant(mysql.VARCHAR(255, charset="ascii", collation="ascii_bin"), "mysql")


class UserThreat(db.Model):
    __tablename__ = "user_threats"
    __table_args__ = (db.Index("idx_threats_owner", "owner_sub"),)

    id = db.Column(record_id, primary_key=True, autoincrement=True)
    owner_sub = db.Column(owner_type, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    severity = db.Column(db.String(10), nullable=False)
    category = db.Column(db.String(80), nullable=False)
    description = db.Column(db.Text, nullable=False)
    mitigation = db.Column(db.Text, nullable=False)

    def to_dict(self):
        return {key: getattr(self, key) for key in (
            "id", "name", "severity", "category", "description", "mitigation"
        )}


class ProfileDevice(db.Model):
    __tablename__ = "profile_devices"
    __table_args__ = (db.Index("idx_devices_owner", "owner_sub"),)

    id = db.Column(record_id, primary_key=True, autoincrement=True)
    owner_sub = db.Column(owner_type, nullable=False)
    name = db.Column(db.String(80), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    result_json = db.Column(db.JSON(none_as_null=True))
    checked_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.current_timestamp())

    def to_dict(self):
        return {
            "id": self.id, "name": self.name, "ip_address": self.ip_address,
            "result_json": self.result_json,
            "checked_at": self.checked_at.isoformat() if self.checked_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class StoredIntelligence(db.Model):
    """Auditable output from one completed threat-summarization generation."""

    __tablename__ = "stored_intelligence"
    __table_args__ = (
        db.Index("idx_intelligence_owner_generated", "owner_sub", "generated_at_utc"),
    )

    id = db.Column(record_id, primary_key=True, autoincrement=True)
    owner_sub = db.Column(owner_type, nullable=False)
    user_request = db.Column(db.Text, nullable=False)
    generated_output = db.Column(db.JSON(none_as_null=True), nullable=False)
    prompt_version = db.Column(db.String(64), nullable=False)
    model_identifier = db.Column(db.String(160), nullable=False)
    generated_at_utc = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
    )
    source_record_ids = db.Column(db.JSON(none_as_null=True), nullable=False)
    context_snapshot = db.Column(db.JSON(none_as_null=True), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "user_request": self.user_request,
            "generated_output": self.generated_output,
            "prompt_version": self.prompt_version,
            "model_identifier": self.model_identifier,
            "generated_at_utc": (
                self.generated_at_utc.replace(tzinfo=timezone.utc).isoformat()
                if self.generated_at_utc else None
            ),
            "source_record_ids": self.source_record_ids,
            "context_snapshot": self.context_snapshot,
        }

"""Mappings for the existing Aiven tables. No startup DDL is performed."""

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

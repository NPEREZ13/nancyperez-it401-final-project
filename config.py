import os
from pathlib import Path

from sqlalchemy import URL

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev")
    DATA_DIR = os.path.join(BASE_DIR, "data")

    # External API keys / service config
    API_KEY = os.environ.get("API_KEY")
    AI_SERVICE_API_KEY = os.environ.get("AI_SERVICE_API_KEY")


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False


config = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}


def configure_database(app):
    """Configure the existing database; never create or alter tables here."""
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    if app.config.get("TESTING") and app.config.get("SQLALCHEMY_DATABASE_URI"):
        return
    required = ("MYSQL_HOST", "MYSQL_PORT", "MYSQL_USER", "MYSQL_PASSWORD",
                "MYSQL_DATABASE", "MYSQL_SSL_CA")
    if any(not os.environ.get(key) for key in required):
        raise RuntimeError("Configure all MYSQL_ settings listed in .env.example.")
    certificate = Path(os.environ["MYSQL_SSL_CA"])
    if not certificate.is_absolute():
        certificate = Path(BASE_DIR) / certificate
    if not certificate.is_file():
        raise RuntimeError("MYSQL_SSL_CA must point to an existing CA certificate.")
    app.config["SQLALCHEMY_DATABASE_URI"] = URL.create(
        "mysql+pymysql", username=os.environ["MYSQL_USER"],
        password=os.environ["MYSQL_PASSWORD"], host=os.environ["MYSQL_HOST"],
        port=int(os.environ["MYSQL_PORT"]), database=os.environ["MYSQL_DATABASE"],
        query={"charset": "utf8mb4"},
    )
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True, "pool_recycle": 300, "hide_parameters": True,
        "connect_args": {
            "ssl_ca": str(certificate.resolve()),
            "ssl_verify_cert": True, "ssl_verify_identity": True,
            "connect_timeout": 10, "read_timeout": 15, "write_timeout": 15,
        },
    }

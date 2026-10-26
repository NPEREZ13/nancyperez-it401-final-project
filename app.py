import os

from flask import Flask, request
from dotenv import load_dotenv

from config import BASE_DIR, config, configure_database
from models import db
from routes.main import register_routes
from routes.search import register_search_routes


def create_app(config_name=None, test_config=None):
    load_dotenv(os.path.join(BASE_DIR, ".env"))
    config_name = config_name or os.environ.get("FLASK_ENV", "default")

    app = Flask(__name__)
    app.config.from_object(config[config_name])
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY"),
        GOOGLE_CLIENT_ID=os.environ.get("GOOGLE_CLIENT_ID"),
        GOOGLE_CLIENT_SECRET=os.environ.get("GOOGLE_CLIENT_SECRET"),
        APIFREAKS_API_KEY=os.environ.get("APIFREAKS_API_KEY"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=config_name == "production",
        MAX_CONTENT_LENGTH=128 * 1024,
    )
    if test_config:
        app.config.update(test_config)
    if not app.config.get("SECRET_KEY"):
        raise RuntimeError("Set SECRET_KEY to a strong random value in .env.")
    configure_database(app)
    db.init_app(app)
    from services.mitigation import MITIGATION_OPTIONS
    app.jinja_env.globals["mitigation_options"] = MITIGATION_OPTIONS
    from services.threat_names import THREAT_NAME_OPTIONS
    app.jinja_env.globals["threat_name_options"] = THREAT_NAME_OPTIONS
    from services.categories import CATEGORY_OPTIONS
    app.jinja_env.globals["category_options"] = CATEGORY_OPTIONS
    from routes.auth import init_auth
    from routes.profile import profile
    from routes.threats import threats
    init_auth(app)
    app.register_blueprint(profile)
    app.register_blueprint(threats)

    register_routes(app)
    register_search_routes(app)
    from routes.records import records
    from services.migration import register_migration_command
    app.register_blueprint(records)
    register_migration_command(app)

    from sqlalchemy.exc import SQLAlchemyError

    @app.errorhandler(SQLAlchemyError)
    def database_error(error):
        db.session.rollback()
        # Exception messages may contain SQL parameters or connection credentials.
        app.logger.error("Database operation failed (%s)", type(error).__name__)
        if request.path.startswith("/api/"):
            return {"error": "Database temporarily unavailable. Please try again."}, 503
        return "Database temporarily unavailable. Please try again.", 503

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=app.config.get("DEBUG", False))

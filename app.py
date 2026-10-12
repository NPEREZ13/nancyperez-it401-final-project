import os

from flask import Flask
from dotenv import load_dotenv
from database import init_app

load_dotenv()

from config import config
from routes.main import register_routes
from routes.auth import init_auth
from routes.profile import profile
from routes.threats import threats


def create_app(config_name=None):
    config_name = config_name or os.environ.get("FLASK_ENV", "default")

    app = Flask(__name__)
    app.config.from_object(config[config_name])
    init_app(app)
    init_auth(app)
    app.register_blueprint(profile)
    app.register_blueprint(threats)

    register_routes(app)

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=app.config.get("DEBUG", False))

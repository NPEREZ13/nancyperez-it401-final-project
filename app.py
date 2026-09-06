import os

from flask import Flask

from config import config
from routes.main import register_routes


def create_app(config_name=None):
    config_name = config_name or os.environ.get("FLASK_ENV", "default")

    app = Flask(__name__)
    app.config.from_object(config[config_name])

    register_routes(app)

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=app.config.get("DEBUG", False))

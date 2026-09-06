import os

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

import pymysql
from flask import current_app, g


def get_db():
    if "db" not in g:
        config = current_app.config
        g.db = pymysql.connect(
            host=config["MYSQL_HOST"],
            port=config["MYSQL_PORT"],
            user=config["MYSQL_USER"],
            password=config["MYSQL_PASSWORD"],
            database=config["MYSQL_DATABASE"],
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
            ssl_ca=config["MYSQL_SSL_CA"],
            ssl_verify_cert=True,
            ssl_verify_identity=True,
            connect_timeout=10,
            read_timeout=10,
            write_timeout=10,
        )
    return g.db


def close_db(error=None):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def init_app(app):
    app.teardown_appcontext(close_db)

    @app.cli.command("init-threats")
    def init_threats():
        """Create the user threat records table."""
        from pathlib import Path
        import click
        with get_db().cursor() as cursor:
            cursor.execute((Path(app.root_path) / "schema_threats.sql").read_text())
        get_db().commit()
        click.echo("Threat records table is ready.")

    @app.cli.command("init-devices")
    def init_devices():
        """Create the profile devices table without changing existing tables."""
        from pathlib import Path
        import click
        with get_db().cursor() as cursor:
            cursor.execute((Path(app.root_path) / "schema_devices.sql").read_text())
        get_db().commit()
        click.echo("Profile devices table is ready.")

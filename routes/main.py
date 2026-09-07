from flask import render_template


def register_routes(app):
    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/menu")
    def menu():
        return render_template("menu.html")

    @app.route("/about")
    def about():
        return render_template("about.html")

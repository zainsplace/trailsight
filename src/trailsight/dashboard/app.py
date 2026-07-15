from flask import Flask, render_template


def create_app():
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.post("/scan")
    def scan():
        return render_template("index.html")

    @app.get("/demo")
    def demo():
        return render_template("index.html")

    return app

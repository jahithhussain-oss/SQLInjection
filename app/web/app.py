"""
Flask application factory.
Run with:  python -m app.web.app
"""
from flask import Flask
from app.web.routes import bp


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = "sqli-scanner-dev-key"
    app.register_blueprint(bp)
    return app


if __name__ == "__main__":
    app = create_app()
    print("\n  SQL Injection Scanner — Web UI")
    print("  Open http://127.0.0.1:5000 in your browser\n")
    app.run(debug=True, use_reloader=False, port=5000)

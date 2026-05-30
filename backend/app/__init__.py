from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from dotenv import load_dotenv
import os

load_dotenv()

db = SQLAlchemy()


def create_app(config_name="development"):
    app = Flask(__name__, instance_relative_config=True)

    # Configuration
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-CHANGE-ME")
    app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "jwt-secret-CHANGE-ME")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50MB max upload

    if config_name == "testing":
        app.config["TESTING"] = True
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    else:
        app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
            "DATABASE_URI", "sqlite:///securetransfer.db"
        )

    # Extensions
    db.init_app(app)
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # Health check
    @app.get("/api/health")
    def health():
        return {"status": "ok", "service": "SecureTransfer API"}

    # Blueprints
    from .routes.auth import auth_bp
    from .routes.files import files_bp
    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(files_bp, url_prefix="/api/files")

    # Create tables
    with app.app_context():
        from . import models  # noqa: F401 — registers models with SQLAlchemy
        db.create_all()

    return app
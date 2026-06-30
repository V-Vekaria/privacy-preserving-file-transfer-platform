from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
import os

load_dotenv()

db = SQLAlchemy()
limiter = Limiter(key_func=get_remote_address, default_limits=[])


def create_app(config_name="development"):
    app = Flask(__name__, instance_relative_config=True)

    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-CHANGE-ME")
    app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "jwt-secret-CHANGE-ME")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    # 50 MB advertised file limit, but base64-encoded ciphertext + JSON overhead
    # inflates the raw request body by ~37% — so the actual cap must be higher
    # than 50 MB or legitimate 50 MB files get rejected at the HTTP layer.
    app.config["MAX_CONTENT_LENGTH"] = 70 * 1024 * 1024  # 70 MB raw request size

    if config_name == "testing":
        app.config["TESTING"] = True
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        app.config["RATELIMIT_ENABLED"] = False
    else:
        app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
            "DATABASE_URI", "sqlite:///securetransfer.db"
        )

    db.init_app(app)
    limiter.init_app(app)
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    @app.get("/api/health")
    def health():
        return {"status": "ok", "service": "SecureTransfer API"}

    @app.errorhandler(413)
    def too_large(_e):
        return jsonify({"error": "File too large — the encrypted upload exceeds the server limit."}), 413

    from .routes.auth import auth_bp
    from .routes.files import files_bp
    from .routes.detection import detection_bp
    from .routes.dashboard import dashboard_bp
    from .routes.share import share_bp

    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(files_bp, url_prefix="/api/files")
    app.register_blueprint(detection_bp, url_prefix="/api/detection")
    app.register_blueprint(dashboard_bp, url_prefix="/api/dashboard")
    app.register_blueprint(share_bp, url_prefix="/api/share")

    with app.app_context():
        from . import models  # noqa: F401
        db.create_all()

    return app

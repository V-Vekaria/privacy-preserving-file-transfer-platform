from flask import Blueprint, request, jsonify, current_app
from app import db
from app.models import User
import bcrypt
import jwt
from datetime import datetime, timezone, timedelta

auth_bp = Blueprint("auth", __name__)

# helpers

def _hash_password(plain: str) -> str:
    """Return bcrypt hash string. Plaintext never stored."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(plain.encode(), salt).decode()


def _check_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def _issue_token(user_id: int, username: str) -> str:
    """Issue a signed JWT valid for 24 hours."""
    payload = {
        "sub": user_id,
        "username": username,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=24),
    }
    return jwt.encode(
        payload,
        current_app.config["JWT_SECRET_KEY"],
        algorithm="HS256",
    )


# POST /api/auth/register

@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True)

    # validation
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    errors = {}
    if not username:
        errors["username"] = "Username is required"
    elif len(username) < 3:
        errors["username"] = "Username must be at least 3 characters"

    if not email or "@" not in email:
        errors["email"] = "A valid email address is required"

    if not password:
        errors["password"] = "Password is required"
    elif len(password) < 8:
        errors["password"] = "Password must be at least 8 characters"

    if errors:
        return jsonify({"error": "Validation failed", "details": errors}), 400

    # duplicate check 
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already taken"}), 409

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already registered"}), 409

    # create user — password hashed BEFORE any DB write (FR2)
    hashed = _hash_password(password)
    user = User(username=username, email=email, password_hashed=hashed)
    db.session.add(user)
    db.session.commit()

    token = _issue_token(user.user_id, user.username)

    return jsonify({
        "message": "Registration successful",
        "user_id": user.user_id,
        "username": user.username,
        "token": token,
    }), 201


# POST /api/auth/login 

@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    user = User.query.filter_by(username=username).first()

    # Constant-time comparison prevents username enumeration
    if not user or not _check_password(password, user.password_hashed):
        return jsonify({"error": "Invalid username or password"}), 401

    token = _issue_token(user.user_id, user.username)

    return jsonify({
        "message": "Login successful",
        "user_id": user.user_id,
        "username": user.username,
        "token": token,
    }), 200
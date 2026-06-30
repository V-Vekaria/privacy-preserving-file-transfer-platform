from flask import Blueprint, request, jsonify, current_app
from app import db, limiter
from app.models import User
import bcrypt
import jwt
import os
import base64
from datetime import datetime, timezone, timedelta

auth_bp = Blueprint("auth", __name__)


def _hash_password(plain: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(plain.encode(), salt).decode()


def _check_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def _issue_token(user_id: int, username: str) -> str:
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=24),
    }
    return jwt.encode(payload, current_app.config["JWT_SECRET_KEY"], algorithm="HS256")


def _generate_key_salt() -> str:
    """Random 16-byte salt for client-side PBKDF2 vault key derivation."""
    return base64.b64encode(os.urandom(16)).decode("ascii")


@auth_bp.route("/register", methods=["POST"])
@limiter.limit("5 per minute")
def register():
    data = request.get_json(silent=True)
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

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already taken"}), 409
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already registered"}), 409

    hashed = _hash_password(password)
    key_salt = _generate_key_salt()
    user = User(username=username, email=email, password_hashed=hashed, key_salt=key_salt)
    db.session.add(user)
    db.session.commit()

    token = _issue_token(user.user_id, user.username)
    return jsonify({
        "message": "Registration successful",
        "user_id": user.user_id,
        "username": user.username,
        "token": token,
        "key_salt": key_salt,
    }), 201


@auth_bp.route("/login", methods=["POST"])
@limiter.limit("10 per minute; 3 per 10 seconds")
def login():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    identifier = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not identifier or not password:
        return jsonify({"error": "Username/email and password are required"}), 400

    # Accept either username or email as the login identifier
    user = User.query.filter(
        (User.username == identifier) | (User.email == identifier.lower())
    ).first()
    if not user or not _check_password(password, user.password_hashed):
        return jsonify({"error": "Invalid username or password"}), 401

    # Backfill key_salt for existing accounts that pre-date this feature
    if not user.key_salt:
        user.key_salt = _generate_key_salt()
        db.session.commit()

    token = _issue_token(user.user_id, user.username)
    return jsonify({
        "message": "Login successful",
        "user_id": user.user_id,
        "username": user.username,
        "token": token,
        "key_salt": user.key_salt,
    }), 200

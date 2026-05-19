from functools import wraps
from flask import request, jsonify, current_app
from app.models import User
import jwt


def require_auth(f):
    #Decorator that validates Bearer JWT and injects current_user.
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or malformed Authorization header"}), 401

        token = auth_header.split(" ", 1)[1]

        try:
            payload = jwt.decode(
                token,
                current_app.config["JWT_SECRET_KEY"],
                algorithms=["HS256"],
            )
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        user = User.query.get(payload.get("sub"))
        if not user:
            return jsonify({"error": "User not found"}), 401

        return f(current_user=user, *args, **kwargs)

    return decorated
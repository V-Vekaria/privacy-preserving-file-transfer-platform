"""Share routes — time-limited file sharing with per-share key wrapping."""

import base64
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from app import db
from app.models import EncryptedFile, ShareToken
from app.middleware.auth import require_auth

share_bp = Blueprint("share", __name__)


@share_bp.route("/<int:file_id>", methods=["POST"])
@require_auth
def create_share(current_user, file_id):
    """Create a 24-hour share token for a file the caller owns."""
    enc_file = EncryptedFile.query.filter_by(
        file_id=file_id, user_id=current_user.user_id
    ).first()
    if not enc_file:
        return jsonify({"error": "File not found"}), 404

    body = request.get_json(silent=True) or {}
    wrapped_key = body.get("wrapped_key")
    share_salt  = body.get("share_salt")
    share_iv    = body.get("share_iv")

    token = ShareToken(
        file_id=file_id,
        owner_id=current_user.user_id,
        wrapped_key=wrapped_key,
        share_salt=share_salt,
        share_iv=share_iv,
    )
    db.session.add(token)
    db.session.commit()

    return jsonify({
        "token": token.token,
        "expires_at": token.expires_at.isoformat(),
        "file_id": file_id,
        "filename": enc_file.filename or f"file_{file_id}",
    }), 201


@share_bp.route("/<string:token>", methods=["GET"])
def download_shared(token):
    """
    Return ciphertext for a valid, unexpired share token.
    No authentication required — the token IS the authorisation.
    The recipient still needs the passphrase to decrypt (zero-knowledge).
    """
    share = ShareToken.query.filter_by(token=token).first()
    if not share:
        return jsonify({"error": "Invalid or expired share link"}), 404

    if share.is_expired:
        return jsonify({"error": "Share link has expired"}), 410

    enc_file = EncryptedFile.query.filter_by(file_id=share.file_id).first()
    if not enc_file:
        return jsonify({"error": "File not found"}), 404

    share.access_count += 1
    share.last_accessed_at = datetime.now(timezone.utc)
    db.session.commit()

    return jsonify({
        "filename": enc_file.filename or f"file_{enc_file.file_id}",
        "ciphertext": base64.b64encode(enc_file.encrypted_data).decode("ascii"),
        "iv": enc_file.iv,
        "salt": enc_file.salt or "",
        "expires_at": share.expires_at.isoformat(),
        "wrapped_key": share.wrapped_key or "",
        "share_salt": share.share_salt or "",
        "share_iv": share.share_iv or "",
        "access_count": share.access_count,
    }), 200


@share_bp.route("/<string:token>/stats", methods=["GET"])
@require_auth
def share_stats(current_user, token):
    """Return access statistics for a share token the caller owns."""
    share = ShareToken.query.filter_by(
        token=token, owner_id=current_user.user_id
    ).first()
    if not share:
        return jsonify({"error": "Token not found"}), 404

    return jsonify({
        "token": share.token,
        "access_count": share.access_count,
        "last_accessed_at": share.last_accessed_at.isoformat() if share.last_accessed_at else None,
        "created_at": share.created_at.isoformat(),
        "expires_at": share.expires_at.isoformat(),
        "is_expired": share.is_expired,
    }), 200


@share_bp.route("/<string:token>", methods=["DELETE"])
@require_auth
def revoke_share(current_user, token):
    """Owner revokes a share token before it expires."""
    share = ShareToken.query.filter_by(
        token=token, owner_id=current_user.user_id
    ).first()
    if not share:
        return jsonify({"error": "Token not found"}), 404

    db.session.delete(share)
    db.session.commit()
    return jsonify({"message": "Share link revoked"}), 200

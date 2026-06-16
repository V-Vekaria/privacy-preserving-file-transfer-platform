"""
File routes — upload, list, download, delete.

Zero-knowledge boundary: the browser encrypts with AES-GCM before sending.
The server stores only ciphertext and IV — no plaintext, no key, no filename.
"""

import base64
import binascii
from flask import Blueprint, request, jsonify
from app import db
from app.models import EncryptedFile, Metadata, ShareToken
from app.middleware.auth import require_auth
from app.services.metadata_service import log_metadata

files_bp = Blueprint("files", __name__)


def _decode_ciphertext(value: str) -> bytes | None:
    """Strictly decode base64 ciphertext; return None if malformed."""
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None


@files_bp.route("/upload", methods=["POST"])
@require_auth
def upload_file(current_user):
    """
    Accept an already-encrypted file from the client and store it.

    Expects JSON:
        { "ciphertext": "<base64>", "iv": "<base64 or hex>" }

    The server never sees plaintext or the key (FR4, FR5).
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    ciphertext_b64 = data.get("ciphertext") or ""
    iv = (data.get("iv") or "").strip()
    salt = (data.get("salt") or "").strip()[:64] or None
    filename_enc = (data.get("filename_enc") or "").strip() or None
    filename_iv = (data.get("filename_iv") or "").strip()[:32] or None

    if not ciphertext_b64 or not iv:
        return jsonify({"error": "ciphertext and iv are required"}), 400

    if len(iv) > 32:
        return jsonify({"error": "iv is malformed"}), 400

    ciphertext = _decode_ciphertext(ciphertext_b64)
    if ciphertext is None:
        return jsonify({"error": "ciphertext must be valid base64"}), 400
    if len(ciphertext) == 0:
        return jsonify({"error": "ciphertext is empty"}), 400

    # Persist ciphertext + IV and its metadata in a single transaction so they
    # can never drift apart (atomicity).
    enc_file = EncryptedFile(
        user_id=current_user.user_id,
        filename=None,
        filename_enc=filename_enc,
        filename_iv=filename_iv,
        encrypted_data=ciphertext,
        iv=iv,
        salt=salt,
    )
    db.session.add(enc_file)
    db.session.flush()  # assign file_id without committing yet

    metadata = log_metadata(
        user_id=current_user.user_id,
        file_id=enc_file.file_id,
        enc_file_size=len(ciphertext),
    )
    db.session.commit()

    return jsonify({
        "message": "File uploaded",
        "file_id": enc_file.file_id,
        "metadata": {
            "metadata_id": metadata.metadata_id,
            "enc_file_size": metadata.enc_file_size,
            "timestamp": metadata.timestamp.isoformat(),
            "transfer_frequency": metadata.transfer_frequency,
        },
    }), 201


@files_bp.route("", methods=["GET"])
@require_auth
def list_files(current_user):
    """
    List the caller's files. Returns metadata only — no ciphertext, no IV —
    so a listing leaks nothing about content and stays cheap to fetch.
    """
    rows = (
        db.session.query(EncryptedFile, Metadata)
        .join(Metadata, Metadata.file_id == EncryptedFile.file_id)
        .filter(EncryptedFile.user_id == current_user.user_id)
        .order_by(EncryptedFile.upload_timestamp.desc())
        .all()
    )

    files = [
        {
            "file_id": enc.file_id,
            "filename": enc.filename or f"file_{enc.file_id}",
            "filename_enc": enc.filename_enc,
            "filename_iv": enc.filename_iv,
            "enc_file_size": meta.enc_file_size,
            "uploaded_at": enc.upload_timestamp.isoformat(),
            "transfer_frequency": meta.transfer_frequency,
            "anomaly_flagged": meta.anomaly_result.anomaly_flag if meta.anomaly_result else False,
            "anomaly_zscore": meta.anomaly_result.zscore_value if meta.anomaly_result else None,
            "anomaly_iqr": meta.anomaly_result.iqr_threshold if meta.anomaly_result else None,
        }
        for enc, meta in rows
    ]
    return jsonify({"files": files, "count": len(files)}), 200


@files_bp.route("/<int:file_id>", methods=["GET"])
@require_auth
def get_file(current_user, file_id):
    """
    Return the ciphertext + IV for one file so the client can decrypt it
    locally. Ownership is enforced: a user can only fetch their own files.
    """
    enc_file = EncryptedFile.query.filter_by(
        file_id=file_id, user_id=current_user.user_id
    ).first()
    if not enc_file:
        return jsonify({"error": "File not found"}), 404

    return jsonify({
        "file_id": enc_file.file_id,
        "filename": enc_file.filename or f"file_{enc_file.file_id}",
        "filename_enc": enc_file.filename_enc,
        "filename_iv": enc_file.filename_iv,
        "ciphertext": base64.b64encode(enc_file.encrypted_data).decode("ascii"),
        "iv": enc_file.iv,
        "salt": enc_file.salt or "",
    }), 200


@files_bp.route("/<int:file_id>", methods=["DELETE"])
@require_auth
def delete_file(current_user, file_id):
    """
    Permanently delete a file and all associated metadata/anomaly records.
    Only the owner may delete their own files.
    """
    enc_file = EncryptedFile.query.filter_by(
        file_id=file_id, user_id=current_user.user_id
    ).first()
    if not enc_file:
        return jsonify({"error": "File not found"}), 404

    # Cascade: remove share tokens, metadata, anomaly results, then the file
    ShareToken.query.filter_by(file_id=file_id).delete()
    if enc_file.metadata_record:
        from app.models import AnomalyResult
        AnomalyResult.query.filter_by(
            metadata_id=enc_file.metadata_record.metadata_id
        ).delete()
        db.session.delete(enc_file.metadata_record)
    db.session.delete(enc_file)
    db.session.commit()

    return jsonify({"message": "File deleted"}), 200


@files_bp.route("/<int:file_id>/dismiss-anomaly", methods=["PATCH"])
@require_auth
def dismiss_anomaly(current_user, file_id):
    """Owner marks an anomaly flag as expected, clearing the warning."""
    enc_file = EncryptedFile.query.filter_by(
        file_id=file_id, user_id=current_user.user_id
    ).first()
    if not enc_file:
        return jsonify({"error": "File not found"}), 404

    from app.models import AnomalyResult
    result = (
        AnomalyResult.query
        .filter_by(metadata_id=enc_file.metadata_record.metadata_id)
        .first()
    )
    if result:
        result.anomaly_flag = False
        db.session.commit()

    return jsonify({"message": "Anomaly dismissed"}), 200
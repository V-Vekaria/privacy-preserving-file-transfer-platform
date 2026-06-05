# app/routes/detection.py
from flask import Blueprint, jsonify, request
from app.middleware.auth import require_auth
from app.services.anomaly_service import analyse_metadata, batch_analyse
from app.models import Metadata

detection_bp = Blueprint("detection", __name__)


@detection_bp.route("/analyse", methods=["POST"])
@require_auth
def analyse(current_user):
    """
    Analyse a single metadata record.
    Body: { "metadata_id": <int> }
    FR7, FR8, FR9 — real-time detection trigger.
    """
    data = request.get_json(silent=True) or {}
    metadata_id = data.get("metadata_id")

    if not metadata_id:
        return jsonify({"error": "metadata_id is required"}), 400

    # Ownership check — user may only analyse their own records
    record = Metadata.query.filter_by(
        metadata_id=metadata_id, user_id=current_user.user_id
    ).first()
    if record is None:
        return jsonify({"error": "Metadata record not found"}), 404

    try:
        result = analyse_metadata(metadata_id)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404

    return jsonify(result), 200


@detection_bp.route("/batch", methods=["POST"])
@require_auth
def batch(current_user):
    """
    Re-run detection on all metadata records for the authenticated user.
    FR9 batch recalibration path.
    """
    results = batch_analyse(current_user.user_id)
    return jsonify({
        "user_id": current_user.user_id,
        "analysed": len(results),
        "results": results,
    }), 200
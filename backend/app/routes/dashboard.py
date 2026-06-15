"""
Dashboard routes — Week 6 (FR11).

Endpoint
--------
GET /api/dashboard/stats   -> aggregate stats, chart data, anomaly events

Zero-knowledge boundary
-----------------------
Only non-semantic metadata is returned (enc_file_size, timestamp, frequency).
No filenames, MIME types, or decryptable content is exposed.
"""

from datetime import datetime, timedelta, timezone
from flask import Blueprint, jsonify, request
from sqlalchemy import func
from app import db
from app.middleware.auth import require_auth
from app.models import Metadata, AnomalyResult, EncryptedFile

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/stats", methods=["GET"])
@require_auth
def stats(current_user):
    """
    Returns all data needed to render the FR11 dashboard:

    - stat_cards   : total uploads, flagged anomalies, average file size
    - frequency    : uploads-per-day for the last 30 days  (line chart)
    - size_dist    : enc_file_size buckets for all uploads (bar/histogram chart)
    - events       : recent anomaly events with Z-score and IQR label
    """
    uid = current_user.user_id

    # ── Stat cards ──────────────────────────────────────────────────────────
    total_uploads = Metadata.query.filter_by(user_id=uid).count()

    flagged_count = (
        db.session.query(func.count(AnomalyResult.result_id))
        .join(Metadata, Metadata.metadata_id == AnomalyResult.metadata_id)
        .filter(Metadata.user_id == uid, AnomalyResult.anomaly_flag.is_(True))
        .scalar()
    ) or 0

    avg_size_result = (
        db.session.query(func.avg(Metadata.enc_file_size))
        .filter(Metadata.user_id == uid)
        .scalar()
    )
    avg_file_size = round(avg_size_result, 0) if avg_size_result else 0

    # ── Upload frequency — last 30 days (FR6 / FR11) ────────────────────────
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    freq_rows = (
        db.session.query(
            func.date(Metadata.timestamp).label("day"),
            func.count(Metadata.metadata_id).label("count"),
        )
        .filter(Metadata.user_id == uid, Metadata.timestamp >= cutoff)
        .group_by(func.date(Metadata.timestamp))
        .order_by(func.date(Metadata.timestamp))
        .all()
    )
    frequency_chart = [{"date": str(r.day), "count": r.count} for r in freq_rows]

    # ── File-size distribution — bucket into 5 equal-width bins ─────────────
    all_sizes = [
        r.enc_file_size
        for r in Metadata.query.filter_by(user_id=uid)
        .with_entities(Metadata.enc_file_size)
        .all()
    ]
    size_dist = _bucket_sizes(all_sizes)

    # ── Anomaly events — most recent 50, ordered newest first ───────────────
    event_rows = (
        db.session.query(AnomalyResult, Metadata)
        .join(Metadata, Metadata.metadata_id == AnomalyResult.metadata_id)
        .filter(Metadata.user_id == uid)
        .order_by(AnomalyResult.detected_at.desc())
        .limit(50)
        .all()
    )
    events = [
        {
            "event_id": ar.result_id,
            "enc_file_size": meta.enc_file_size,
            "timestamp": meta.timestamp.isoformat(),
            "z_score": ar.zscore_value,
            "iqr_label": ar.iqr_threshold,
            "anomaly_flag": ar.anomaly_flag,
        }
        for ar, meta in event_rows
    ]

    return jsonify(
        {
            "stat_cards": {
                "total_uploads": total_uploads,
                "flagged_anomalies": flagged_count,
                "avg_file_size_bytes": int(avg_file_size),
            },
            "frequency_chart": frequency_chart,
            "size_distribution": size_dist,
            "anomaly_events": events,
        }
    ), 200


# ── Helpers ──────────────────────────────────────────────────────────────────

def _bucket_sizes(sizes: list[int], n_bins: int = 5) -> list[dict]:
    """
    Partition sizes into n_bins equal-width buckets for the histogram chart.
    Returns list of {label, count} dicts — empty list when no data.
    """
    if not sizes:
        return []

    min_s, max_s = min(sizes), max(sizes)
    if min_s == max_s:
        # All files identical in size — single bucket
        return [{"label": f"{_fmt(min_s)}", "count": len(sizes)}]

    width = (max_s - min_s) / n_bins
    buckets = [0] * n_bins
    for s in sizes:
        idx = min(int((s - min_s) / width), n_bins - 1)
        buckets[idx] += 1

    return [
        {
            "label": f"{_fmt(min_s + i * width)}–{_fmt(min_s + (i + 1) * width)}",
            "count": buckets[i],
        }
        for i in range(n_bins)
    ]


def _fmt(bytes_val: float) -> str:
    """Human-readable byte size label (KB / MB)."""
    if bytes_val >= 1_048_576:
        return f"{bytes_val / 1_048_576:.1f} MB"
    if bytes_val >= 1_024:
        return f"{bytes_val / 1_024:.1f} KB"
    return f"{int(bytes_val)} B"
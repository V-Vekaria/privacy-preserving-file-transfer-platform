# app/services/anomaly_service.py
import math
from app.models import db, Metadata, AnomalyResult


def _zscore(value: float, mean: float, std: float):
    """Z = (x - μ) / σ. Returns None if std is zero."""
    if std == 0:
        return None
    return (value - mean) / std


def _iqr_bounds(values: list) -> tuple:
    """Returns (lower_bound, upper_bound) using Q1 - 1.5*IQR, Q3 + 1.5*IQR."""
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    q1 = sorted_vals[n // 4]
    q3 = sorted_vals[(3 * n) // 4]
    iqr = q3 - q1
    return (q1 - 1.5 * iqr, q3 + 1.5 * iqr)


def analyse_metadata(metadata_id: int) -> dict:
    """
    Runs Z-score and IQR detection on a single Metadata record.
    Persists result to AnomalyResult. Returns detection summary dict.
    Covers FR7, FR8, FR9, FR10.
    """
    record = Metadata.query.filter_by(metadata_id=metadata_id).first()
    if record is None:
        raise ValueError(f"Metadata record {metadata_id} not found")

    # Fetch all enc_file_size values for this user to build the distribution
    all_records = Metadata.query.filter_by(user_id=record.user_id).all()
    sizes = [r.enc_file_size for r in all_records]

    flagged = False
    zscore_val = None
    iqr_flagged = False
    zscore_flagged = False

    if len(sizes) >= 2:
        mean = sum(sizes) / len(sizes)
        variance = sum((x - mean) ** 2 for x in sizes) / len(sizes)
        std = math.sqrt(variance)

        zscore_val = _zscore(record.enc_file_size, mean, std)
        zscore_flagged = zscore_val is not None and abs(zscore_val) > 2.0

        lower, upper = _iqr_bounds(sizes)
        iqr_flagged = record.enc_file_size < lower or record.enc_file_size > upper

        flagged = zscore_flagged or iqr_flagged

    # Upsert: remove existing result for this metadata record first
    existing = AnomalyResult.query.filter_by(metadata_id=metadata_id).first()
    if existing:
        db.session.delete(existing)
        db.session.flush()

    iqr_threshold_str = "exceeded" if iqr_flagged else "normal"

    result = AnomalyResult(
        metadata_id=metadata_id,
        anomaly_flag=flagged,
        zscore_value=round(zscore_val, 4) if zscore_val is not None else None,
        iqr_threshold=iqr_threshold_str,
    )
    db.session.add(result)
    db.session.commit()

    return {
        "metadata_id": metadata_id,
        "enc_file_size": record.enc_file_size,
        "is_flagged": flagged,
        "zscore": result.zscore_value,
        "iqr_flagged": iqr_flagged,
        "sample_size": len(sizes),
    }


def batch_analyse(user_id: int) -> list:
    """
    Re-runs detection on ALL metadata records for a user.
    Used for threshold recalibration (FR9 batch path).
    """
    records = Metadata.query.filter_by(user_id=user_id).all()
    return [analyse_metadata(r.metadata_id) for r in records]
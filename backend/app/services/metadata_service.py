"""
Metadata logging service — Week 3 (FR6).

Captures ONLY non-semantic, structured attributes about an upload:
    - encrypted file size (bytes of ciphertext, never plaintext size)
    - timestamp
    - transfer frequency (how many uploads this user made in a rolling 24h window)

Crucially, NO filename, MIME type, or content-derived value is ever stored.
This keeps metadata logging inside the zero-knowledge boundary while still
producing the numeric signals the Week 4 Z-score / IQR engine consumes.
"""

from datetime import datetime, timezone, timedelta
from app import db
from app.models import Metadata

# Rolling window over which "transfer frequency" is counted.
FREQUENCY_WINDOW_HOURS = 24


def _recent_transfer_count(user_id: int, now: datetime) -> int:
    """Number of uploads this user already logged within the rolling window."""
    window_start = now - timedelta(hours=FREQUENCY_WINDOW_HOURS)
    return (
        Metadata.query.filter(
            Metadata.user_id == user_id,
            Metadata.timestamp >= window_start,
        ).count()
    )


def log_metadata(user_id: int, file_id: int, enc_file_size: int) -> Metadata:
    """
    Create and persist a Metadata row for a freshly uploaded ciphertext.

    transfer_frequency = (uploads already in the last 24h) + 1, so the value
    reflects this upload's position in the user's recent activity. A sudden
    spike is exactly the kind of signal anomaly detection looks for.

    The caller is responsible for committing the surrounding transaction so
    the EncryptedFile row and its Metadata row commit together (atomicity).
    """
    now = datetime.now(timezone.utc)
    frequency = _recent_transfer_count(user_id, now) + 1

    record = Metadata(
        file_id=file_id,
        user_id=user_id,
        enc_file_size=enc_file_size,
        timestamp=now,
        transfer_frequency=frequency,
    )
    db.session.add(record)
    return record
"""
Tests for GET /api/dashboard/stats  (FR11).

Covers:
- 401 without auth token
- Empty state (new user, no uploads)
- Populated state: stat cards, frequency chart, size distribution, events
"""

import pytest
import json
from app import create_app, db
from app.models import User, EncryptedFile, Metadata, AnomalyResult
from datetime import datetime, timezone
import bcrypt


@pytest.fixture
def client():
    app = create_app("testing")
    with app.test_client() as c:
        with app.app_context():
            db.create_all()
            yield c
            db.session.remove()
            db.drop_all()


def _register_and_login(client):
    pw_hash = bcrypt.hashpw(b"Password1!", bcrypt.gensalt()).decode()
    app = client.application
    with app.app_context():
        user = User(username="dashuser", email="dash@test.com", password_hashed=pw_hash)
        db.session.add(user)
        db.session.commit()

    resp = client.post(
        "/api/auth/login",
        json={"username": "dashuser", "password": "Password1!"},
    )
    token = resp.get_json()["token"]
    return token


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


# ── Auth guard ──────────────────────────────────────────────────────────────

def test_stats_requires_auth(client):
    resp = client.get("/api/dashboard/stats")
    assert resp.status_code == 401


# ── Empty state ─────────────────────────────────────────────────────────────

def test_stats_empty(client):
    token = _register_and_login(client)
    resp = client.get("/api/dashboard/stats", headers=_auth(token))
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["stat_cards"]["total_uploads"] == 0
    assert data["stat_cards"]["flagged_anomalies"] == 0
    assert data["stat_cards"]["avg_file_size_bytes"] == 0
    assert data["frequency_chart"] == []
    assert data["size_distribution"] == []
    assert data["anomaly_events"] == []


# ── Populated state ─────────────────────────────────────────────────────────

def _seed_upload(app, user_id, size_bytes, flagged=False):
    """Insert one EncryptedFile + Metadata + AnomalyResult row."""
    with app.app_context():
        ef = EncryptedFile(
            user_id=user_id,
            encrypted_data=b"\x00" * min(size_bytes, 8),
            iv="aabbccdd11223344",
        )
        db.session.add(ef)
        db.session.flush()

        meta = Metadata(
            file_id=ef.file_id,
            user_id=user_id,
            enc_file_size=size_bytes,
            timestamp=datetime.now(timezone.utc),
            transfer_frequency=1,
        )
        db.session.add(meta)
        db.session.flush()

        ar = AnomalyResult(
            metadata_id=meta.metadata_id,
            anomaly_flag=flagged,
            zscore_value=3.5 if flagged else 0.2,
            iqr_threshold="exceeded" if flagged else "normal",
        )
        db.session.add(ar)
        db.session.commit()
        return meta.metadata_id


def test_stats_populated(client):
    token = _register_and_login(client)
    app = client.application

    # Resolve user_id inside an app context
    with app.app_context():
        from app.models import User as U
        uid = U.query.filter_by(username="dashuser").first().user_id

    _seed_upload(app, uid, 1024, flagged=False)
    _seed_upload(app, uid, 2048, flagged=True)
    _seed_upload(app, uid, 4096, flagged=False)

    resp = client.get("/api/dashboard/stats", headers=_auth(token))
    assert resp.status_code == 200
    data = resp.get_json()

    cards = data["stat_cards"]
    assert cards["total_uploads"] == 3
    assert cards["flagged_anomalies"] == 1
    # avg of 1024+2048+4096 = 7168/3 ≈ 2389
    assert cards["avg_file_size_bytes"] == pytest.approx(2389, abs=1)

    assert len(data["frequency_chart"]) >= 1
    assert len(data["size_distribution"]) >= 1

    events = data["anomaly_events"]
    assert len(events) == 3
    flagged_events = [e for e in events if e["anomaly_flag"]]
    assert len(flagged_events) == 1
    assert flagged_events[0]["iqr_label"] == "exceeded"


def test_stats_event_fields(client):
    token = _register_and_login(client)
    app = client.application

    with app.app_context():
        from app.models import User as U
        uid = U.query.filter_by(username="dashuser").first().user_id

    _seed_upload(app, uid, 512, flagged=True)

    resp = client.get("/api/dashboard/stats", headers=_auth(token))
    event = resp.get_json()["anomaly_events"][0]
    assert "enc_file_size" in event
    assert "timestamp" in event
    assert "z_score" in event
    assert "iqr_label" in event
    assert "anomaly_flag" in event


def test_stats_isolates_users(client):
    """User A's stats must not include User B's uploads."""
    app = client.application

    # Register User B separately
    pw_hash = bcrypt.hashpw(b"Password1!", bcrypt.gensalt()).decode()
    with app.app_context():
        user_b = User(username="userB", email="b@test.com", password_hashed=pw_hash)
        db.session.add(user_b)
        db.session.commit()
        uid_b = user_b.user_id

    _seed_upload(app, uid_b, 99999, flagged=True)

    token_a = _register_and_login(client)
    resp = client.get("/api/dashboard/stats", headers=_auth(token_a))
    data = resp.get_json()
    assert data["stat_cards"]["total_uploads"] == 0
    assert data["stat_cards"]["flagged_anomalies"] == 0
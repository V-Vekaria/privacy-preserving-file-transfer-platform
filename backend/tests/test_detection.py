# tests/test_detection.py
import pytest
from app import create_app
from app.models import db, User, Metadata, EncryptedFile, AnomalyResult
from app.services.anomaly_service import analyse_metadata, _zscore, _iqr_bounds


# ---------------------------------------------------------------------------
# Shared app — one in-memory DB for the whole module
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def app():
    _app = create_app("testing")
    with _app.app_context():
        db.create_all()
        # Register the test user once here, inside the app context
        from app.routes.auth import _hash_password
        user = User(
            username="detectionuser",
            email="detection@test.com",
            password_hashed=_hash_password("TestPass123!")
        )
        db.session.add(user)
        db.session.commit()
        yield _app
        db.session.remove()
        db.drop_all()


@pytest.fixture(scope="module")
def client(app):
    return app.test_client()


@pytest.fixture(scope="module")
def auth_token(app, client):
    """Login and return the raw token string."""
    resp = client.post("/api/auth/login", json={
        "username": "detectionuser",
        "password": "TestPass123!"
    })
    assert resp.status_code == 200, f"Login failed: {resp.get_json()}"
    return resp.get_json()["token"]


@pytest.fixture(scope="module")
def auth_headers(auth_token):
    return {"Authorization": f"Bearer {auth_token}"}


@pytest.fixture(scope="module")
def seeded_metadata(app, auth_headers):
    """
    Insert 10 normal + 1 outlier metadata records for detectionuser.
    Runs once per module. Returns the outlier metadata_id.
    """
    with app.app_context():
        user = User.query.filter_by(username="detectionuser").first()

        normal_sizes = [1_000_000, 1_100_000, 950_000, 1_050_000,
                        1_020_000, 980_000, 1_030_000, 1_010_000,
                        990_000, 1_040_000]

        for size in normal_sizes:
            ef = EncryptedFile(
                user_id=user.user_id,
                encrypted_data=b"dummy",
                iv="aabbccdd" * 4
            )
            db.session.add(ef)
            db.session.flush()
            m = Metadata(
                file_id=ef.file_id,
                user_id=user.user_id,
                enc_file_size=size,
                transfer_frequency=1
            )
            db.session.add(m)

        # Outlier — 50MB when typical is ~1MB
        ef_out = EncryptedFile(
            user_id=user.user_id,
            encrypted_data=b"dummy",
            iv="aabbccdd" * 4
        )
        db.session.add(ef_out)
        db.session.flush()
        outlier = Metadata(
            file_id=ef_out.file_id,
            user_id=user.user_id,
            enc_file_size=50_000_000,
            transfer_frequency=1
        )
        db.session.add(outlier)
        db.session.commit()

        return outlier.metadata_id


# ---------------------------------------------------------------------------
# Unit tests — pure functions, no DB needed
# ---------------------------------------------------------------------------

def test_zscore_calculation():
    """FR7 — Z-score matches manual calculation."""
    z = _zscore(10.0, 5.0, 2.0)
    assert abs(z - 2.5) < 1e-9


def test_zscore_zero_std_returns_none():
    """Z-score returns None when all values are identical (std=0)."""
    assert _zscore(5.0, 5.0, 0.0) is None


def test_iqr_bounds():
    """FR8 — IQR bounds match manual calculation."""
    values = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    lower, upper = _iqr_bounds(values)
    assert lower < 1
    assert upper > 10


def test_iqr_flags_outlier():
    """IQR correctly identifies an extreme value as outside bounds."""
    values = [1_000_000] * 9 + [50_000_000]
    lower, upper = _iqr_bounds(values)
    assert 50_000_000 > upper


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------

def test_analyse_flags_outlier(app, seeded_metadata):
    """FR9 — outlier metadata record is flagged after analysis."""
    with app.app_context():
        result = analyse_metadata(seeded_metadata)
        assert result["is_flagged"] is True
        assert result["zscore"] is not None
        assert result["zscore"] > 2.0


def test_analyse_persists_result(app, seeded_metadata):
    """FR10 — AnomalyResult row is written to the database."""
    with app.app_context():
        analyse_metadata(seeded_metadata)
        ar = AnomalyResult.query.filter_by(metadata_id=seeded_metadata).first()
        assert ar is not None
        assert ar.anomaly_flag is True


def test_analyse_endpoint_returns_200(client, auth_headers, seeded_metadata):
    """POST /api/detection/analyse returns 200 with correct shape."""
    resp = client.post("/api/detection/analyse",
                       json={"metadata_id": seeded_metadata},
                       headers=auth_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert "is_flagged" in data
    assert "zscore" in data
    assert "iqr_flagged" in data


def test_analyse_endpoint_missing_id(client, auth_headers):
    """POST /api/detection/analyse with no metadata_id returns 400."""
    resp = client.post("/api/detection/analyse",
                       json={},
                       headers=auth_headers)
    assert resp.status_code == 400


def test_analyse_endpoint_wrong_owner(client, app, seeded_metadata):
    """User cannot analyse another user's metadata record — returns 404."""
    # Create second user directly in DB
    with app.app_context():
        from app.routes.auth import _hash_password
        other = User(
            username="otheruser",
            email="other@test.com",
            password_hashed=_hash_password("TestPass123!")
        )
        db.session.add(other)
        db.session.commit()

    resp = client.post("/api/auth/login", json={
        "username": "otheruser",
        "password": "TestPass123!"
    })
    other_token = resp.get_json()["token"]
    other_headers = {"Authorization": f"Bearer {other_token}"}

    resp = client.post("/api/detection/analyse",
                       json={"metadata_id": seeded_metadata},
                       headers=other_headers)
    assert resp.status_code == 404


def test_batch_endpoint(client, auth_headers, seeded_metadata):
    """POST /api/detection/batch analyses all records and returns count."""
    resp = client.post("/api/detection/batch", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["analysed"] == 11  # 10 normal + 1 outlier
    assert "results" in data


def test_analyse_unauthenticated(client, seeded_metadata):
    """No JWT token returns 401."""
    resp = client.post("/api/detection/analyse",
                       json={"metadata_id": seeded_metadata})
    assert resp.status_code == 401
"""
Week 3 — file upload, metadata logging, and retrieval tests.

Each test maps to a functional requirement so the suite doubles as
traceable evidence for the AT3 code walkthrough.
"""

import base64
import pytest
from app import create_app, db
from app.models import EncryptedFile, Metadata


@pytest.fixture
def client():
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        with app.test_client() as c:
            yield c
        db.session.remove()
        db.drop_all()


def _register_and_token(client, username="alice"):
    resp = client.post("/api/auth/register", json={
        "username": username,
        "email": f"{username}@example.com",
        "password": "Sup3rSecret!",
    })
    return resp.get_json()["token"]


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _sample_payload(plaintext=b"hello zero-knowledge world"):
    # Simulate the client: the "ciphertext" is opaque bytes to the server.
    return {
        "ciphertext": base64.b64encode(plaintext).decode("ascii"),
        "iv": base64.b64encode(b"123456789012").decode("ascii"),  # 12-byte IV
    }


# --- FR3 / FR5: upload stores ciphertext ----------------------------------
def test_upload_requires_auth(client):
    resp = client.post("/api/files/upload", json=_sample_payload())
    assert resp.status_code == 401


def test_upload_succeeds_and_returns_metadata(client):
    token = _register_and_token(client)
    resp = client.post("/api/files/upload", json=_sample_payload(), headers=_auth(token))
    assert resp.status_code == 201
    body = resp.get_json()
    assert body["file_id"] >= 1
    assert body["metadata"]["enc_file_size"] > 0
    assert body["metadata"]["transfer_frequency"] == 1


def test_upload_rejects_non_base64_ciphertext(client):
    token = _register_and_token(client)
    bad = {"ciphertext": "!!!not-base64!!!", "iv": "abc"}
    resp = client.post("/api/files/upload", json=bad, headers=_auth(token))
    assert resp.status_code == 400


def test_upload_rejects_missing_fields(client):
    token = _register_and_token(client)
    resp = client.post("/api/files/upload", json={"iv": "abc"}, headers=_auth(token))
    assert resp.status_code == 400


# --- FR4 / FR5: zero-knowledge — server stores only what the client sent ---
def test_server_stores_exact_ciphertext_no_plaintext(client):
    token = _register_and_token(client)
    secret = b"this plaintext must never appear in the DB"
    payload = _sample_payload(secret)
    client.post("/api/files/upload", json=payload, headers=_auth(token))

    stored = EncryptedFile.query.first()
    # The stored bytes equal the base64-decoded ciphertext the client sent...
    assert stored.encrypted_data == base64.b64decode(payload["ciphertext"])
    # ...and there is no key column anywhere on the model.
    assert not hasattr(stored, "key")
    assert not hasattr(stored, "encryption_key")


# --- FR6: metadata logging is non-semantic ---------------------------------
def test_metadata_holds_no_filename_or_content_fields(client):
    token = _register_and_token(client)
    client.post("/api/files/upload", json=_sample_payload(), headers=_auth(token))

    meta = Metadata.query.first()
    cols = {c.name for c in meta.__table__.columns}
    # Only non-semantic structured attributes — no filename / mimetype.
    assert "filename" not in cols
    assert "mimetype" not in cols
    assert {"enc_file_size", "timestamp", "transfer_frequency"} <= cols


def test_transfer_frequency_increments_within_window(client):
    token = _register_and_token(client)
    for expected in (1, 2, 3):
        resp = client.post(
            "/api/files/upload", json=_sample_payload(), headers=_auth(token)
        )
        assert resp.get_json()["metadata"]["transfer_frequency"] == expected


# --- listing + retrieval ---------------------------------------------------
def test_list_returns_metadata_only(client):
    token = _register_and_token(client)
    client.post("/api/files/upload", json=_sample_payload(), headers=_auth(token))

    resp = client.get("/api/files", headers=_auth(token))
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["count"] == 1
    entry = body["files"][0]
    # Listing must NOT leak ciphertext or IV.
    assert "ciphertext" not in entry
    assert "iv" not in entry


def test_get_file_returns_ciphertext_and_iv(client):
    token = _register_and_token(client)
    payload = _sample_payload()
    up = client.post("/api/files/upload", json=payload, headers=_auth(token))
    file_id = up.get_json()["file_id"]

    resp = client.get(f"/api/files/{file_id}", headers=_auth(token))
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["ciphertext"] == payload["ciphertext"]
    assert body["iv"] == payload["iv"]


def test_user_cannot_access_another_users_file(client):
    alice_token = _register_and_token(client, "alice")
    up = client.post("/api/files/upload", json=_sample_payload(), headers=_auth(alice_token))
    alice_file_id = up.get_json()["file_id"]

    bob_token = _register_and_token(client, "bob")
    resp = client.get(f"/api/files/{alice_file_id}", headers=_auth(bob_token))
    assert resp.status_code == 404  # ownership enforced
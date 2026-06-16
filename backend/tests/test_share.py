"""Share token tests — creation, retrieval, expiry, and ownership."""

import base64
import pytest
from app import create_app, db
from app.models import ShareToken


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


def _upload(client, token):
    payload = {
        "ciphertext": base64.b64encode(b"fake ciphertext").decode(),
        "iv": base64.b64encode(b"123456789012").decode(),
    }
    resp = client.post("/api/files/upload", json=payload, headers=_auth(token))
    return resp.get_json()["file_id"]


def _wrapped_key_body():
    return {
        "wrapped_key": base64.b64encode(b"fakewrappedkey" * 3).decode(),
        "share_salt": base64.b64encode(b"fakesalt12345678").decode(),
        "share_iv": "aabbccdd" * 3,
    }


# --- token creation ---

def test_create_share_token_requires_auth(client):
    token = _register_and_token(client)
    file_id = _upload(client, token)
    resp = client.post(f"/api/share/{file_id}", json=_wrapped_key_body())
    assert resp.status_code == 401


def test_create_share_token_success(client):
    token = _register_and_token(client)
    file_id = _upload(client, token)
    resp = client.post(f"/api/share/{file_id}", json=_wrapped_key_body(), headers=_auth(token))
    assert resp.status_code == 201
    body = resp.get_json()
    assert "token" in body
    assert "expires_at" in body
    assert len(body["token"]) == 32  # uuid4().hex


def test_create_share_stores_wrapped_key(client):
    token = _register_and_token(client)
    file_id = _upload(client, token)
    body_in = _wrapped_key_body()
    client.post(f"/api/share/{file_id}", json=body_in, headers=_auth(token))

    share = ShareToken.query.first()
    assert share.wrapped_key == body_in["wrapped_key"]
    assert share.share_salt == body_in["share_salt"]
    assert share.share_iv == body_in["share_iv"]


def test_owner_cannot_share_another_users_file(client):
    alice = _register_and_token(client, "alice")
    bob = _register_and_token(client, "bob")
    file_id = _upload(client, alice)
    resp = client.post(f"/api/share/{file_id}", json=_wrapped_key_body(), headers=_auth(bob))
    assert resp.status_code == 404


# --- token retrieval ---

def test_download_shared_returns_ciphertext_and_wrapped_key(client):
    token = _register_and_token(client)
    file_id = _upload(client, token)
    body_in = _wrapped_key_body()
    share_resp = client.post(f"/api/share/{file_id}", json=body_in, headers=_auth(token))
    share_token = share_resp.get_json()["token"]

    resp = client.get(f"/api/share/{share_token}")
    assert resp.status_code == 200
    body = resp.get_json()
    assert "ciphertext" in body
    assert "iv" in body
    assert body["wrapped_key"] == body_in["wrapped_key"]
    assert body["share_salt"] == body_in["share_salt"]
    assert body["share_iv"] == body_in["share_iv"]


def test_download_shared_no_auth_required(client):
    token = _register_and_token(client)
    file_id = _upload(client, token)
    share_resp = client.post(f"/api/share/{file_id}", json=_wrapped_key_body(), headers=_auth(token))
    share_token = share_resp.get_json()["token"]

    # No Authorization header — should still work
    resp = client.get(f"/api/share/{share_token}")
    assert resp.status_code == 200


def test_invalid_share_token_returns_404(client):
    resp = client.get("/api/share/nonexistenttoken123")
    assert resp.status_code == 404


# --- revocation ---

def test_owner_can_revoke_share_token(client):
    token = _register_and_token(client)
    file_id = _upload(client, token)
    share_resp = client.post(f"/api/share/{file_id}", json=_wrapped_key_body(), headers=_auth(token))
    share_token = share_resp.get_json()["token"]

    revoke = client.delete(f"/api/share/{share_token}", headers=_auth(token))
    assert revoke.status_code == 200

    resp = client.get(f"/api/share/{share_token}")
    assert resp.status_code == 404


def test_non_owner_cannot_revoke_share_token(client):
    alice = _register_and_token(client, "alice")
    bob = _register_and_token(client, "bob")
    file_id = _upload(client, alice)
    share_resp = client.post(f"/api/share/{file_id}", json=_wrapped_key_body(), headers=_auth(alice))
    share_token = share_resp.get_json()["token"]

    resp = client.delete(f"/api/share/{share_token}", headers=_auth(bob))
    assert resp.status_code == 404

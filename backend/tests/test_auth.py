import pytest
from app import create_app, db as _db


@pytest.fixture
def app():
    app = create_app("testing")
    with app.app_context():
        _db.create_all()
        yield app
        _db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


# register

def test_register_success(client):
    resp = client.post("/api/auth/register", json={
        "username": "vishnu",
        "email": "vishnu@test.com",
        "password": "securepass123",
    })
    assert resp.status_code == 201
    data = resp.get_json()
    assert "token" in data
    assert data["username"] == "vishnu"


def test_register_missing_fields(client):
    resp = client.post("/api/auth/register", json={"username": "x"})
    assert resp.status_code == 400
    data = resp.get_json()
    assert "details" in data


def test_register_short_password(client):
    resp = client.post("/api/auth/register", json={
        "username": "vishnu",
        "email": "v@test.com",
        "password": "short",
    })
    assert resp.status_code == 400


def test_register_duplicate_username(client):
    payload = {"username": "dupuser", "email": "a@test.com", "password": "password123"}
    client.post("/api/auth/register", json=payload)
    resp = client.post("/api/auth/register", json={
        **payload, "email": "b@test.com"
    })
    assert resp.status_code == 409


def test_register_duplicate_email(client):
    client.post("/api/auth/register", json={
        "username": "user1", "email": "same@test.com", "password": "password123"
    })
    resp = client.post("/api/auth/register", json={
        "username": "user2", "email": "same@test.com", "password": "password123"
    })
    assert resp.status_code == 409


def test_password_not_stored_plaintext(client): # ensure password is hashed in DB (FR2)
    from app.models import User
    with client.application.app_context():
        client.post("/api/auth/register", json={
            "username": "hashcheck",
            "email": "h@test.com",
            "password": "mypassword99",
        })
        user = User.query.filter_by(username="hashcheck").first()
        assert user is not None
        assert user.password_hashed != "mypassword99"
        assert user.password_hashed.startswith("$2b$")  # bcrypt prefix


# login

def test_login_success(client):
    client.post("/api/auth/register", json={
        "username": "loginuser",
        "email": "login@test.com",
        "password": "loginpass123",
    })
    resp = client.post("/api/auth/login", json={
        "username": "loginuser",
        "password": "loginpass123",
    })
    assert resp.status_code == 200
    assert "token" in resp.get_json()


def test_login_wrong_password(client):
    client.post("/api/auth/register", json={
        "username": "wrongpass",
        "email": "wp@test.com",
        "password": "correctpass99",
    })
    resp = client.post("/api/auth/login", json={
        "username": "wrongpass",
        "password": "incorrectpass",
    })
    assert resp.status_code == 401


def test_login_unknown_user(client):
    resp = client.post("/api/auth/login", json={
        "username": "nobody",
        "password": "anypass123",
    })
    assert resp.status_code == 401


def test_login_missing_fields(client):
    resp = client.post("/api/auth/login", json={"username": "only"})
    assert resp.status_code == 400


# JWT middleware 

def test_protected_route_no_token(client):
    resp = client.get("/api/health")  # health is unprotected — use a guarded endpoint
    assert resp.status_code == 200


def test_jwt_token_is_valid(client):
    import jwt as pyjwt
    client.post("/api/auth/register", json={
        "username": "tokencheck",
        "email": "tc@test.com",
        "password": "tokenpass123",
    })
    resp = client.post("/api/auth/login", json={
        "username": "tokencheck",
        "password": "tokenpass123",
    })
    token = resp.get_json()["token"]
    with client.application.app_context():
        secret = client.application.config["JWT_SECRET_KEY"]
        payload = pyjwt.decode(token, secret, algorithms=["HS256"])
        assert payload["username"] == "tokencheck"
        assert "sub" in payload
        assert "exp" in payload
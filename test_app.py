import pytest
import app as auth_app


@pytest.fixture()
def client():
    auth_app.USERS.clear()
    auth_app.LOGIN_ATTEMPTS.clear()
    auth_app.app.config.update(TESTING=True, SECRET_KEY="test-secret-key")
    with auth_app.app.test_client() as client:
        yield client


def register(client, username="student_1", password="correct horse battery"):
    return client.post("/register", json={"username": username, "password": password})


def login(client, username="student_1", password="correct horse battery"):
    return client.post("/login", json={"username": username, "password": password})


def test_register_hashes_password(client):
    response = register(client)
    assert response.status_code == 201
    stored = auth_app.USERS["student_1"]["password_hash"]
    assert stored != "correct horse battery"
    assert stored.startswith("scrypt:")


def test_rejects_weak_password_and_invalid_username(client):
    assert client.post("/register", json={"username": "ab", "password": "short"}).status_code == 400
    assert client.post("/register", json={"username": "valid_user", "password": "tiny"}).status_code == 400


def test_login_and_protected_profile(client):
    assert register(client).status_code == 201
    assert client.get("/me").status_code == 401
    assert login(client).status_code == 200
    response = client.get("/me")
    assert response.status_code == 200
    assert response.json["username"] == "student_1"


def test_generic_login_error_for_unknown_user_and_wrong_password(client):
    register(client)
    wrong = login(client, password="incorrect password here")
    unknown = login(client, username="unknown_user", password="incorrect password here")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json["error"] == unknown.json["error"] == "Invalid username or password."


def test_rate_limit_after_five_failed_attempts(client):
    register(client)
    for _ in range(auth_app.RATE_LIMIT_MAX):
        response = login(client, password="wrong password value")
        assert response.status_code == 401
    blocked = login(client, password="wrong password value")
    assert blocked.status_code == 429


def test_logout_clears_session(client):
    register(client)
    login(client)
    assert client.get("/me").status_code == 200
    assert client.post("/logout").status_code == 200
    assert client.get("/me").status_code == 401


def test_security_headers_present(client):
    response = client.get("/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Cache-Control"] == "no-store"


def test_cookie_configuration(client):
    assert auth_app.app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert auth_app.app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert auth_app.app.config["PERMANENT_SESSION_LIFETIME"].total_seconds() == 900

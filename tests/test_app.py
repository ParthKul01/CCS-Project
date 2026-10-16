import re
import time

import pyotp
import pytest

from app import create_app, TOTP_INTERVAL, MAX_FAILED_ATTEMPTS

PASSWORD = "Str0ng!Pass"


@pytest.fixture
def app(tmp_path):
    return create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret",
        "DATABASE": str(tmp_path / "test.db"),
        "BCRYPT_ROUNDS": 4,
        "WTF_CSRF_ENABLED": False,
        "RATELIMIT_ENABLED": False,
    })


@pytest.fixture
def client(app):
    return app.test_client()


def register(client, username="alice", password=PASSWORD, confirm=None):
    return client.post("/register", data={
        "username": username, "password": password,
        "confirm": password if confirm is None else confirm})


def pending_secret(client):
    with client.session_transaction() as s:
        return s["pending_secret"]


def code_for(secret, offset=0):
    step = int(time.time() // TOTP_INTERVAL) + offset
    return pyotp.TOTP(secret).generate_otp(step)


def full_signup(client, username="alice"):
    """Register + enrol authenticator. Returns the TOTP secret."""
    register(client, username)
    client.get("/setup-mfa")  # browser follows the redirect
    secret = pending_secret(client)
    r = client.post("/setup-mfa", data={"otp": code_for(secret)})
    assert r.status_code == 302 and r.headers["Location"].endswith("/dashboard")
    client.post("/logout")
    return secret


def test_pages_load(client):
    assert client.get("/login").status_code == 200
    assert client.get("/register").status_code == 200
    assert client.get("/").status_code == 302
    assert client.get("/nope").status_code == 404


def test_dashboard_requires_login(client):
    r = client.get("/dashboard")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_otp_page_requires_password_step(client):
    r = client.get("/verify-otp")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_setup_page_requires_registration_or_login(client):
    r = client.get("/setup-mfa")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


@pytest.mark.parametrize("bad", ["Sh0rt!A", "alllowercase1!", "ALLUPPERCASE1!",
                                 "NoDigits!!!", "NoSpecial123"])
def test_weak_passwords_rejected(client, bad):
    r = register(client, password=bad)
    assert r.status_code == 400


def test_password_mismatch_and_bad_username(client):
    assert register(client, confirm="Different1!").status_code == 400
    assert register(client, username="a b").status_code == 400


def test_duplicate_username_rejected(client):
    register(client)
    client.get("/logout")
    with client.session_transaction() as s:
        s.clear()
    assert register(client, username="ALICE").status_code == 409


def test_password_is_hashed_with_bcrypt(app, client):
    register(client)
    import sqlite3
    row = sqlite3.connect(app.config["DATABASE"]).execute(
        "SELECT password_hash FROM users").fetchone()
    assert row[0].startswith(b"$2b$") and PASSWORD.encode() not in row[0]


def test_setup_shows_qr_and_rejects_wrong_code(client):
    register(client)
    page = client.get("/setup-mfa")
    assert b"data:image/png;base64," in page.data
    r = client.post("/setup-mfa", data={"otp": "000000"})
    assert r.status_code == 200 and b"Invalid code" in r.data


def test_full_login_flow(client):
    secret = full_signup(client)
    r = client.post("/login", data={"username": "alice", "password": PASSWORD})
    assert r.status_code == 302 and r.headers["Location"].endswith("/verify-otp")
    # Dashboard must still be blocked after only the password step.
    assert client.get("/dashboard").status_code == 302
    # Next time step avoids the replay rule (the setup code used the current one).
    r = client.post("/verify-otp", data={"otp": code_for(secret, offset=1)})
    assert r.status_code == 302 and r.headers["Location"].endswith("/dashboard")
    page = client.get("/dashboard")
    assert page.status_code == 200 and b"alice" in page.data
    assert b"login_success" in page.data


def test_wrong_password_generic_error(client):
    full_signup(client)
    r = client.post("/login", data={"username": "alice", "password": "Wrong!Pass1"})
    assert r.status_code == 401 and b"Invalid username or password" in r.data
    r = client.post("/login", data={"username": "ghost", "password": "Wrong!Pass1"})
    assert r.status_code == 401 and b"Invalid username or password" in r.data


def test_wrong_otp_rejected(client):
    secret = full_signup(client)
    client.post("/login", data={"username": "alice", "password": PASSWORD})
    good = code_for(secret, offset=1)
    bad = "000000" if good != "000000" else "111111"
    r = client.post("/verify-otp", data={"otp": bad})
    assert r.status_code == 401
    assert client.get("/dashboard").status_code == 302
    assert client.post("/verify-otp", data={"otp": "abc"}).status_code == 401


def test_otp_replay_rejected(client):
    secret = full_signup(client)
    used = code_for(secret)  # same step consumed during setup
    client.post("/login", data={"username": "alice", "password": PASSWORD})
    r = client.post("/verify-otp", data={"otp": used})
    assert r.status_code == 401


def test_otp_cannot_be_reused_after_login(client):
    secret = full_signup(client)
    code = code_for(secret, offset=1)
    client.post("/login", data={"username": "alice", "password": PASSWORD})
    assert client.post("/verify-otp", data={"otp": code}).status_code == 302
    client.post("/logout")
    client.post("/login", data={"username": "alice", "password": PASSWORD})
    assert client.post("/verify-otp", data={"otp": code}).status_code == 401


def test_old_code_outside_window_rejected(client):
    secret = full_signup(client)
    client.post("/login", data={"username": "alice", "password": PASSWORD})
    r = client.post("/verify-otp", data={"otp": code_for(secret, offset=-5)})
    assert r.status_code == 401


def test_account_lockout_after_failed_passwords(client):
    full_signup(client)
    for _ in range(MAX_FAILED_ATTEMPTS):
        client.post("/login", data={"username": "alice", "password": "Wrong!Pass1"})
    r = client.post("/login", data={"username": "alice", "password": PASSWORD})
    assert r.status_code == 403 and b"locked" in r.data


def test_account_lockout_after_failed_otps(client):
    secret = full_signup(client)
    good = code_for(secret, offset=1)
    bad = "000000" if good != "000000" else "111111"
    client.post("/login", data={"username": "alice", "password": PASSWORD})
    for _ in range(MAX_FAILED_ATTEMPTS):
        client.post("/verify-otp", data={"otp": bad})
    r = client.post("/login", data={"username": "alice", "password": PASSWORD})
    assert r.status_code == 403


def test_login_user_without_mfa_is_sent_to_setup(client):
    register(client)
    with client.session_transaction() as s:
        s.clear()
    r = client.post("/login", data={"username": "alice", "password": PASSWORD})
    assert r.status_code == 302 and r.headers["Location"].endswith("/setup-mfa")


def test_logout_requires_post_and_clears_session(client):
    full_signup(client)
    client.post("/login", data={"username": "alice", "password": PASSWORD})
    assert client.get("/logout").status_code == 405


def test_security_headers_present(client):
    r = client.get("/login")
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert r.headers["Cache-Control"] == "no-store"


def test_csrf_enforced_when_enabled(tmp_path):
    app = create_app({
        "TESTING": True, "SECRET_KEY": "k", "BCRYPT_ROUNDS": 4,
        "DATABASE": str(tmp_path / "c.db"), "RATELIMIT_ENABLED": False})
    c = app.test_client()
    r = c.post("/login", data={"username": "a", "password": "b"})
    assert r.status_code == 400
    page = c.get("/login").get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    r = c.post("/login", data={"username": "a", "password": "b", "csrf_token": token})
    assert r.status_code == 401


def test_rate_limiting_blocks_burst(tmp_path):
    app = create_app({
        "TESTING": True, "SECRET_KEY": "k", "BCRYPT_ROUNDS": 4,
        "DATABASE": str(tmp_path / "r.db"), "WTF_CSRF_ENABLED": False})
    c = app.test_client()
    codes = [c.post("/login", data={"username": "x", "password": "y"}).status_code
             for _ in range(12)]
    assert 429 in codes

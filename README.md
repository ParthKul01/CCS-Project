# MFA Login System (Password + TOTP)

Mini project for CCS (Unit III: Authentication and Network Security).
Python + Flask. Login needs a password **and** a 6-digit code from an authenticator app.

## Features
- Registration with password-strength rules
- Passwords hashed with **bcrypt** (unique salt per user)
- **TOTP** (RFC 6238, 30 s codes) via **PyOTP**; QR code enrolment via `qrcode`
- Two-step login: password, then OTP. Dashboard is blocked until both pass
- Replay protection: a used OTP cannot be reused
- Account lockout: 5 failed attempts locks the account for 5 minutes
- Rate limiting (Flask-Limiter) and CSRF protection (Flask-WTF)
- Security headers (CSP, X-Frame-Options, nosniff, no-store)
- Generic login errors (no username enumeration), constant-time OTP compare
- Activity log (login success/failure, lockouts) shown on the dashboard
- SQLite storage with parameterised queries (no SQL injection)

## Setup
```bash
cd mfa_login_system
python -m venv venv
# Windows:  venv\Scripts\activate
# Linux/Mac: source venv/bin/activate
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000

## How to use
1. Click **Create one**, register with a strong password.
2. Scan the QR code with Google Authenticator / Microsoft Authenticator / Authy.
3. Enter the 6-digit code to enable MFA (you are then logged in).
4. Log out, log in again: password first, then the current code.

Note: each code works once. If you log in right after setup, wait for the next code.

## Run tests
```bash
python -m pytest -q
```
26 tests cover registration, password rules, full MFA flow, wrong/expired/replayed OTP,
lockout, CSRF, rate limiting and security headers.

## Project structure
```
app.py              Flask app (routes, bcrypt, TOTP, lockout, logging)
templates/          HTML pages (Jinja2)
static/style.css    Minimal styling
tests/test_app.py   Automated tests
requirements.txt    Dependencies
instance/           Created at first run: mfa.db and secret_key (do not share)
```

## Security testing (for the report)
- **OWASP ZAP**: run an automated scan against http://127.0.0.1:5000 and note findings
- **Postman**: test `/login` and `/verify-otp` with wrong data to show 401/403/429 responses
- **Wireshark**: capture traffic on localhost to show why HTTPS is needed in production

## Configuration (optional)
- `SECRET_KEY` env var: session signing key (auto-generated into `instance/` if not set)
- `COOKIE_SECURE=1`: set when serving over HTTPS
- `FLASK_DEBUG=1`: debug mode (development only)

## Limitations / future work
- TOTP secrets are stored in plain text in SQLite; encrypt them at rest in production
- No backup/recovery codes or password reset
- Run behind HTTPS (e.g., Nginx) and use Redis for rate-limit storage in production

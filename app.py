import os
import time
from collections import defaultdict, deque
from datetime import timedelta
from functools import wraps

from flask import Flask, jsonify, request, session
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "dev-only-change-this-secret-before-deployment"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
    SESSION_REFRESH_EACH_REQUEST=False,
)

# Demo-only in-memory storage. Use a real database and shared rate-limit store in production.
USERS = {}
LOGIN_ATTEMPTS = defaultdict(deque)
RATE_LIMIT_MAX = 5
RATE_LIMIT_WINDOW_SECONDS = 60


def clean_old_attempts(key, now=None):
    now = time.time() if now is None else now
    attempts = LOGIN_ATTEMPTS[key]
    while attempts and now - attempts[0] >= RATE_LIMIT_WINDOW_SECONDS:
        attempts.popleft()


def too_many_attempts(key, now=None):
    clean_old_attempts(key, now)
    return len(LOGIN_ATTEMPTS[key]) >= RATE_LIMIT_MAX


def record_failed_attempt(key, now=None):
    LOGIN_ATTEMPTS[key].append(time.time() if now is None else now)


def valid_username(username):
    return (
        isinstance(username, str)
        and 3 <= len(username) <= 32
        and username.isascii()
        and username.replace("_", "").isalnum()
    )


def valid_password(password):
    return isinstance(password, str) and 12 <= len(password) <= 128


def json_error(message, status):
    return jsonify({"error": message}), status


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.post("/register")
def register():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return json_error("Invalid request.", 400)
    username = data.get("username")
    password = data.get("password")
    if not valid_username(username) or not valid_password(password):
        return json_error(
            "Use a username of 3-32 ASCII letters/numbers/underscores and a password of 12-128 characters.",
            400,
        )
    username_key = username.lower()
    if username_key in USERS:
        # Avoid revealing account details beyond the registration response.
        return json_error("Unable to create account with those details.", 409)
    USERS[username_key] = {
        "username": username,
        "password_hash": generate_password_hash(password, method="scrypt"),
    }
    return jsonify({"message": "Account created."}), 201


@app.post("/login")
def login():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return json_error("Invalid request.", 400)
    username = data.get("username")
    password = data.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        return json_error("Invalid username or password.", 401)

    key = username.lower()[:64]
    now = time.time()
    if too_many_attempts(key, now):
        return json_error("Too many attempts. Try again later.", 429)

    user = USERS.get(key)
    # Check a fixed dummy hash for unknown accounts to reduce obvious timing differences.
    dummy_hash = generate_password_hash("not-a-real-user-password", method="scrypt")
    stored_hash = user["password_hash"] if user else dummy_hash
    password_ok = check_password_hash(stored_hash, password)
    if user is None or not password_ok:
        record_failed_attempt(key, now)
        return json_error("Invalid username or password.", 401)

    LOGIN_ATTEMPTS.pop(key, None)
    session.clear()  # Prevent session fixation; establish a fresh authenticated session.
    session.permanent = True
    session["username"] = user["username"]
    return jsonify({"message": "Login successful."}), 200


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            return json_error("Authentication required.", 401)
        return view(*args, **kwargs)
    return wrapped


@app.get("/me")
@login_required
def me():
    return jsonify({"username": session["username"]}), 200


@app.post("/logout")
def logout():
    session.clear()
    response = jsonify({"message": "Logged out."})
    response.delete_cookie(
        app.config.get("SESSION_COOKIE_NAME", "session"),
        httponly=True,
        secure=app.config["SESSION_COOKIE_SECURE"],
        samesite=app.config["SESSION_COOKIE_SAMESITE"],
    )
    return response, 200


@app.get("/health")
def health():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    # Local development only. Do not use Flask's development server in production.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)

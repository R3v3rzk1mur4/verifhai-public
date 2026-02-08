"""
Vulnerable SAML Application - Security Training Target
=======================================================
Module: EG-LAB-SAML-PENTEST-001
Purpose: Intentionally vulnerable Flask app for SAML penetration testing training.

WARNING: This application contains INTENTIONAL security vulnerabilities.
         DO NOT deploy to production. Run only on localhost for training.

Planted Vulnerabilities:
    POST /saml/acs-nosig    -> No signature validation at all              [Lab 1.2]
    POST /saml/acs-xxe      -> lxml default parser (XXE vulnerable)        [Lab 1.3]
    POST /saml/acs-replay   -> No Response ID tracking (replay)            [Lab 1.4]
    POST /saml/acs-xsw      -> Claims from root not signed element (XSW)   [Lab 2.1]
    POST /saml/acs-comment  -> Uses .text for NameID (comment injection)   [Lab 2.2]
    POST /saml/acs-nostrict -> strict:False (audience/destination bypass)   [Lab 2.3]
    POST /saml/acs-session  -> No session regeneration after auth           [Lab 2.4]
    POST /saml/acs-relay    -> Unvalidated RelayState redirect              [Lab 2.3]
    POST /saml/acs-golden   -> Accepts any valid signature (Golden SAML)    [Lab 3.1]
"""

import base64
import datetime
import os
import uuid

from flask import Flask, request, jsonify, session, redirect

# ---------------------------------------------------------------------------
# Attempt imports – give helpful messages
# ---------------------------------------------------------------------------
try:
    from lxml import etree
except ImportError:
    raise SystemExit("lxml is required.  Install with:  pip install lxml")

try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography import x509
    from cryptography.x509.oid import NameOID
except ImportError:
    raise SystemExit(
        "cryptography is required.  Install with:  pip install cryptography"
    )

app = Flask(__name__)
app.secret_key = "insecure-session-key-for-training"

# ---------------------------------------------------------------------------
# SAML namespaces
# ---------------------------------------------------------------------------
SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"
NSMAP = {
    "saml": SAML_NS,
    "samlp": SAMLP_NS,
    "ds": DS_NS,
}

# ---------------------------------------------------------------------------
# Generate a self-signed IdP certificate for training
# ---------------------------------------------------------------------------
_idp_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_idp_subject = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "training-idp.example.com"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Verifhai Training IdP"),
])
_idp_cert = (
    x509.CertificateBuilder()
    .subject_name(_idp_subject)
    .issuer_name(_idp_subject)
    .public_key(_idp_private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    .sign(_idp_private_key, hashes.SHA256())
)

IDP_PRIVATE_PEM = _idp_private_key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
).decode()

IDP_CERT_PEM = _idp_cert.public_bytes(serialization.Encoding.PEM).decode()

# ---------------------------------------------------------------------------
# SP configuration
# ---------------------------------------------------------------------------
SP_ENTITY_ID = "https://vulnerable-sp.example.com"
SP_ACS_URL = "http://127.0.0.1:5001/saml/acs"
IDP_ENTITY_ID = "https://training-idp.example.com"

# In-memory session store (tracks authenticated users)
ACTIVE_SESSIONS: dict[str, dict] = {}

# Response ID tracking – intentionally empty for replay endpoint
SEEN_RESPONSE_IDS: set[str] = set()


# ===========================================================================
# Helper – decode SAML response from POST
# ===========================================================================
def _decode_saml_response() -> str | None:
    """Extract and Base64-decode the SAMLResponse from POST data."""
    saml_b64 = request.form.get("SAMLResponse")
    if not saml_b64:
        return None
    try:
        return base64.b64decode(saml_b64).decode("utf-8")
    except Exception:
        return None


def _extract_nameid_text(element):
    """Extract NameID using .text (vulnerable to comment injection)."""
    return element.text


def _extract_nameid_safe(element):
    """Extract NameID using itertext() (safe from comment injection)."""
    return "".join(element.itertext())


# ===========================================================================
# Helper – generate a valid SAML response for testing
# ===========================================================================
def _generate_saml_response(username, role="user", audience=SP_ENTITY_ID):
    """Generate a Base64-encoded SAML response (for the /generate endpoint)."""
    now = datetime.datetime.utcnow()
    not_after = now + datetime.timedelta(minutes=5)
    response_id = f"_resp_{uuid.uuid4().hex[:16]}"
    assertion_id = f"_assert_{uuid.uuid4().hex[:16]}"

    xml = f"""<samlp:Response xmlns:samlp="{SAMLP_NS}" xmlns:saml="{SAML_NS}"
    ID="{response_id}" Version="2.0"
    IssueInstant="{now.isoformat()}Z"
    Destination="{SP_ACS_URL}">
  <saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="{assertion_id}" Version="2.0"
      IssueInstant="{now.isoformat()}Z">
    <saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{username}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData
            Recipient="{SP_ACS_URL}"
            NotOnOrAfter="{not_after.isoformat()}Z"
            InResponseTo="_authn_request_001"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{now.isoformat()}Z"
        NotOnOrAfter="{not_after.isoformat()}Z">
      <saml:AudienceRestriction>
        <saml:Audience>{audience}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name="role">
        <saml:AttributeValue>{role}</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="email">
        <saml:AttributeValue>{username}</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"""

    return base64.b64encode(xml.encode()).decode()


# ===========================================================================
# POST /saml/acs-nosig – no signature validation
# ===========================================================================
@app.route("/saml/acs-nosig", methods=["POST"])
def acs_nosig():
    """Assertion Consumer Service – no signature validation.

    Vulnerability [1.2]: The SP does not validate the XML signature at all.
    Any Base64-encoded SAML response is accepted as-is.
    """
    xml_str = _decode_saml_response()
    if not xml_str:
        return jsonify({"error": "Missing or invalid SAMLResponse"}), 400

    try:
        root = etree.fromstring(xml_str.encode())
        # VULNERABLE: no signature validation whatsoever
        nameid_el = root.find(f".//{{{SAML_NS}}}NameID")
        role_el = root.find(f".//{{{SAML_NS}}}AttributeValue")

        if nameid_el is None:
            return jsonify({"error": "No NameID found"}), 400

        username = "".join(nameid_el.itertext())
        role = role_el.text if role_el is not None else "unknown"

        return jsonify({
            "message": "Authentication successful (no signature check)",
            "user": username,
            "role": role,
            "vulnerability": "No signature validation performed",
        })
    except etree.XMLSyntaxError as exc:
        return jsonify({"error": f"XML parse error: {exc}"}), 400


# ===========================================================================
# POST /saml/acs-xxe – XXE via lxml default parser
# ===========================================================================
@app.route("/saml/acs-xxe", methods=["POST"])
def acs_xxe():
    """Assertion Consumer Service – XXE vulnerable parser.

    Vulnerability [1.3]: Uses lxml with resolve_entities=True (default)
    and allows DTD loading – external entities are resolved.
    """
    xml_str = _decode_saml_response()
    if not xml_str:
        return jsonify({"error": "Missing or invalid SAMLResponse"}), 400

    try:
        # VULNERABLE: DTD loading and entity resolution enabled
        parser = etree.XMLParser(
            resolve_entities=True,
            load_dtd=True,
            no_network=False,
        )
        root = etree.fromstring(xml_str.encode(), parser=parser)

        nameid_el = root.find(f".//{{{SAML_NS}}}NameID")
        if nameid_el is None:
            return jsonify({"error": "No NameID found"}), 400

        username = "".join(nameid_el.itertext())

        return jsonify({
            "message": "Authentication processed (XXE-vulnerable parser)",
            "user": username,
            "vulnerability": "XML parser resolves external entities",
        })
    except etree.XMLSyntaxError as exc:
        return jsonify({"error": f"XML parse error: {exc}"}), 400


# ===========================================================================
# POST /saml/acs-replay – no Response ID tracking
# ===========================================================================
@app.route("/saml/acs-replay", methods=["POST"])
def acs_replay():
    """Assertion Consumer Service – replay vulnerable.

    Vulnerability [1.4]: The SP does not track Response IDs, so the same
    SAML response can be submitted multiple times.
    """
    xml_str = _decode_saml_response()
    if not xml_str:
        return jsonify({"error": "Missing or invalid SAMLResponse"}), 400

    try:
        root = etree.fromstring(xml_str.encode())
        response_id = root.get("ID", "unknown")

        # VULNERABLE: Response ID is logged but never checked for reuse
        # (no SEEN_RESPONSE_IDS tracking)

        nameid_el = root.find(f".//{{{SAML_NS}}}NameID")
        if nameid_el is None:
            return jsonify({"error": "No NameID found"}), 400

        username = "".join(nameid_el.itertext())

        return jsonify({
            "message": "Authentication successful (replay possible)",
            "user": username,
            "response_id": response_id,
            "vulnerability": "Response ID not tracked — replays accepted",
        })
    except etree.XMLSyntaxError as exc:
        return jsonify({"error": f"XML parse error: {exc}"}), 400


# ===========================================================================
# POST /saml/acs-xsw – XML Signature Wrapping
# ===========================================================================
@app.route("/saml/acs-xsw", methods=["POST"])
def acs_xsw():
    """Assertion Consumer Service – XSW vulnerable.

    Vulnerability [2.1]: The SP validates the signature over the original
    signed element but then extracts claims from the FIRST assertion in the
    document tree (which may be an attacker-injected unsigned assertion).
    """
    xml_str = _decode_saml_response()
    if not xml_str:
        return jsonify({"error": "Missing or invalid SAMLResponse"}), 400

    try:
        root = etree.fromstring(xml_str.encode())

        # Simulate signature validation (checks if ds:Signature element exists)
        sig_el = root.find(f".//{{{DS_NS}}}Signature")
        if sig_el is None:
            return jsonify({"error": "No signature found"}), 401

        # VULNERABLE: extracts claims from the FIRST assertion in the tree,
        # not from the element that was actually signed
        nameid_el = root.find(f".//{{{SAML_NS}}}NameID")
        role_el = root.find(f".//{{{SAML_NS}}}AttributeValue")

        if nameid_el is None:
            return jsonify({"error": "No NameID found"}), 400

        username = "".join(nameid_el.itertext())
        role = role_el.text if role_el is not None else "unknown"

        return jsonify({
            "message": "Authentication successful (XSW vulnerable)",
            "user": username,
            "role": role,
            "vulnerability": "Claims extracted from first assertion, not signed element",
        })
    except etree.XMLSyntaxError as exc:
        return jsonify({"error": f"XML parse error: {exc}"}), 400


# ===========================================================================
# POST /saml/acs-comment – NameID comment injection
# ===========================================================================
@app.route("/saml/acs-comment", methods=["POST"])
def acs_comment():
    """Assertion Consumer Service – comment injection in NameID.

    Vulnerability [2.2]: Uses .text property to extract NameID value.
    XML comments split the text node, so:
        <NameID>attacker@evil.com<!-- -->.legit.com</NameID>
    returns only "attacker@evil.com" via .text
    """
    xml_str = _decode_saml_response()
    if not xml_str:
        return jsonify({"error": "Missing or invalid SAMLResponse"}), 400

    try:
        root = etree.fromstring(xml_str.encode())

        nameid_el = root.find(f".//{{{SAML_NS}}}NameID")
        if nameid_el is None:
            return jsonify({"error": "No NameID found"}), 400

        # VULNERABLE: uses .text which truncates at XML comments
        username = _extract_nameid_text(nameid_el)
        # Safe version would be: username = _extract_nameid_safe(nameid_el)

        return jsonify({
            "message": "Authentication successful (comment-vulnerable)",
            "user": username,
            "vulnerability": "NameID extracted with .text (comment injection possible)",
        })
    except etree.XMLSyntaxError as exc:
        return jsonify({"error": f"XML parse error: {exc}"}), 400


# ===========================================================================
# POST /saml/acs-nostrict – strict:False (audience/destination bypass)
# ===========================================================================
@app.route("/saml/acs-nostrict", methods=["POST"])
def acs_nostrict():
    """Assertion Consumer Service – no strict validation.

    Vulnerability [2.3]: Does not validate Audience, Destination, or
    Recipient fields. Assertions meant for other SPs are accepted.
    """
    xml_str = _decode_saml_response()
    if not xml_str:
        return jsonify({"error": "Missing or invalid SAMLResponse"}), 400

    try:
        root = etree.fromstring(xml_str.encode())

        # VULNERABLE: Audience, Destination, and Recipient are NOT validated
        destination = root.get("Destination", "not-checked")
        audience_el = root.find(f".//{{{SAML_NS}}}Audience")
        audience = audience_el.text if audience_el is not None else "not-present"

        nameid_el = root.find(f".//{{{SAML_NS}}}NameID")
        if nameid_el is None:
            return jsonify({"error": "No NameID found"}), 400

        username = "".join(nameid_el.itertext())

        return jsonify({
            "message": "Authentication successful (no strict validation)",
            "user": username,
            "destination_received": destination,
            "audience_received": audience,
            "vulnerability": "Audience/Destination/Recipient not validated",
        })
    except etree.XMLSyntaxError as exc:
        return jsonify({"error": f"XML parse error: {exc}"}), 400


# ===========================================================================
# POST /saml/acs-session – no session regeneration
# ===========================================================================
@app.route("/saml/acs-session", methods=["POST"])
def acs_session():
    """Assertion Consumer Service – session fixation vulnerable.

    Vulnerability [2.4]: The session ID is not regenerated after SAML
    authentication, enabling session fixation attacks.
    """
    xml_str = _decode_saml_response()
    if not xml_str:
        return jsonify({"error": "Missing or invalid SAMLResponse"}), 400

    try:
        root = etree.fromstring(xml_str.encode())

        nameid_el = root.find(f".//{{{SAML_NS}}}NameID")
        if nameid_el is None:
            return jsonify({"error": "No NameID found"}), 400

        username = "".join(nameid_el.itertext())

        # VULNERABLE: session is not regenerated — session fixation possible
        # If attacker pre-sets the session cookie, they inherit the auth session
        session["authenticated"] = True
        session["user"] = username
        session["auth_time"] = datetime.datetime.utcnow().isoformat()

        return jsonify({
            "message": "Authentication successful (session fixation possible)",
            "user": username,
            "session_id": request.cookies.get("session", "not-set"),
            "vulnerability": "Session ID not regenerated after authentication",
        })
    except etree.XMLSyntaxError as exc:
        return jsonify({"error": f"XML parse error: {exc}"}), 400


# ===========================================================================
# POST /saml/acs-relay – unvalidated RelayState
# ===========================================================================
@app.route("/saml/acs-relay", methods=["POST"])
def acs_relay():
    """Assertion Consumer Service – open redirect via RelayState.

    Vulnerability [2.3]: RelayState parameter is used as redirect target
    without validation – allows open redirect after authentication.
    """
    xml_str = _decode_saml_response()
    if not xml_str:
        return jsonify({"error": "Missing or invalid SAMLResponse"}), 400

    relay_state = request.form.get("RelayState", "/dashboard")

    try:
        root = etree.fromstring(xml_str.encode())

        nameid_el = root.find(f".//{{{SAML_NS}}}NameID")
        if nameid_el is None:
            return jsonify({"error": "No NameID found"}), 400

        username = "".join(nameid_el.itertext())

        # VULNERABLE: RelayState used as redirect without validation
        # In a real app, this would be: return redirect(relay_state)
        # For the lab, we return it in JSON so learners can see the issue
        return jsonify({
            "message": "Authentication successful (open redirect)",
            "user": username,
            "redirect_to": relay_state,
            "vulnerability": "RelayState not validated — open redirect possible",
        })
    except etree.XMLSyntaxError as exc:
        return jsonify({"error": f"XML parse error: {exc}"}), 400


# ===========================================================================
# POST /saml/acs-golden – accepts any valid signature (Golden SAML)
# ===========================================================================
@app.route("/saml/acs-golden", methods=["POST"])
def acs_golden():
    """Assertion Consumer Service – Golden SAML target.

    Vulnerability [3.1]: The SP accepts any assertion signed by ANY
    certificate. This simulates the scenario where an attacker has
    obtained the IdP signing key and can forge arbitrary assertions.
    The SP only checks that a signature element is present, not that
    it was signed by the trusted IdP certificate.
    """
    xml_str = _decode_saml_response()
    if not xml_str:
        return jsonify({"error": "Missing or invalid SAMLResponse"}), 400

    try:
        root = etree.fromstring(xml_str.encode())

        # VULNERABLE: only checks signature element presence,
        # does not verify against trusted IdP certificate
        sig_el = root.find(f".//{{{DS_NS}}}Signature")
        if sig_el is None:
            return jsonify({"error": "Signature required"}), 401

        # Check for X509Certificate in the signature
        cert_el = root.find(f".//{{{DS_NS}}}X509Certificate")
        cert_source = "embedded" if cert_el is not None else "none"

        nameid_el = root.find(f".//{{{SAML_NS}}}NameID")
        if nameid_el is None:
            return jsonify({"error": "No NameID found"}), 400

        username = "".join(nameid_el.itertext())
        role_el = root.find(f".//{{{SAML_NS}}}AttributeValue")
        role = role_el.text if role_el is not None else "unknown"

        return jsonify({
            "message": "Authentication successful (Golden SAML target)",
            "user": username,
            "role": role,
            "certificate_source": cert_source,
            "vulnerability": "Signature presence checked but not verified against trusted IdP cert",
        })
    except etree.XMLSyntaxError as exc:
        return jsonify({"error": f"XML parse error: {exc}"}), 400


# ===========================================================================
# GET /generate – generate test SAML responses
# ===========================================================================
@app.route("/generate")
def generate():
    """Generate a Base64-encoded SAML response for testing.

    Query params:
        username: NameID value (default: user@example.com)
        role: role attribute (default: user)
    """
    username = request.args.get("username", "user@example.com")
    role = request.args.get("role", "user")
    saml_response = _generate_saml_response(username, role)

    return jsonify({
        "SAMLResponse": saml_response,
        "usage": "POST this as form data to any /saml/acs-* endpoint",
        "curl_example": (
            f'curl -X POST http://127.0.0.1:5001/saml/acs-nosig '
            f'-d "SAMLResponse={saml_response}"'
        ),
    })


# ===========================================================================
# GET /idp-metadata – expose IdP certificate (for Golden SAML lab)
# ===========================================================================
@app.route("/idp-metadata")
def idp_metadata():
    """Expose the training IdP certificate and private key.

    In a real attack, the private key would be obtained through
    AD FS compromise, Azure AD Connect exploit, etc.
    For training, we expose it directly.
    """
    return jsonify({
        "idp_entity_id": IDP_ENTITY_ID,
        "sp_entity_id": SP_ENTITY_ID,
        "sp_acs_url": SP_ACS_URL,
        "idp_certificate_pem": IDP_CERT_PEM,
        "idp_private_key_pem": IDP_PRIVATE_PEM,
        "warning": "Private key exposed for training — simulates compromised IdP",
    })


# ===========================================================================
# GET / – app info
# ===========================================================================
@app.route("/")
def index():
    return jsonify({
        "app": "Vulnerable SAML Application",
        "module": "EG-LAB-SAML-PENTEST-001",
        "purpose": "Security training target — INTENTIONALLY VULNERABLE",
        "endpoints": [
            {"method": "POST", "path": "/saml/acs-nosig", "description": "No signature validation"},
            {"method": "POST", "path": "/saml/acs-xxe", "description": "XXE vulnerable parser"},
            {"method": "POST", "path": "/saml/acs-replay", "description": "No replay protection"},
            {"method": "POST", "path": "/saml/acs-xsw", "description": "XSW vulnerable"},
            {"method": "POST", "path": "/saml/acs-comment", "description": "Comment injection"},
            {"method": "POST", "path": "/saml/acs-nostrict", "description": "No strict validation"},
            {"method": "POST", "path": "/saml/acs-session", "description": "Session fixation"},
            {"method": "POST", "path": "/saml/acs-relay", "description": "Open redirect"},
            {"method": "POST", "path": "/saml/acs-golden", "description": "Golden SAML target"},
            {"method": "GET", "path": "/generate", "description": "Generate test SAML response"},
            {"method": "GET", "path": "/idp-metadata", "description": "IdP cert & key (training)"},
        ],
    })


if __name__ == "__main__":
    print("=" * 60)
    print("  VULNERABLE SAML APPLICATION — TRAINING USE ONLY")
    print("  Module: EG-LAB-SAML-PENTEST-001")
    print("  DO NOT expose to untrusted networks")
    print("=" * 60)
    print(f"\n  IdP Entity ID: {IDP_ENTITY_ID}")
    print(f"  SP Entity ID:  {SP_ENTITY_ID}")
    print(f"  SP ACS URL:    {SP_ACS_URL}")
    print()
    app.run(host="127.0.0.1", port=5001, debug=False)

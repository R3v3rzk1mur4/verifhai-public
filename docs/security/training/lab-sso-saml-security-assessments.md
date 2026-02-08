# Lab: SSO & SAML Security for Python Developers - Assessments

## Assessment Overview

| Level | Questions | Passing Score | Format |
|-------|-----------|---------------|--------|
| L1 | 10 questions | 80% (8/10) | Multiple choice |
| L2 | 10 questions | 80% (8/10) | Multiple choice + scenario |
| L3 | 8 questions + practical | 80% + practical pass | Scenario + code review |

---

## Level 1 Assessment: SAML Security Fundamentals

### Instructions
- 10 multiple choice questions
- 80% passing score required (8/10 correct)
- Time limit: 15 minutes

---

### Questions

**Q1. In a SAML SP-initiated SSO flow, what is the correct order of events?**

- A) User authenticates at IdP → IdP sends assertion to SP → SP creates session ✓
- B) SP sends credentials to IdP → IdP validates → SP receives token
- C) User sends password to SP → SP forwards to IdP → IdP confirms
- D) IdP pushes assertion to SP → SP validates user → User logs in

**Explanation:** In SP-initiated SSO, the user visits the SP, gets redirected to the IdP to authenticate, and the IdP sends a signed SAML assertion back to the SP's ACS endpoint, where the SP validates it and creates a session.

---

**Q2. What is the most critical security check when processing a SAML response?**

- A) Checking the response timestamp
- B) Validating the XML formatting
- C) Verifying the digital signature on the assertion ✓
- D) Confirming the user exists in the local database

**Explanation:** Signature validation is the only mechanism that prevents an attacker from forging SAML assertions. Without it, anyone can craft an assertion claiming to be any user.

---

**Q3. Which Python library should you use to safely parse XML in SAML responses?**

- A) `xml.etree.ElementTree` with default settings
- B) `lxml` with default parser
- C) `json` after converting XML to JSON
- D) `defusedxml` ✓

**Explanation:** `defusedxml` blocks XXE (XML External Entity) attacks, entity expansion, and DTD loading. Default XML parsers in Python are vulnerable to XXE when processing untrusted XML like SAML responses.

---

**Q4. What does an XXE attack through a SAML response allow an attacker to do?**

- A) Only crash the XML parser
- B) Read server files, perform SSRF, or cause denial of service ✓
- C) Modify the IdP's signing certificate
- D) Bypass network firewalls

**Explanation:** XXE (XML External Entity) injection allows attackers to define external entities in the XML DOCTYPE that reference local files (`file:///etc/passwd`) or internal URLs, enabling server-side file reading and SSRF.

---

**Q5. How should you prevent SAML replay attacks?**

- A) Track Response IDs and reject duplicates ✓
- B) Use a longer signing key
- C) Encrypt the SAML response with AES
- D) Increase the assertion validity window

**Explanation:** Replay attacks are prevented by tracking each SAML Response ID in a cache (like Redis) and rejecting any response with an ID that has already been processed. Combined with InResponseTo validation and NotOnOrAfter enforcement.

---

**Q6. What does `strict: True` enforce in python3-saml?**

- A) It only allows RSA-4096 certificates
- B) It enables XML schema validation
- C) It requires all assertions to be encrypted
- D) It enforces Destination, Audience, and Recipient validation ✓

**Explanation:** `strict: True` is the single most important python3-saml setting. It ensures the SAML response's Destination matches the SP's ACS URL, the Audience matches the SP's entity ID, and the Recipient is validated.

---

**Q7. What is the role of the Assertion Consumer Service (ACS) URL?**

- A) It is the SP endpoint that receives and processes SAML responses ✓
- B) It stores the IdP's signing certificates
- C) It generates SAML authentication requests
- D) It encrypts assertions before sending them

**Explanation:** The ACS URL is the endpoint on the Service Provider where the IdP sends the SAML response after the user authenticates. The SP validates the response and creates a user session at this endpoint.

---

**Q8. Why should you NOT extract claims from a SAML response using raw XML parsing?**

- A) XML parsing is slower than JSON
- B) It skips signature validation, allowing assertion forgery ✓
- C) XML cannot represent complex data structures
- D) The claims are always encrypted

**Explanation:** Manually parsing SAML XML with lxml or ElementTree bypasses signature validation, audience/destination checks, and time validation. An attacker can craft any assertion they want if these checks are skipped.

---

**Q9. What information does a SAML NameID typically contain?**

- A) The IdP's IP address
- B) A session timeout value
- C) The authenticated user's identifier (email, username, or opaque ID) ✓
- D) The SP's certificate fingerprint

**Explanation:** The NameID element in a SAML assertion contains the subject's identifier — typically an email address, username, or unique identifier that the SP uses to identify the authenticated user.

---

**Q10. Which of the following is a secure python3-saml security configuration?**

- A) `{"strict": False, "wantAssertionsSigned": True}`
- B) `{"strict": True, "wantAssertionsSigned": False}`
- C) `{"strict": False, "wantAssertionsSigned": False}`
- D) `{"strict": True, "wantAssertionsSigned": True, "wantMessagesSigned": True}` ✓

**Explanation:** A secure configuration requires `strict: True` (enforces destination/audience/recipient), `wantAssertionsSigned: True` (prevents unsigned assertions), and `wantMessagesSigned: True` (prevents unsigned responses).

---

## Level 2 Assessment: Advanced SAML Attacks

### Instructions
- 10 multiple choice and scenario-based questions
- 80% passing score required (8/10 correct)
- Time limit: 20 minutes

---

### Questions

**Q1. What is XML Signature Wrapping (XSW)?**

- A) Encrypting the XML signature to hide it
- B) Adding extra signatures to confuse the validator
- C) Wrapping XML in a ZIP archive to avoid detection
- D) An attack that moves the signed element and inserts an unsigned one where the application reads claims ✓

**Explanation:** XSW attacks exploit the separation between "which element the signature covers" and "which element the application reads." The attacker keeps the signed element intact but moves it, then places a forged element where the application expects to find it.

---

**Q2. In the following code, what is the critical XSW vulnerability?**

```python
result = XMLVerifier().verify(root, x509_cert=cert)
name_id = root.find('.//saml:NameID', ns)
```

- A) Claims are extracted from `root` instead of `result.signed_xml` ✓
- B) The certificate is not being validated
- C) The XMLVerifier is using the wrong algorithm
- D) The namespace declaration is incorrect

**Explanation:** After signature verification, `result.signed_xml` contains the element that was actually signed. But the code extracts claims from `root` (the original, potentially manipulated document). An attacker could inject an unsigned assertion that `root.find()` encounters first.

---

**Q3. How does a SAML comment injection attack work?**

- A) Comments in the XML declaration change the encoding
- B) XML comments inside NameID cause different parsers to read different identities ✓
- C) Comments disable signature validation
- D) HTML comments are injected into the SAML response page

**Explanation:** XML comments in NameID (`user@evil.com<!-- -->.legit.com`) cause a mismatch: the IdP may sign the full text including content after the comment, while the SP's `.text` property only returns content before the comment, resulting in a different identity.

---

> **Scenario for Q4-Q5:** Your application uses python3-saml with `strict: False`. Two applications (App-A and App-B) share the same Okta IdP. A user has "viewer" role on App-A and "admin" role on App-B.

**Q4. What attack does this configuration enable?**

- A) The user can replay their App-B admin assertion to App-A's ACS endpoint ✓
- B) The user can perform SQL injection through SAML attributes
- C) The user can modify their Okta password
- D) The user can decrypt other users' SAML assertions

**Explanation:** With `strict: False`, App-A doesn't validate Destination or Audience. The user can capture their signed admin assertion from App-B and submit it to App-A's ACS endpoint, gaining admin access to App-A.

---

**Q5. What is the primary fix for this cross-application attack?**

- A) Use different IdP certificates for each application
- B) Require MFA for all users
- C) Encrypt all SAML assertions
- D) Set `strict: True` to enforce Audience and Destination validation ✓

**Explanation:** `strict: True` enforces that the Audience in the assertion matches App-A's entity ID and the Destination matches App-A's ACS URL. An assertion meant for App-B would fail these checks.

---

**Q6. Which approach correctly prevents NameID comment injection?**

- A) Using `name_id_elem.text` to extract the value
- B) Disabling XML comments in the HTTP header
- C) Rejecting assertions that contain XML comments in the NameID element ✓
- D) Converting the NameID to uppercase before processing

**Explanation:** The strictest defense is to reject assertions with XML comments in identity fields entirely. This eliminates the parser mismatch problem. Alternatively, use `itertext()` to concatenate all text nodes.

---

> **Scenario for Q7-Q8:** You're reviewing a Flask SAML integration. After successful SAML validation, the session is created with:
> ```python
> session['user'] = auth.get_nameid()
> session['roles'] = auth.get_attributes().get('role', [])
> return redirect('/dashboard')
> ```

**Q7. What is the most critical session management vulnerability in this code?**

- A) The session cookie name is too generic
- B) No session regeneration after authentication (session fixation) ✓
- C) The redirect URL is hardcoded
- D) The attributes dictionary is too large

**Explanation:** Without session regeneration (clearing the old session and creating a new one), an attacker who sets a session cookie before authentication can hijack the authenticated session. The attacker's pre-set session ID becomes authenticated.

---

**Q8. Which additional session protection is missing?**

- A) Secure cookie flags (HttpOnly, Secure, SameSite) and session timeout ✓
- B) Adding a CAPTCHA to the dashboard
- C) Base64-encoding the session data
- D) Compressing the session data

**Explanation:** Without `HttpOnly` (prevents JavaScript access), `Secure` (HTTPS only), and `SameSite` (CSRF protection) cookie flags, the session is vulnerable to cookie theft. Without a timeout, compromised sessions persist indefinitely.

---

**Q9. In multi-tenant SAML, what prevents a user from tenant-A accessing tenant-B's data?**

- A) Using different Python versions for each tenant
- B) Using separate Redis instances per tenant
- C) Rate limiting SAML requests per tenant
- D) Domain allowlisting that verifies the NameID domain matches the tenant's allowed domains ✓

**Explanation:** The critical control is verifying that the authenticated user's email domain matches the tenant's registered domains. This prevents a user from one tenant's IdP from being granted access to another tenant's data.

---

**Q10. What should you do if python3-saml's `auth.get_errors()` returns errors but `auth.is_authenticated()` returns True?**

- A) Proceed with authentication since the user is authenticated
- B) Log a warning but allow access
- C) Reject the authentication — errors indicate validation failures ✓
- D) Retry the SAML response processing

**Explanation:** Errors from `get_errors()` indicate that one or more validation checks failed. Even if `is_authenticated()` returns True, the presence of errors means the response did not pass all security checks. Always check errors first and reject if any are present.

---

## Level 3 Assessment: Enterprise SSO Architecture

### Instructions
- 8 scenario-based questions + 1 practical exercise
- 80% passing score required (7/8 correct) + practical pass
- Time limit: 30 minutes (questions) + 45 minutes (practical)

---

### Questions

> **Scenario for Q1-Q2:** Your organization's Okta tenant was compromised in a supply chain attack. The attacker exfiltrated the SAML token-signing private key before being detected. All user passwords have been reset and MFA tokens rotated.

**Q1. Why do password resets and MFA rotation NOT mitigate this attack?**

- A) Because the attacker can still access Okta's admin console
- B) Because password resets take 24 hours to propagate
- C) Because SAML doesn't support MFA
- D) Because Golden SAML allows forging assertions without touching the IdP, so no authentication is needed ✓

**Explanation:** Golden SAML attacks use the stolen signing key to forge assertions directly. The attacker never needs to authenticate at the IdP, so password resets and MFA changes have no effect. The attack persists until the signing certificate is rotated.

---

**Q2. What is the correct remediation for this compromise?**

- A) Block all SAML traffic at the network firewall
- B) Rotate the IdP's token-signing certificate and update all SP configurations ✓
- C) Switch all users to password-only authentication
- D) Redeploy the IdP on new infrastructure

**Explanation:** The only effective remediation is rotating the compromised signing certificate. All SPs must update their IdP certificate configuration to trust only the new certificate. The old certificate must be revoked.

---

> **Scenario for Q3-Q4:** You're architecting a new B2B SaaS platform. Enterprise customers need SSO. Some use Okta, some use Azure AD, some use on-premise ADFS. Consumer users authenticate with email/password.

**Q3. Which SSO architecture best supports these requirements?**

- A) Hybrid: SAML for enterprise IdPs, OIDC for modern IdPs, local auth for consumers, with a normalized identity layer ✓
- B) OIDC-only since it's the newer standard
- C) SAML-only for all users including consumers
- D) OAuth 2.0 with API keys for all authentication

**Explanation:** Enterprise customers with ADFS require SAML support. Modern IdPs like Okta/Azure AD support both SAML and OIDC. Consumers need local authentication. A normalized identity layer abstracts the protocol differences.

---

**Q4. What is the most critical security control for multi-tenant IdP integration?**

- A) Using the same SP entity ID for all tenants
- B) Rate limiting SAML requests
- C) Tenant-scoped domain allowlisting to prevent cross-tenant assertion replay ✓
- D) Encrypting all database queries

**Explanation:** Each tenant must have a verified list of allowed email domains. When a SAML assertion is processed, the SP must verify that the NameID's domain matches the tenant's registered domains, preventing a user from tenant-A's IdP from accessing tenant-B's data.

---

> **Scenario for Q5-Q6:** Your security team detects that a user account "admin@company.com" authenticated to your application via SAML at 3:17 AM on a Sunday. The user reports they were not online at that time. Your IdP (Azure AD) shows no corresponding sign-in event.

**Q5. What does the absence of an IdP sign-in event indicate?**

- A) The IdP logs are delayed by a few hours
- B) The SP's clock is out of sync with the IdP
- C) The user forgot they logged in
- D) A possible Golden SAML attack where assertions are forged without IdP involvement ✓

**Explanation:** If the SP received a valid SAML assertion but the IdP has no corresponding authentication event, this is a strong indicator of a Golden SAML attack. The attacker forged the assertion using a stolen signing key without touching the IdP.

---

**Q6. Which detection mechanism would have caught this earlier?**

- A) Cross-referencing SP authentication events with IdP audit logs in real-time ✓
- B) Adding a CAPTCHA to the login page
- C) Increasing the password complexity requirements
- D) Requiring users to authenticate every hour

**Explanation:** Real-time correlation between SP authentication events and IdP sign-in logs can detect Golden SAML attacks. If the SP sees a successful SAML authentication but the IdP has no matching event, an alert should fire immediately.

---

**Q7. When choosing between SAML and OIDC for a new microservices application, which factor most strongly favors OIDC?**

- A) OIDC is always more secure than SAML
- B) OIDC uses JSON/JWT which propagates easily between microservices ✓
- C) SAML cannot handle more than 100 users
- D) OIDC doesn't require any configuration

**Explanation:** OIDC uses JWTs which are compact, JSON-based, and easily passed between microservices in Authorization headers. SAML's XML-based assertions are bulky and awkward to propagate in API calls between services.

---

**Q8. In a production SAML SP, why should the `RelayState` parameter be validated before redirecting?**

- A) To prevent SQL injection
- B) To ensure the RelayState is properly encrypted
- C) To prevent open redirect vulnerabilities where attackers redirect to malicious sites ✓
- D) To verify the IdP's certificate

**Explanation:** The RelayState is often used as a post-authentication redirect URL. If not validated (e.g., checking it starts with `/` or matches allowed domains), an attacker can craft a SAML flow that redirects the user to a malicious site after authentication.

---

### Practical Exercise: SAML Integration Security Audit

**Scenario:** You are conducting a security audit of the following Flask SAML integration. Review the code and identify all security vulnerabilities. For each vulnerability, explain the risk and provide a secure code fix.

```python
from flask import Flask, request, redirect, session
from lxml import etree
from signxml import XMLVerifier
import base64

app = Flask(__name__)
app.secret_key = "saml-app-2024"

IDP_CERT = open("/app/certs/idp.pem", "rb").read()

@app.route('/saml/acs', methods=['POST'])
def saml_acs():
    saml_response = request.form.get('SAMLResponse')
    xml_bytes = base64.b64decode(saml_response)
    root = etree.fromstring(xml_bytes)

    # Verify signature
    try:
        XMLVerifier().verify(root, x509_cert=IDP_CERT)
    except Exception:
        return "Invalid signature", 403

    # Extract user info
    ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}
    name_id = root.find('.//saml:NameID', ns).text
    role = root.find(
        ".//saml:Attribute[@Name='role']/saml:AttributeValue", ns
    ).text

    session['user'] = name_id
    session['role'] = role

    relay = request.form.get('RelayState', '/dashboard')
    return redirect(relay)

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/login')
    return f"Welcome {session['user']}, role: {session['role']}"
```

**Deliverables:**

1. List all security vulnerabilities (aim for 10+)
2. For each vulnerability, explain:
   - The risk (what an attacker could do)
   - The severity (Critical / High / Medium / Low)
   - The fix (show corrected code or configuration)
3. Provide a fully corrected version of the code

**Evaluation Criteria:**

| Criterion | Pass Requirement |
|-----------|-----------------|
| Vulnerability identification | Find at least 8 of the vulnerabilities |
| Risk explanation | Clearly describe the attack scenario for each |
| Fix quality | Fixes are correct and don't introduce new issues |
| Completeness | Corrected code addresses all identified issues |

---

## Answer Key

### L1 Answers
1-A, 2-C, 3-D, 4-B, 5-A, 6-D, 7-A, 8-B, 9-C, 10-D

### L2 Answers
1-D, 2-A, 3-B, 4-A, 5-D, 6-C, 7-B, 8-A, 9-D, 10-C

### L3 Answers
1-D, 2-B, 3-A, 4-C, 5-D, 6-A, 7-B, 8-C

---

**Framework:** HAIAMM v2.0
**Practice:** Education & Guidance (EG)
**Module:** EG-LAB-SAML-001
**Author:** Verifhai

# Vendors Domain: Third-Party & Supply Chain Security - Assessments

## Assessment Overview

| Level | Questions | Passing Score | Format |
|-------|-----------|---------------|--------|
| L1 | 10 questions | 80% (8/10) | Multiple choice |
| L2 | 15 questions | 80% (12/15) | Multiple choice + scenario |
| L3 | 10 questions + practical | 80% + practical pass | Scenario + program design |

---

## Level 1 Assessment: Vendor Security & Supply Chain Basics

### Instructions
- 10 multiple choice questions
- 80% passing score required (8/10 correct)
- Time limit: 15 minutes

---

### Questions

**Q1. Why is vendor security particularly important for HAI (Human-Assisted Intelligence) systems?**

- A) HAI systems don't use vendors
- B) HAI systems often rely on multiple external services (AI APIs, cloud, dependencies) that extend the attack surface ✓
- C) Vendors are always more secure than internal systems
- D) HAI systems are immune to vendor security issues

**Explanation:** HAI systems typically integrate with AI API providers, cloud infrastructure, and numerous dependencies, making vendor security critical to overall system security.

---

**Q2. Which supply chain attack involved a compromised software update mechanism affecting thousands of organizations?**

- A) Log4Shell
- B) SolarWinds ✓
- C) Heartbleed
- D) Shellshock

**Explanation:** The SolarWinds attack (2020) compromised the software update mechanism, distributing malicious code to approximately 18,000 organizations.

---

**Q3. What does SBOM stand for?**

- A) Security Bill of Materials
- B) Software Bill of Materials ✓
- C) System Baseline Operations Manual
- D) Supply Base Ordering Module

**Explanation:** SBOM (Software Bill of Materials) is an inventory of all software components, dependencies, and their versions in an application.

---

**Q4. Which type of supply chain attack involves publishing a malicious package with a name similar to a popular package?**

- A) Dependency confusion
- B) Typosquatting ✓
- C) Maintainer compromise
- D) Version rollback

**Explanation:** Typosquatting creates malicious packages with names similar to popular ones (e.g., "Iodash" vs "lodash") hoping developers make typos.

---

**Q5. What is the primary difference between a SOC 2 Type I and Type II report?**

- A) Type I is more secure
- B) Type II covers a period of time and tests control effectiveness, Type I is point-in-time ✓
- C) Type I is newer than Type II
- D) There is no difference

**Explanation:** Type I describes controls at a point in time; Type II evaluates control effectiveness over a period (typically 6-12 months), making Type II more valuable.

---

**Q6. For AI vendors specifically, which of the following should be assessed?**

- A) Only their physical security
- B) How they handle prompts/responses and whether customer data is used for training ✓
- C) Only their pricing model
- D) AI vendors don't need security assessment

**Explanation:** AI vendors require specific assessment of how they handle customer prompts, responses, and whether data is used for model training.

---

**Q7. What is SCA in the context of supply chain security?**

- A) Security Compliance Audit
- B) Software Composition Analysis ✓
- C) Supply Chain Assessment
- D) System Configuration Analysis

**Explanation:** SCA (Software Composition Analysis) tools scan software dependencies to identify known vulnerabilities and license issues.

---

**Q8. What is a "transitive dependency"?**

- A) A dependency that changes frequently
- B) A dependency of your direct dependency (indirect) ✓
- C) A temporary dependency
- D) A deprecated dependency

**Explanation:** Transitive dependencies are indirect - they're packages pulled in by your direct dependencies, often invisible but still posing security risks.

---

**Q9. Which vendor risk tier would typically require the most thorough security assessment?**

- A) Low - they need the most scrutiny since they're often overlooked
- B) Medium - they balance risk and effort
- C) Critical - they handle sensitive data or are essential to business operations ✓
- D) All tiers require identical assessment depth

**Explanation:** Critical vendors (core business function, sensitive data access) require the deepest assessment due to their potential impact.

---

**Q10. What should you do if a vendor claims "we follow industry best practices" on a security questionnaire?**

- A) Accept it as sufficient evidence
- B) Request specific controls and evidence to verify the claim ✓
- C) Automatically reject the vendor
- D) Skip that question

**Explanation:** Vague claims require follow-up to understand exactly what controls are implemented and request evidence.

---

## Level 2 Assessment: Comprehensive Vendor Risk Management

### Instructions
- 15 questions (10 multiple choice + 5 scenario-based)
- 80% passing score required (12/15 correct)
- Time limit: 30 minutes

---

### Multiple Choice Questions (1-10)

**Q1. What are "Complementary User Entity Controls" (CUECs) in a SOC 2 report?**

- A) Controls the auditor recommends
- B) Controls the customer organization must implement for the overall control environment to be effective ✓
- C) Additional controls the vendor charges extra for
- D) Controls that are optional

**Explanation:** CUECs are controls the customer must implement on their side for the vendor's controls to be fully effective.

---

**Q2. Which SBOM format is widely used and supported by CISA?**

- A) JSON only
- B) CycloneDX and SPDX ✓
- C) XML only
- D) CSV

**Explanation:** CycloneDX and SPDX are the two main SBOM standards, both supported by CISA and widely adopted.

---

**Q3. What is "dependency confusion" attack?**

- A) Developers using too many dependencies
- B) Attacker publishes public package with same name as internal private package ✓
- C) Dependencies having conflicting versions
- D) Forgetting which dependencies are used

**Explanation:** Dependency confusion exploits package managers that may prefer public packages, allowing attackers to hijack internal package names.

---

**Q4. In vendor contract security clauses, what is a reasonable breach notification timeline to require?**

- A) Within 24-72 hours of detection ✓
- B) Within 30 days
- C) Only after investigation is complete
- D) Breach notification is not important

**Explanation:** 24-72 hours allows timely incident response; GDPR requires 72 hours, making this a reasonable industry standard.

---

**Q5. What does a "carved out" subservice organization mean in a SOC 2 report?**

- A) The subservice org was removed from the vendor relationship
- B) The subservice org's controls are NOT covered in this report ✓
- C) The subservice org has superior security
- D) The subservice org is a competitor

**Explanation:** "Carved out" means the subservice organization's controls are excluded from the SOC 2 report and may need separate assessment.

---

**Q6. When prioritizing vulnerability remediation in dependencies, which factor is MOST important?**

- A) Package size
- B) Exploitability and severity (CVSS score, known exploits, exposure) ✓
- C) When the package was last updated
- D) Number of GitHub stars

**Explanation:** Prioritize based on actual risk: severity, whether exploits exist, and whether the vulnerable code path is reachable in your application.

---

**Q7. What vendor security monitoring should be continuous rather than periodic?**

- A) Full security questionnaire
- B) Contract review
- C) Security rating services and breach monitoring ✓
- D) Onsite assessments

**Explanation:** Continuous monitoring (security ratings, breach news, dark web) provides real-time awareness between periodic assessments.

---

**Q8. What contract clause protects you from vendor's vendors (fourth parties)?**

- A) Indemnification clause
- B) Subprocessor notification and approval rights ✓
- C) Pricing clause
- D) Termination clause

**Explanation:** Subprocessor clauses require vendors to notify you of and get approval for fourth parties handling your data.

---

**Q9. When analyzing a vendor's security questionnaire responses with AI assistance, what should you NOT do?**

- A) Use AI to identify potential red flags
- B) Have AI pre-score responses
- C) Blindly accept AI risk scores without human review ✓
- D) Use AI to suggest follow-up questions

**Explanation:** AI assessments require human review, especially for critical vendors where context and business judgment matter.

---

**Q10. What is the primary purpose of requiring audit rights in vendor contracts?**

- A) To punish vendors
- B) To verify vendor security practices and request evidence when needed ✓
- C) To conduct audits every month
- D) To reduce contract costs

**Explanation:** Audit rights allow you to verify vendor claims, request evidence, and assess security posture beyond self-reported questionnaires.

---

### Scenario-Based Questions (11-15)

**Scenario A:** Your company uses an AI API provider for a customer-facing chatbot. The AI provider's SOC 2 Type II report shows:
- Security, Availability, and Confidentiality criteria covered
- One exception: "User access reviews were not performed quarterly as required for 2 of 4 quarters"
- CUEC: "Customer is responsible for encrypting data before transmission"

**Q11. How should you evaluate the access review exception in Scenario A?**

- A) Reject the vendor immediately
- B) Assess if the exception materially affects your risk, check management response, and determine if compensating controls exist ✓
- C) Ignore it because it's only one exception
- D) Assume it's already been fixed

**Explanation:** Evaluate the exception's materiality, how the vendor responded, and whether it's been remediated or compensating controls are in place.

---

**Q12. What action must you take based on the CUEC in Scenario A?**

- A) Nothing - it's the vendor's responsibility
- B) Implement encryption for data sent to the AI provider as specified ✓
- C) Ask the vendor to encrypt for you
- D) CUECs are optional suggestions

**Explanation:** CUECs are your responsibility. If you don't implement them, the overall control environment has gaps regardless of vendor controls.

---

**Scenario B:** Your SCA tool reports a critical vulnerability (CVE-2024-XXXX, CVSS 9.8) in a transitive dependency: `libxml2` is used by `beautifulsoup4`, which your application uses for HTML parsing.

**Q13. What is the first step in responding to Scenario B?**

- A) Immediately remove beautifulsoup4 from the project
- B) Determine if the vulnerable code path in libxml2 is actually used by your application ✓
- C) Ignore it because it's a transitive dependency
- D) Wait for the library maintainer to fix it

**Explanation:** First, assess reachability - does your use of beautifulsoup4 actually trigger the vulnerable code path? This determines true risk.

---

**Q14. If the vulnerability in Scenario B is confirmed reachable and exploitable, what is the remediation path?**

- A) Pin to the vulnerable version permanently
- B) Update beautifulsoup4 to a version that uses a patched libxml2, or override the transitive dependency version ✓
- C) Ignore it since it's not your direct dependency
- D) Stop using HTML parsing entirely

**Explanation:** Update the direct dependency if a new version fixes it, or explicitly override the transitive dependency version to a patched version.

---

**Scenario C:** During vendor onboarding, a new AI analytics vendor responds to your security questionnaire. For the question "Have you experienced any security incidents in the past 3 years?" they answer "No incidents have occurred."

**Q15. How should you interpret this response?**

- A) Accept it - they must be very secure
- B) View it skeptically and ask follow-up questions about their detection capabilities and incident classification ✓
- C) This is the best possible answer
- D) Reject them for being dishonest

**Explanation:** No incidents in 3 years is unusual and may indicate weak detection rather than strong security. Ask about their detection capabilities and how they classify incidents.

---

## Level 3 Assessment: Vendor Security Leadership

### Instructions
- 10 scenario-based questions + 1 practical exercise
- 80% on written questions (8/10) + practical pass required
- Time limit: 45 minutes for written, 45 minutes for practical

---

### Scenario-Based Questions (1-10)

**Q1. What is SLSA (Supply chain Levels for Software Artifacts) designed to protect against?**

- A) Network attacks
- B) Tampering and integrity issues in the software build and distribution process ✓
- C) Social engineering
- D) Physical theft

**Explanation:** SLSA provides a framework for ensuring software artifact integrity from source to deployment, preventing tampering at various stages.

---

**Q2. At which SLSA level is "non-falsifiable provenance" required?**

- A) SLSA 1
- B) SLSA 2
- C) SLSA 3 ✓
- D) SLSA 4

**Explanation:** SLSA 3 requires non-falsifiable provenance (the build platform generates it, not the user), providing stronger tamper resistance.

---

**Q3. What is Sigstore used for in supply chain security?**

- A) Encrypting source code
- B) Signing and verifying software artifacts using keyless signing with identity verification ✓
- C) Monitoring vendor security
- D) Generating SBOMs

**Explanation:** Sigstore provides keyless signing for artifacts, using OIDC identity verification to sign containers, binaries, and other artifacts.

---

**Q4. In fourth-party risk management, what is the vendor's responsibility regarding subprocessors?**

- A) No responsibility - fourth parties manage themselves
- B) Vendors should notify customers, get approval, and ensure subprocessors meet equivalent security requirements ✓
- C) Vendors only need to list subprocessors once
- D) Fourth-party risk is the customer's sole responsibility

**Explanation:** Vendors should maintain subprocessor lists, notify customers of changes, ensure equivalent security requirements, and remain liable for subprocessor actions.

---

**Q5. Which metric measures how quickly critical vulnerabilities in dependencies are remediated?**

- A) Assessment Coverage
- B) Supply Chain Vulnerability MTTR ✓
- C) Contract Compliance
- D) Vendor Incident Rate

**Explanation:** Supply Chain Vulnerability MTTR (Mean Time to Remediate) tracks how quickly critical CVEs in dependencies are addressed.

---

**Scenario D:** Your vendor security council is deciding whether to approve a new AI data processing vendor. The vendor:
- Has SOC 2 Type II with 2 exceptions (both have remediation plans)
- Uses 3 subprocessors including a cloud provider in a different country
- Wants to use customer data to improve their AI models
- Has a security rating of 720/900 from a rating service

**Q6. What is the most significant concern in Scenario D?**

- A) The SOC 2 exceptions
- B) The security rating
- C) The vendor's intention to use customer data for AI model training ✓
- D) Having 3 subprocessors

**Explanation:** Using customer data for AI training raises major privacy, IP, and compliance concerns that require careful consideration or prohibition.

---

**Q7. What contract clause should address the AI training concern in Scenario D?**

- A) Just rely on the vendor's privacy policy
- B) Explicit prohibition on using customer data for training, with audit rights to verify ✓
- C) Price reduction clause
- D) Longer termination notice

**Explanation:** Contracts should explicitly prohibit use of customer data for training (or require explicit opt-in), with audit rights to verify compliance.

---

**Scenario E:** Your organization is implementing a vendor security program from scratch. You have:
- 50 vendors total (5 critical, 15 high, 20 medium, 10 low)
- Limited security team capacity (1 FTE for vendor security)
- No existing vendor inventory or assessments
- Board pressure to show progress in 90 days

**Q8. What is the best approach for the first 90 days in Scenario E?**

- A) Assess all 50 vendors equally
- B) Focus on critical and high vendors first, use tiered assessment depth, leverage AI tools for efficiency ✓
- C) Ignore vendor security until you have more resources
- D) Assess only the newest vendors

**Explanation:** Prioritize by risk tier (critical and high first), use appropriate assessment depth per tier, and leverage AI tools to increase efficiency with limited resources.

---

**Q9. What should your 90-day progress report include for Scenario E?**

- A) Only a list of vendors
- B) Coverage metrics, critical vendor status, identified risks, remediation priorities, and resource needs ✓
- C) Just a statement that work is ongoing
- D) Financial costs only

**Explanation:** Progress reports should show what's been achieved (coverage), what's been found (risks), what's being done (remediation), and what's needed (resources).

---

**Q10. As vendor security program matures, what indicates industry leadership?**

- A) Having the most vendors
- B) Contributing to standards (SLSA, Shared Assessments), publishing case studies, participating in industry groups ✓
- C) Spending the most money
- D) Never having vendor incidents

**Explanation:** Industry leadership is demonstrated through contributing to standards, sharing knowledge, participating in industry forums, and advancing the practice.

---

### Practical Exercise: Vendor Security Program Design

**Exercise:** Design a vendor security program for the following organization:

> **Organization Profile:**
> - Mid-size fintech company (500 employees)
> - Handles financial transactions and PII
> - Uses multiple AI/ML services for fraud detection
> - Regulatory requirements: SOC 2, PCI-DSS
> - Current state: Ad-hoc vendor reviews, no formal program
> - 75 vendors (estimated: 8 critical, 20 high, 30 medium, 17 low)

**Deliverables (45 minutes):**

1. **Governance Structure** (10 points)
   - Roles and responsibilities
   - Decision-making process
   - Escalation paths
   - Reporting structure

2. **Vendor Tier Criteria** (10 points)
   - Define criteria for Critical/High/Medium/Low tiers
   - Consider: data access, criticality, regulatory impact, AI-specific factors
   - Map to assessment requirements

3. **Assessment Process** (15 points)
   - Workflow from intake to ongoing monitoring
   - Assessment depth per tier
   - AI tool integration points
   - Timeline expectations

4. **Contract Security Requirements** (10 points)
   - Key security clauses for each tier
   - AI-specific requirements
   - Regulatory compliance requirements (PCI, SOC 2)

5. **Supply Chain Security** (10 points)
   - SBOM requirements
   - Vulnerability management SLAs
   - SLSA adoption roadmap

6. **Metrics and Reporting** (10 points)
   - KPIs for program effectiveness
   - Executive reporting cadence
   - Continuous improvement mechanisms

7. **90-Day Implementation Roadmap** (10 points)
   - Prioritized activities
   - Quick wins
   - Resource requirements
   - Risk-based prioritization

**Passing Criteria:**
- Governance structure is complete and appropriate for organization size
- Tier criteria are clear, measurable, and consider AI/fintech factors
- Assessment process is risk-proportionate and efficient
- Contract requirements address PCI-DSS and AI-specific risks
- Supply chain security plan is realistic and progressive
- Metrics are measurable and actionable
- Roadmap is achievable and prioritizes highest risks

---

## Answer Key Summary

### L1 Answers
1-B, 2-B, 3-B, 4-B, 5-B, 6-B, 7-B, 8-B, 9-C, 10-B

### L2 Answers
1-B, 2-B, 3-B, 4-A, 5-B, 6-B, 7-C, 8-B, 9-C, 10-B, 11-B, 12-B, 13-B, 14-B, 15-B

### L3 Answers
1-B, 2-C, 3-B, 4-B, 5-B, 6-C, 7-B, 8-B, 9-B, 10-B
Practical: Rubric-based evaluation

---

**Document Version:** 1.0
**Framework:** HAIAMM v2.0
**Practice:** Education & Guidance (EG)
**Domain:** Vendors
**Author:** Verifhai

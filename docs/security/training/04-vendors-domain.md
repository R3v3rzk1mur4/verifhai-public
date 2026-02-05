# Vendors Domain: Third-Party & Supply Chain Security

## Module Overview

| Attribute | Value |
|-----------|-------|
| **Module ID** | EG-VENDORS-001 |
| **Primary Audience** | Procurement, Legal, Security Team, Vendor Management |
| **Secondary Audience** | Developers (supply chain), Engineering Managers |
| **Prerequisite** | Core Module (HAI Security Fundamentals) |
| **Duration** | L1: 1 hour, L2: 4 hours, L3: 8+ hours |
| **Version** | 1.0 |
| **Last Updated** | 2025-02 |

---

## Module Purpose

Enable teams to manage third-party and supply chain security risks with AI assistance. Covers vendor assessment, software supply chain security (SBOMs, SCA), contract security, and continuous vendor monitoring.

---

## Level 1: CRAWL - Vendor Security & Supply Chain Basics

### Learning Objectives

After completing L1, learners will be able to:

1. Explain why vendor and supply chain security matters for HAI systems
2. Identify different types of third-party risks
3. Understand basics of AI-assisted vendor risk management
4. Recognize software supply chain threats

---

### 1.1 Why Vendor Security Matters for HAI

**The Extended Attack Surface:**

HAI systems often rely on:
- **AI/LLM API providers** (OpenAI, Anthropic, Google, etc.)
- **Cloud infrastructure** (AWS, Azure, GCP)
- **Software dependencies** (npm, PyPI, Go modules)
- **Data providers** (training data, enrichment services)
- **Tool integrations** (APIs your AI agents call)

> **Key Insight:** Your AI system is only as secure as its weakest vendor. A breach at any vendor can cascade to compromise your HAI system.

**Real-World Vendor Security Incidents:**

| Incident | What Happened | Impact |
|----------|---------------|--------|
| **SolarWinds (2020)** | Supply chain attack via software update | 18,000+ organizations compromised |
| **Log4Shell (2021)** | Vulnerability in ubiquitous logging library | Millions of systems vulnerable |
| **Codecov (2021)** | CI/CD tool compromise | Secrets exfiltrated from thousands of repos |
| **npm Malicious Packages** | Typosquatting and dependency confusion | Credentials stolen, crypto miners installed |

---

### 1.2 Types of Third-Party Risk

**Vendor Risk Categories:**

| Category | Description | Examples |
|----------|-------------|----------|
| **SaaS Vendors** | Cloud software services | AI APIs, CRM, collaboration tools |
| **Infrastructure Providers** | Cloud and hosting | AWS, Azure, GCP, data centers |
| **Software Dependencies** | Libraries and packages | npm, PyPI, Maven packages |
| **Service Providers** | Professional services | Consultants, MSPs, outsourcing |
| **Data Providers** | Data sources and enrichment | Training data, threat intelligence |

**AI-Specific Vendor Risks:**

| Risk | Description | Impact |
|------|-------------|--------|
| **Model Provider Security** | Security of AI API provider | Data exposure, availability |
| **Training Data Provenance** | Origin and integrity of training data | Poisoned models, legal issues |
| **Tool Integration Security** | Security of APIs agents call | Compromise via tool chain |
| **Prompt/Response Logging** | How vendors handle your prompts | Data leakage, privacy |

---

### 1.3 AI-Assisted Vendor Risk Management

**How AI Helps with Vendor Security:**

| Capability | What It Does | Benefit |
|------------|--------------|---------|
| **Questionnaire Analysis** | AI reviews vendor security questionnaires | Faster assessment, flag issues |
| **Vendor Risk Scoring** | AI assigns risk scores based on multiple factors | Prioritization, consistency |
| **Continuous Monitoring** | AI monitors vendor security posture changes | Real-time risk awareness |
| **SOC 2 Report Analysis** | AI extracts key findings from audit reports | Efficient review |
| **Supply Chain Scanning** | AI identifies vulnerable dependencies | Proactive risk detection |

**AI Vendor Risk Tool Limitations:**

| Limitation | Risk | Mitigation |
|------------|------|------------|
| Context blindness | AI may miss business-specific risks | Human review for critical vendors |
| Questionnaire gaming | Vendors may craft responses to pass AI | Verify claims with evidence |
| Score over-reliance | Blindly trusting AI scores | Understand scoring methodology |
| Historical data | AI may miss recent vendor changes | Supplement with real-time intel |

---

### 1.4 Software Supply Chain Security Basics

**What is Software Supply Chain Security?**

> Managing security risks from software dependencies - the libraries, packages, and components your application uses.

**Software Supply Chain Threats:**

| Threat | Description | Example |
|--------|-------------|---------|
| **Malicious Packages** | Attacker publishes trojanized package | event-stream npm package |
| **Typosquatting** | Malicious package with similar name | lodash vs. Iodash (with capital I) |
| **Dependency Confusion** | Public package replacing private | Attacker claims internal package name |
| **Compromised Maintainer** | Legitimate maintainer account hacked | ua-parser-js compromise |
| **Vulnerable Dependencies** | Using libraries with known CVEs | Log4Shell in log4j |

**Key Concepts:**

| Term | Definition |
|------|------------|
| **SCA** | Software Composition Analysis - tools that scan dependencies |
| **SBOM** | Software Bill of Materials - inventory of all components |
| **CVE** | Common Vulnerabilities and Exposures - vulnerability IDs |
| **Transitive Dependency** | Dependency of your dependency (indirect) |

---

### 1.5 Vendor Security Due Diligence Basics

**Basic Vendor Assessment Questions:**

```markdown
## Quick Vendor Security Check

### Security Program
- [ ] Does the vendor have a documented security program?
- [ ] Do they have security certifications (SOC 2, ISO 27001)?
- [ ] Do they conduct regular penetration testing?

### Data Protection
- [ ] How do they protect customer data?
- [ ] Where is data stored (geography, cloud provider)?
- [ ] Do they encrypt data at rest and in transit?

### Access Control
- [ ] How do they control access to customer data?
- [ ] Do they support SSO/MFA for authentication?
- [ ] What is their employee offboarding process?

### Incident Response
- [ ] Do they have an incident response plan?
- [ ] What are their breach notification timelines?
- [ ] Have they had security incidents? What happened?

### AI-Specific (for AI vendors)
- [ ] How do they handle prompt/response data?
- [ ] Do they use customer data for training?
- [ ] What is their model security posture?
```

---

### L1 Quick Reference: Vendor Security

```
┌─────────────────────────────────────────────────────────────┐
│        VENDOR SECURITY - QUICK REFERENCE                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  VENDOR RISK CATEGORIES:                                    │
│  • SaaS Vendors (AI APIs, cloud software)                   │
│  • Infrastructure (cloud, hosting)                          │
│  • Software Dependencies (packages, libraries)              │
│  • Service Providers (consultants, MSPs)                    │
│  • Data Providers (training data, intelligence)             │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  SUPPLY CHAIN THREATS:                                      │
│  • Malicious packages (trojanized code)                     │
│  • Typosquatting (similar package names)                    │
│  • Dependency confusion (public/private mix)                │
│  • Compromised maintainers (account takeover)               │
│  • Vulnerable dependencies (known CVEs)                     │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  BEFORE ONBOARDING A VENDOR:                                │
│  ✓ Check for security certifications (SOC 2, ISO 27001)     │
│  ✓ Review data protection practices                         │
│  ✓ Understand incident response procedures                  │
│  ✓ For AI vendors: verify prompt/data handling              │
│  ✓ Document assessment and risk acceptance                  │
└─────────────────────────────────────────────────────────────┘
```

---

## Level 2: WALK - Comprehensive Vendor Risk Management

### Learning Objectives

After completing L2, learners will be able to:

1. Conduct thorough vendor security assessments with AI assistance
2. Analyze SBOMs and manage software supply chain risks
3. Negotiate security requirements in vendor contracts
4. Implement continuous vendor monitoring

---

### 2.1 Vendor Security Assessment Process

**Assessment Workflow:**

```
1. CATEGORIZE
   └── Determine vendor risk tier based on data access and criticality
       ├── Critical: Core business function, sensitive data access
       ├── High: Important function, some sensitive data
       ├── Medium: Support function, limited data access
       └── Low: Minimal access, easily replaceable

2. ASSESS
   └── Conduct assessment appropriate to risk tier
       ├── Critical: Full assessment + onsite/deep dive
       ├── High: Full questionnaire + SOC 2 review
       ├── Medium: Standard questionnaire
       └── Low: Self-attestation

3. ANALYZE
   └── Review responses and documentation
       ├── AI pre-scoring for efficiency
       ├── Human review of AI findings
       └── Request clarification on gaps

4. DECIDE
   └── Accept, conditionally accept, or reject
       ├── Document risk acceptance rationale
       ├── Define compensating controls if needed
       └── Set reassessment schedule

5. MONITOR
   └── Ongoing vendor security monitoring
       ├── Continuous posture monitoring
       ├── Periodic reassessment
       └── Incident notification tracking
```

**Vendor Risk Tier Definitions:**

| Tier | Criteria | Assessment Depth | Reassessment |
|------|----------|------------------|--------------|
| **Critical** | Core business function, PII/PHI access, single point of failure | Full + evidence verification | Annual + continuous monitoring |
| **High** | Important function, some sensitive data | Full questionnaire + SOC 2 | Annual |
| **Medium** | Support function, limited data | Standard questionnaire | Every 2 years |
| **Low** | Minimal access, easily replaced | Self-attestation | Every 3 years |

---

### 2.2 AI-Assisted Vendor Assessment

**Using AI for Questionnaire Analysis:**

```python
# Example: AI-assisted questionnaire review

def analyze_vendor_questionnaire(responses: dict) -> AssessmentResult:
    """
    AI analyzes vendor questionnaire responses and flags issues.
    """
    findings = []

    for question, response in responses.items():
        # AI analysis of each response
        analysis = ai_model.analyze(
            prompt=f"""
            Analyze this vendor security questionnaire response:

            Question: {question}
            Response: {response}

            Evaluate for:
            1. Completeness - Does it fully answer the question?
            2. Red flags - Are there concerning statements?
            3. Verification needed - What evidence should we request?
            4. Risk level - Low/Medium/High based on response

            Be specific and cite exact phrases that concern you.
            """
        )

        if analysis.risk_level in ['Medium', 'High']:
            findings.append({
                'question': question,
                'concern': analysis.concern,
                'evidence_needed': analysis.evidence_needed,
                'risk_level': analysis.risk_level
            })

    return AssessmentResult(
        overall_risk=calculate_overall_risk(findings),
        findings=findings,
        requires_human_review=len([f for f in findings if f['risk_level'] == 'High']) > 0
    )
```

**Red Flags in Vendor Responses:**

| Response Pattern | Concern | Follow-up |
|------------------|---------|-----------|
| "We follow industry best practices" | Vague, non-committal | Request specific controls and evidence |
| "N/A" for security questions | May not have controls | Clarify why not applicable |
| No incident history ever | Unlikely or underreporting | Ask about detection capabilities |
| "We're working on certification" | Not currently compliant | Timeline and interim controls |
| Inconsistent responses | Copy/paste or inaccurate | Request clarification |

---

### 2.3 SOC 2 Report Analysis

**What to Look for in SOC 2 Reports:**

```markdown
## SOC 2 Report Review Checklist

### Report Basics
- [ ] Type II report (covers period of time, not point in time)
- [ ] Report period is recent (within last 12 months)
- [ ] Covers relevant trust services criteria for your needs

### Trust Services Criteria Coverage
- [ ] Security (required) - Core security controls
- [ ] Availability - Uptime and disaster recovery
- [ ] Processing Integrity - Accurate processing
- [ ] Confidentiality - Data protection
- [ ] Privacy - Personal information handling

### Opinion
- [ ] Unqualified opinion (clean) vs. qualified (exceptions)
- [ ] Read any qualifications carefully

### Control Exceptions
- [ ] Review all exceptions and management responses
- [ ] Assess if exceptions affect your use case
- [ ] Check if exceptions are remediated

### Complementary User Entity Controls (CUECs)
- [ ] Identify controls YOU must implement
- [ ] Document how you'll address each CUEC

### Subservice Organizations
- [ ] Identify vendor's vendors (fourth parties)
- [ ] Check if subservice orgs are "carved out" or "inclusive"
- [ ] Assess if carved-out subservice orgs need separate review
```

**AI-Assisted SOC 2 Review:**

```python
def review_soc2_report(report_text: str) -> SOC2Analysis:
    """
    AI extracts key findings from SOC 2 report.
    """
    analysis = ai_model.analyze(
        prompt=f"""
        Analyze this SOC 2 Type II report and extract:

        1. Report period and opinion type
        2. Trust service criteria covered
        3. All control exceptions with:
           - Exception description
           - Severity assessment
           - Management response adequacy
        4. Complementary User Entity Controls (CUECs)
        5. Subservice organizations (carved out vs inclusive)
        6. Key concerns for a customer evaluating this vendor

        Report:
        {report_text}

        Provide a structured analysis with specific page/section references.
        """
    )

    return SOC2Analysis(
        summary=analysis.summary,
        exceptions=analysis.exceptions,
        cuecs=analysis.cuecs,
        subservice_orgs=analysis.subservice_orgs,
        risk_assessment=analysis.risk_assessment,
        recommendations=analysis.recommendations
    )
```

---

### 2.4 Software Supply Chain Security

**SBOM Analysis:**

```json
// Example SBOM (CycloneDX format)
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "components": [
    {
      "type": "library",
      "name": "lodash",
      "version": "4.17.21",
      "purl": "pkg:npm/lodash@4.17.21",
      "licenses": [{"license": {"id": "MIT"}}]
    },
    {
      "type": "library",
      "name": "axios",
      "version": "0.21.1",
      "purl": "pkg:npm/axios@0.21.1",
      "licenses": [{"license": {"id": "MIT"}}]
    }
  ]
}
```

**SBOM Security Analysis Workflow:**

```
1. GENERATE SBOM
   └── Use tools like Syft, Trivy, or SPDX tools
       ├── Include direct and transitive dependencies
       └── Include version information

2. VULNERABILITY SCANNING
   └── Cross-reference with vulnerability databases
       ├── NVD (National Vulnerability Database)
       ├── OSV (Open Source Vulnerabilities)
       └── GitHub Advisory Database

3. LICENSE COMPLIANCE
   └── Check for license compatibility issues
       ├── Copyleft licenses (GPL implications)
       ├── Commercial use restrictions
       └── Attribution requirements

4. DEPENDENCY HEALTH
   └── Assess dependency maintenance status
       ├── Last update date
       ├── Maintainer activity
       ├── Known security issues
       └── Project abandonment risk

5. REMEDIATION
   └── Prioritize and address findings
       ├── Critical CVEs: Immediate action
       ├── High CVEs: Within sprint
       ├── Outdated dependencies: Plan upgrade
       └── License issues: Legal review
```

**Dependency Selection Criteria:**

| Factor | What to Check | Red Flags |
|--------|---------------|-----------|
| **Popularity** | Downloads, GitHub stars | Very low usage (unmaintained?) |
| **Maintenance** | Recent commits, issue responses | No updates in 2+ years |
| **Security Track Record** | Past vulnerabilities, response time | Repeated critical CVEs |
| **License** | Compatible with your use | Copyleft in commercial product |
| **Dependencies** | What it pulls in transitively | Large dependency tree |
| **Alternatives** | Are there better options? | Using deprecated package |

---

### 2.5 Contract Security Requirements

**Security Clauses for Vendor Contracts:**

```markdown
## Vendor Contract Security Requirements

### 1. Data Protection
The Vendor shall:
- Encrypt all Customer Data at rest using AES-256 or equivalent
- Encrypt all Customer Data in transit using TLS 1.2 or higher
- Not use Customer Data for training AI/ML models without explicit consent
- Delete Customer Data within 30 days of contract termination

### 2. Security Program
The Vendor shall maintain:
- SOC 2 Type II certification (or equivalent)
- Annual penetration testing by qualified third party
- Vulnerability management program with defined SLAs
- Security awareness training for all employees

### 3. Access Control
The Vendor shall:
- Implement role-based access control (RBAC)
- Require multi-factor authentication for administrative access
- Maintain access logs for minimum 12 months
- Conduct quarterly access reviews

### 4. Incident Response
The Vendor shall:
- Notify Customer of security incidents within 24 hours of detection
- Provide incident details including scope, impact, and remediation
- Cooperate with Customer incident response activities
- Conduct post-incident review and share lessons learned

### 5. Subcontractors
The Vendor shall:
- Obtain Customer approval before using subcontractors for Customer Data
- Ensure subcontractors meet equivalent security requirements
- Remain responsible for subcontractor security

### 6. Audit Rights
Customer shall have the right to:
- Request and receive SOC 2 reports annually
- Request vulnerability scan results
- Conduct security assessments with reasonable notice
- Receive remediation plans for identified issues

### 7. AI-Specific Requirements (for AI vendors)
The Vendor shall:
- Not use prompts, responses, or Customer Data for model training
- Provide transparency on AI model security practices
- Support customer-side content filtering and moderation
- Document AI system security architecture
```

---

### 2.6 Continuous Vendor Monitoring

**Monitoring Program Components:**

| Component | Frequency | What to Monitor |
|-----------|-----------|-----------------|
| **Security Ratings** | Continuous | Third-party security ratings (BitSight, SecurityScorecard) |
| **Breach Monitoring** | Continuous | Data breach news, dark web mentions |
| **Certificate Monitoring** | Daily | SSL cert expiration, configuration |
| **Compliance Status** | Quarterly | Certification renewals, audit findings |
| **Financial Health** | Quarterly | Bankruptcy risk, acquisition news |
| **Reassessment** | Per tier schedule | Full security questionnaire |

**Vendor Monitoring Dashboard Metrics:**

```
┌─────────────────────────────────────────────────────────────┐
│            VENDOR SECURITY MONITORING DASHBOARD             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  OVERALL VENDOR RISK                                        │
│  Critical Vendors: 5    Risk Score: ████████░░ 78/100      │
│  High Vendors: 12       Risk Score: ███████░░░ 71/100      │
│  Medium Vendors: 34     Risk Score: █████████░ 85/100      │
│                                                             │
│  ALERTS                                                     │
│  ⚠️  2 vendors with degraded security ratings              │
│  ⚠️  1 vendor SOC 2 report expiring in 30 days             │
│  🔴 1 vendor mentioned in breach notification              │
│                                                             │
│  SUPPLY CHAIN                                               │
│  Dependencies: 342      Critical CVEs: 0                    │
│  Outdated: 23 (6.7%)    High CVEs: 3                       │
│                                                             │
│  ACTIONS REQUIRED                                           │
│  • Review Vendor X breach notification (Due: Today)         │
│  • Update axios to 1.6.0 (CVE-2023-xxxx)                   │
│  • Request Vendor Y updated SOC 2 (Due: Next week)         │
└─────────────────────────────────────────────────────────────┘
```

---

## Level 3: RUN - Vendor Security Leadership

### Learning Objectives

After completing L3, learners will be able to:

1. Lead cross-functional vendor security programs
2. Contribute to industry vendor security standards
3. Implement advanced supply chain security (SLSA, Sigstore)
4. Measure and optimize vendor risk management effectiveness

---

### 3.1 Vendor Security Community of Practice

**Cross-Functional Collaboration Model:**

```
                    ┌─────────────────┐
                    │ Vendor Security │
                    │    Community    │
                    └────────┬────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
        ▼                    ▼                    ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│  Procurement  │   │    Legal      │   │   Security    │
│               │   │               │   │               │
│ • RFP process │   │ • Contracts   │   │ • Assessments │
│ • Selection   │   │ • DPAs        │   │ • Monitoring  │
│ • Onboarding  │   │ • Liability   │   │ • Incidents   │
└───────────────┘   └───────────────┘   └───────────────┘
        │                    │                    │
        ▼                    ▼                    ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│  Engineering  │   │   Compliance  │   │    Finance    │
│               │   │               │   │               │
│ • Supply chain│   │ • Regulatory  │   │ • Insurance   │
│ • Integration │   │ • Audits      │   │ • Budget      │
│ • SBOMs       │   │ • Reporting   │   │ • ROI         │
└───────────────┘   └───────────────┘   └───────────────┘
```

**Community Activities:**

| Activity | Frequency | Participants | Purpose |
|----------|-----------|--------------|---------|
| Vendor Security Council | Monthly | All stakeholders | Strategic decisions, policy updates |
| Vendor Review Board | Weekly | Security, Procurement, Legal | Vendor approval/rejection decisions |
| Supply Chain Working Group | Bi-weekly | Engineering, Security | Dependency management |
| Incident Response Sync | As needed | Security, Legal, affected teams | Vendor security incidents |
| Training Sessions | Quarterly | All vendor-facing roles | Skill development |

---

### 3.2 Advanced Supply Chain Security

**SLSA (Supply chain Levels for Software Artifacts):**

| Level | Requirements | Protection |
|-------|--------------|------------|
| **SLSA 1** | Build process documented | Basic transparency |
| **SLSA 2** | Hosted build service, authenticated provenance | Tamper resistance |
| **SLSA 3** | Hardened build platform, non-falsifiable provenance | Moderate confidence |
| **SLSA 4** | Hermetic, reproducible builds, two-person review | High confidence |

**Implementing SLSA:**

```yaml
# Example: GitHub Actions with SLSA provenance

name: Build with SLSA Provenance
on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      id-token: write  # For OIDC
      contents: read
      attestations: write

    steps:
      - uses: actions/checkout@v4

      - name: Build artifact
        run: |
          npm ci
          npm run build
          tar -czvf artifact.tar.gz dist/

      - name: Generate SLSA provenance
        uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v1.9.0
        with:
          artifact_path: artifact.tar.gz

      - name: Upload artifact with provenance
        uses: actions/upload-artifact@v3
        with:
          name: artifact-with-provenance
          path: |
            artifact.tar.gz
            artifact.tar.gz.intoto.jsonl
```

**Sigstore for Artifact Signing:**

```bash
# Sign a container image
cosign sign --key cosign.key myregistry/myimage:v1.0

# Verify a signed image
cosign verify --key cosign.pub myregistry/myimage:v1.0

# Sign with keyless (OIDC identity)
cosign sign myregistry/myimage:v1.0
# Uses ambient OIDC credentials (GitHub Actions, etc.)

# Verify with keyless
cosign verify myregistry/myimage:v1.0 \
  --certificate-identity user@example.com \
  --certificate-oidc-issuer https://accounts.google.com
```

---

### 3.3 Fourth-Party Risk Management

**Managing Vendor's Vendors:**

```
Your Organization
       │
       ▼
┌─────────────────┐
│ Direct Vendor   │ ← Third Party (you assess directly)
│ (e.g., CRM SaaS)│
└────────┬────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌────────┐ ┌────────┐
│ AWS    │ │ Stripe │ ← Fourth Parties (vendor's vendors)
│        │ │        │
└────────┘ └────────┘
```

**Fourth-Party Risk Assessment:**

| Question | What to Ask Vendor |
|----------|-------------------|
| Who are your subprocessors? | Complete list of fourth parties |
| What data do they access? | Data flow to fourth parties |
| How do you assess them? | Vendor's vendor management program |
| What's your liability? | Contract terms with subprocessors |
| How will we be notified? | Subprocessor change notification |

**Contract Language for Fourth-Party Risk:**

```
The Vendor shall:
- Maintain a current list of subprocessors and provide to Customer upon request
- Notify Customer at least 30 days before engaging new subprocessors
  for Customer Data processing
- Ensure subprocessors meet security requirements equivalent to this Agreement
- Remain fully liable for subprocessor actions
- Allow Customer to object to new subprocessors with resolution process
```

---

### 3.4 Vendor Security Metrics

**Key Performance Indicators:**

| Metric | Definition | Target |
|--------|------------|--------|
| **Assessment Coverage** | % of vendors assessed per tier requirements | 100% |
| **Assessment Timeliness** | % of assessments completed on schedule | >95% |
| **Critical Finding Remediation** | Time to remediate critical vendor findings | <30 days |
| **Vendor Incident Rate** | # of security incidents from vendors | Decreasing |
| **Supply Chain Vulnerability MTTR** | Time to remediate critical CVEs | <7 days |
| **SBOM Coverage** | % of applications with complete SBOMs | >90% |
| **Contract Security Compliance** | % of contracts with required security clauses | 100% |

**Vendor Security Scorecard:**

```
Vendor Security Program Scorecard - Q1 2025

Assessment Coverage:      ██████████ 100% (Target: 100%)
Assessment Timeliness:    █████████░  92% (Target: 95%)
Critical Remediation:     ████████░░  21 days (Target: <30)
Vendor Incidents:         ██████████   2 (Down from 5)
CVE MTTR:                 █████████░   5 days (Target: <7)
SBOM Coverage:            ███████░░░  78% (Target: 90%)
Contract Compliance:      █████████░  95% (Target: 100%)

Overall Score: B+ (improving from B last quarter)

Priority Actions:
1. Increase SBOM coverage for legacy applications
2. Update 3 contracts missing security clauses
3. Improve assessment scheduling automation
```

---

### 3.5 Industry Contributions

**Standards and Frameworks:**

| Standard | Focus | How to Contribute |
|----------|-------|-------------------|
| **NIST SCRM** | Supply chain risk management | Comment on drafts, case studies |
| **SLSA** | Software supply chain integrity | Implementation guides, tools |
| **OpenSSF** | Open source security | Projects, working groups |
| **Shared Assessments** | Vendor assessment standards | SIG questionnaire updates |
| **ISO 27036** | Supplier relationship security | National body participation |

**Thought Leadership Activities:**

1. **Publish case studies** - Share vendor security program successes
2. **Open source tools** - Contribute vendor assessment automation
3. **Conference presentations** - RSA, vendor risk conferences
4. **Industry groups** - FAIR Institute, ISACs, vendor risk forums
5. **Regulatory engagement** - Comment on vendor security regulations

---

## Module Summary

| Level | Focus | Key Outcomes |
|-------|-------|--------------|
| **L1: Crawl** | Basics | Understand vendor/supply chain risks, basic assessment |
| **L2: Walk** | Comprehensive | Conduct assessments, analyze SBOMs, negotiate contracts |
| **L3: Run** | Leadership | Lead programs, SLSA, fourth-party risk, industry contribution |

---

## Hands-On Labs

### Lab 1: Vendor Security Quick Assessment (L1)
Complete a basic vendor security assessment using the checklist.

### Lab 2: Supply Chain Vulnerability Scan (L1)
Run SCA tools on a sample project and remediate findings.

### Lab 3: SOC 2 Report Analysis (L2)
Review a sample SOC 2 report and extract key findings.

### Lab 4: SBOM Generation and Analysis (L2)
Generate SBOM for an application and analyze for risks.

### Lab 5: Contract Security Review (L2)
Review vendor contract for security gaps and propose improvements.

### Lab 6: SLSA Implementation (L3)
Implement SLSA Level 2 provenance for a build pipeline.

### Lab 7: Vendor Security Program Design (L3)
Design a complete vendor security program for a hypothetical organization.

---

## Resources

### Vendor Security
- [NIST SP 800-161: Supply Chain Risk Management](https://csrc.nist.gov/publications/detail/sp/800-161/rev-1/final)
- [Shared Assessments SIG Questionnaire](https://sharedassessments.org/)
- [CAIQ (Consensus Assessments Initiative Questionnaire)](https://cloudsecurityalliance.org/star)

### Supply Chain Security
- [SLSA Framework](https://slsa.dev/)
- [Sigstore](https://sigstore.dev/)
- [OpenSSF Scorecard](https://securityscorecards.dev/)
- [SBOM Formats (SPDX, CycloneDX)](https://www.cisa.gov/sbom)

### Tools
- [Syft](https://github.com/anchore/syft) - SBOM generation
- [Grype](https://github.com/anchore/grype) - Vulnerability scanner
- [Trivy](https://trivy.dev/) - Comprehensive scanner
- [Cosign](https://github.com/sigstore/cosign) - Container signing

---

## Related Modules

- [Core Module: HAI Security Fundamentals](./00-core-module-hai-fundamentals.md)
- [Software Domain Training](./01-software-domain.md)
- [Infrastructure Domain Training](./03-infrastructure-domain.md)

---

**Document Version:** 1.0
**Framework:** HAIAMM v2.0
**Practice:** Education & Guidance (EG)
**Domain:** Vendors
**Author:** Verifhai

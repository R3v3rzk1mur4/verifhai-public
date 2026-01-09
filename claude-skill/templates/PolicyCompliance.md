# Policy & Compliance (PC) Template

## Document Control

| Field | Value |
|-------|-------|
| Project | [Project Name] |
| Version | 1.0 |
| Date | [YYYY-MM-DD] |
| Author | [Author Name] |
| Status | Draft / Approved |

---

## 1. HAI Security Policy

### 1.1 Policy Statement

```
[Organization Name] is committed to the secure development and operation
of Human-Assisted Intelligence (HAI) systems. This policy establishes
mandatory security requirements for all AI agents, LLM integrations,
and automated decision-making systems.

All HAI systems MUST:
- Operate within defined permission boundaries
- Log all actions for audit and compliance
- Protect user data and privacy
- Implement defense-in-depth security controls
- Comply with applicable regulations and standards
```

### 1.2 Scope

This policy applies to:

| System Type | In Scope | Notes |
|-------------|----------|-------|
| AI Agents | Yes | Autonomous agents using tools |
| LLM Integrations | Yes | Applications calling LLM APIs |
| AI Pipelines | Yes | ML/AI data processing workflows |
| AI Infrastructure | Yes | Platforms hosting AI models |
| Internal AI tools | Yes | Developer productivity tools |
| Third-party AI services | Partial | Vendor assessment required |

### 1.3 Policy Ownership

| Role | Name | Responsibility |
|------|------|---------------|
| Policy Owner | [Name] | Approve changes, ensure enforcement |
| Policy Author | [Name] | Draft updates, manage reviews |
| Compliance Lead | [Name] | Monitor adherence, report violations |

---

## 2. Security Requirements Policy

### 2.1 Permission Boundaries (Mandatory)

**PC-PB-001: Explicit Permission Model**
All HAI systems SHALL define explicit permission boundaries:
- **ALLOWED**: Actions the system CAN perform
- **PROHIBITED**: Actions the system CANNOT perform
- **MUST**: Required behaviors in all circumstances

**PC-PB-002: Deny by Default**
All HAI systems SHALL deny any action not explicitly allowed.

**PC-PB-003: Least Privilege**
All HAI systems SHALL operate with the minimum permissions necessary.

**PC-PB-004: Permission Verification**
All HAI systems SHALL verify permissions before each action.

### 2.2 Data Protection (Mandatory)

**PC-DP-001: PII Handling**
HAI systems SHALL NOT:
- Store PII without explicit authorization
- Log PII in plain text
- Expose PII in AI outputs without sanitization

**PC-DP-002: Secret Management**
HAI systems SHALL:
- Store secrets in approved secret managers (not code)
- Rotate secrets according to schedule
- Audit secret access

**PC-DP-003: Data Classification**
All data processed by HAI systems SHALL be classified:
| Classification | Handling Requirements |
|----------------|----------------------|
| Public | Standard controls |
| Internal | Access controls, logging |
| Confidential | Encryption, access controls, audit |
| Restricted | Encryption, MFA, approval workflow |

### 2.3 AI-Specific Requirements (Mandatory)

**PC-AI-001: Prompt Injection Defense**
All HAI systems SHALL implement prompt injection defenses:
- Separate system instructions from user input
- Mark user content as untrusted
- Validate AI outputs before execution

**PC-AI-002: Tool Safety**
All tool integrations SHALL:
- Validate inputs against defined schemas
- Enforce rate limits
- Timeout after defined period
- Sanitize outputs

**PC-AI-003: Agent Containment**
AI agents SHALL:
- Have iteration limits
- Have resource budgets
- Have external kill switch
- Fail secure on errors

**PC-AI-004: Action Logging**
All HAI actions SHALL be logged including:
- Tool invocations with parameters
- User inputs (sanitized)
- AI outputs
- Permission decisions
- Errors and anomalies

---

## 3. Compliance Framework

### 3.1 Regulatory Requirements

| Regulation | Applicability | Key Requirements | Status |
|------------|---------------|------------------|--------|
| GDPR | EU users | Data protection, consent, right to explanation | [ ] |
| CCPA | CA users | Privacy rights, data access, deletion | [ ] |
| SOC 2 | Enterprise | Security, availability, confidentiality | [ ] |
| HIPAA | Healthcare | PHI protection, access controls | [ ] |
| PCI DSS | Payments | Cardholder data protection | [ ] |
| [Regulation] | [When applicable] | [What's required] | [ ] |

### 3.2 AI-Specific Regulations

| Framework | Applicability | Key Requirements | Status |
|-----------|---------------|------------------|--------|
| EU AI Act | EU market | Risk assessment, transparency, human oversight | [ ] |
| NIST AI RMF | US Federal | Risk management, governance | [ ] |
| ISO/IEC 42001 | Certification | AI management system | [ ] |
| [Framework] | [When applicable] | [What's required] | [ ] |

### 3.3 Industry Standards

| Standard | Applicability | Key Areas | Status |
|----------|---------------|-----------|--------|
| OWASP Top 10 for LLM | All LLM systems | LLM-specific vulnerabilities | [ ] |
| MITRE ATLAS | All AI systems | AI attack patterns | [ ] |
| HAIAMM | All HAI systems | Maturity assessment | [ ] |
| [Standard] | [When applicable] | [Focus areas] | [ ] |

---

## 4. Compliance Controls

### 4.1 Control Mapping

| Policy Requirement | Control | Implementation | Evidence |
|-------------------|---------|----------------|----------|
| PC-PB-001 | Permission Gate | PermissionGate class | Code review, tests |
| PC-PB-002 | Deny by Default | Default deny in gate | Config audit |
| PC-DP-001 | PII Sanitization | Sanitizer middleware | Log audit |
| PC-AI-001 | Injection Defense | InputValidator class | Injection tests |
| PC-AI-004 | Action Logging | SecureLogger class | Log completeness |

### 4.2 Control Assessment

| Control | Last Assessed | Effectiveness | Gaps | Remediation |
|---------|--------------|---------------|------|-------------|
| Permission Gate | [Date] | [High/Med/Low] | [Issues] | [Actions] |
| Input Validation | [Date] | [High/Med/Low] | [Issues] | [Actions] |
| Action Logging | [Date] | [High/Med/Low] | [Issues] | [Actions] |
| [Control] | [Date] | [Effectiveness] | [Gaps] | [Actions] |

---

## 5. Governance Procedures

### 5.1 Policy Review

| Activity | Frequency | Responsible | Output |
|----------|-----------|-------------|--------|
| Policy review | Annual | Policy Owner | Updated policy |
| Control assessment | Quarterly | Compliance Lead | Assessment report |
| Exception review | Monthly | Security Lead | Exception status |
| Audit preparation | Per audit | Compliance Lead | Evidence package |

### 5.2 Exception Process

```
┌─────────────────────────────────────────────────────────────────┐
│                    EXCEPTION REQUEST                             │
│                                                                  │
│  1. Requester submits exception request                         │
│     - Business justification                                    │
│     - Risk assessment                                           │
│     - Compensating controls                                     │
│     - Duration                                                  │
│                                                                  │
│  2. Security Lead reviews                                       │
│     - Risk evaluation                                           │
│     - Compensating control adequacy                             │
│     - Recommendation                                            │
│                                                                  │
│  3. Policy Owner approves/denies                               │
│     - Critical/High risk: Executive approval required           │
│     - Medium risk: Policy Owner approval                        │
│     - Low risk: Security Lead approval                          │
│                                                                  │
│  4. If approved:                                                │
│     - Document in exception register                            │
│     - Implement compensating controls                           │
│     - Schedule review                                           │
│                                                                  │
│  5. Regular review                                              │
│     - Monthly status update                                     │
│     - Reassess risk                                             │
│     - Extend/close exception                                    │
└─────────────────────────────────────────────────────────────────┘
```

### 5.3 Exception Register

| Exception ID | Requirement | Justification | Compensating Controls | Expiry | Owner | Status |
|--------------|-------------|---------------|----------------------|--------|-------|--------|
| EXC-001 | [Requirement] | [Why needed] | [Alternative controls] | [Date] | [Who] | [Status] |

---

## 6. Compliance Monitoring

### 6.1 Continuous Monitoring

| Control Area | Monitoring Method | Frequency | Alert Threshold |
|--------------|------------------|-----------|-----------------|
| Permission enforcement | Log analysis | Real-time | >10 denials/hour |
| Data protection | DLP scanning | Daily | Any PII leak |
| Logging completeness | Log audit | Hourly | <95% coverage |
| Policy violations | SIEM alerts | Real-time | Any violation |

### 6.2 Audit Trail Requirements

All HAI systems SHALL maintain audit trails that:

- **Completeness**: Capture all security-relevant events
- **Integrity**: Protected from tampering (hash chain, signatures)
- **Availability**: Retained for [X] years
- **Confidentiality**: Access restricted to authorized personnel
- **Non-repudiation**: Events attributable to actors

### 6.3 Compliance Reporting

| Report | Audience | Frequency | Content |
|--------|----------|-----------|---------|
| Compliance dashboard | Security team | Real-time | Control status |
| Compliance summary | Leadership | Monthly | Posture, gaps, remediation |
| Audit report | Auditors | Per audit | Evidence, findings |
| Regulatory filing | Regulators | As required | Required disclosures |

---

## 7. Training & Awareness

### 7.1 Mandatory Training

| Training | Audience | Frequency | Duration |
|----------|----------|-----------|----------|
| HAI Security Fundamentals | All developers | Annual | 2 hours |
| Secure AI Development | AI/ML engineers | Annual | 4 hours |
| Policy & Compliance | All staff | Annual | 1 hour |
| Incident Response | On-call engineers | Quarterly | 2 hours |

### 7.2 Training Records

| Employee | Training | Completion Date | Expiry | Status |
|----------|----------|-----------------|--------|--------|
| [Name] | [Training] | [Date] | [Date] | [Current/Expired] |

---

## 8. Violation Handling

### 8.1 Violation Categories

| Category | Description | Examples | Response |
|----------|-------------|----------|----------|
| Critical | Severe policy breach | Intentional data exfiltration | Immediate suspension, investigation |
| High | Significant violation | Disabled security controls | 24-hour remediation, escalation |
| Medium | Policy non-compliance | Missing logging | 7-day remediation, documented |
| Low | Minor deviation | Incomplete documentation | 30-day remediation, awareness |

### 8.2 Response Procedure

1. **Detect**: Identify violation through monitoring, audit, or report
2. **Assess**: Determine severity and impact
3. **Contain**: Stop ongoing harm
4. **Investigate**: Determine root cause
5. **Remediate**: Fix the issue
6. **Document**: Record in violation register
7. **Follow-up**: Ensure non-recurrence

### 8.3 Violation Register

| Violation ID | Date | Category | Description | Root Cause | Remediation | Status |
|--------------|------|----------|-------------|------------|-------------|--------|
| VIO-001 | [Date] | [Severity] | [What happened] | [Why] | [Fix] | [Status] |

---

## Approval

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Policy Owner | | | |
| Legal/Compliance | | | |
| Executive Sponsor | | | |

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | [Date] | [Author] | Initial policy document |

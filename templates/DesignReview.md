# Design Review (DR) Template

## Document Control

| Field | Value |
|-------|-------|
| Review ID | [DR-YYYY-NNN] |
| Project | [Project Name] |
| Feature | [Feature Name] |
| Version | 1.0 |
| Date | [YYYY-MM-DD] |
| Reviewer | [Name] |
| Status | Draft / In Review / Approved |

---

## 1. Design Overview

### 1.1 Feature Description

```
[Provide a 2-3 paragraph description of the feature/system being reviewed]

Purpose: [What problem does this solve?]
Scope: [What is included/excluded?]
Dependencies: [What does this depend on?]
```

### 1.2 Architecture Diagram

```
[Include or reference architecture diagram]

Example:
┌─────────────────────────────────────────────────────────────────┐
│                         TRUST BOUNDARY                           │
│  ┌───────────────┐                                              │
│  │   User Input  │                                              │
│  │   (Untrusted) │                                              │
│  └───────┬───────┘                                              │
│          │                                                       │
│          ▼                                                       │
│  ┌───────────────┐    ┌───────────────┐    ┌───────────────┐   │
│  │    Input      │    │    AI Agent   │    │    Tools      │   │
│  │  Validation   │───▶│   (Logic)     │───▶│  (Actions)    │   │
│  └───────────────┘    └───────────────┘    └───────────────┘   │
│                              │                      │            │
│                              ▼                      ▼            │
│                       ┌───────────────┐    ┌───────────────┐   │
│                       │   LLM API     │    │   Data Store  │   │
│                       │  (External)   │    │  (Internal)   │   │
│                       └───────────────┘    └───────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### 1.3 Data Flow

| Source | Data Type | Destination | Protection |
|--------|-----------|-------------|------------|
| User | Untrusted input | Input Validator | Validation, sanitization |
| Input Validator | Sanitized input | AI Agent | Permission check |
| AI Agent | Tool request | Tool Executor | Schema validation |
| Tool | Result | AI Agent | Output validation |
| AI Agent | Response | User | Sanitization |

---

## 2. Security Design Review Checklist

### 2.1 Permission Design

| ID | Criterion | Status | Notes |
|----|-----------|--------|-------|
| DR-PD-001 | Permission boundaries explicitly defined | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-PD-002 | Allowed actions documented with scope | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-PD-003 | Prohibited actions explicitly listed | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-PD-004 | Deny-by-default architecture | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-PD-005 | Least privilege applied | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-PD-006 | Permission enforcement layer present | [ ] Pass / [ ] Fail / [ ] N/A | |

**Permission Model Review:**

```
ALLOWED (CAN):
- [ ] Actions clearly defined
- [ ] Scope limits specified
- [ ] Conditions documented

PROHIBITED (CANNOT):
- [ ] Dangerous actions listed
- [ ] Rationale documented
- [ ] Enforcement mechanism specified

REQUIRED (MUST):
- [ ] Mandatory behaviors defined
- [ ] Verification method specified
```

### 2.2 Trust Boundary Design

| ID | Criterion | Status | Notes |
|----|-----------|--------|-------|
| DR-TB-001 | Trust boundaries clearly identified | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-TB-002 | All boundary crossings have controls | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-TB-003 | External inputs marked as untrusted | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-TB-004 | Internal/external systems distinguished | [ ] Pass / [ ] Fail / [ ] N/A | |

**Trust Boundary Analysis:**

| Boundary | From | To | Controls |
|----------|------|-----|----------|
| [Name] | [Untrusted/Trusted] | [Component] | [What validates?] |

### 2.3 Input/Output Design

| ID | Criterion | Status | Notes |
|----|-----------|--------|-------|
| DR-IO-001 | Input validation at all entry points | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-IO-002 | Input size limits defined | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-IO-003 | Injection detection designed | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-IO-004 | Output sanitization planned | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-IO-005 | Error messages don't leak info | [ ] Pass / [ ] Fail / [ ] N/A | |

### 2.4 AI/LLM Design

| ID | Criterion | Status | Notes |
|----|-----------|--------|-------|
| DR-AI-001 | System prompt isolation designed | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-AI-002 | User input clearly delimited | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-AI-003 | Prompt injection defenses planned | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-AI-004 | AI output validation designed | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-AI-005 | Goal integrity protection planned | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-AI-006 | Context window management addressed | [ ] Pass / [ ] Fail / [ ] N/A | |

### 2.5 Tool Integration Design

| ID | Criterion | Status | Notes |
|----|-----------|--------|-------|
| DR-TI-001 | Each tool has defined purpose | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-TI-002 | Tool input schemas defined | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-TI-003 | Tool output validation planned | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-TI-004 | Rate limits per tool defined | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-TI-005 | Timeouts configured per tool | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-TI-006 | Dangerous tools require confirmation | [ ] Pass / [ ] Fail / [ ] N/A | |

**Tool Security Assessment:**

| Tool | Purpose | Risk Level | Input Validation | Rate Limit | Timeout |
|------|---------|------------|------------------|------------|---------|
| [Tool name] | [What it does] | [Low/Med/High/Critical] | [Schema defined?] | [Limit] | [Duration] |

### 2.6 Containment Design

| ID | Criterion | Status | Notes |
|----|-----------|--------|-------|
| DR-CT-001 | Iteration limits designed | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-CT-002 | Resource budgets planned | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-CT-003 | Timeout protection designed | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-CT-004 | Kill switch mechanism planned | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-CT-005 | Fail-secure behavior defined | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-CT-006 | Escape paths analyzed and closed | [ ] Pass / [ ] Fail / [ ] N/A | |

**Containment Parameters:**

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Max iterations | [Number] | [Why this limit?] |
| Max tokens | [Number] | [Why this limit?] |
| Timeout | [Duration] | [Why this duration?] |
| Kill switch | [Mechanism] | [How it works?] |

### 2.7 Logging & Monitoring Design

| ID | Criterion | Status | Notes |
|----|-----------|--------|-------|
| DR-LM-001 | Security events identified for logging | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-LM-002 | Log format supports analysis | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-LM-003 | PII sanitization planned | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-LM-004 | Log integrity protection designed | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-LM-005 | Alerting rules defined | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-LM-006 | Anomaly detection considered | [ ] Pass / [ ] Fail / [ ] N/A | |

### 2.8 Data Protection Design

| ID | Criterion | Status | Notes |
|----|-----------|--------|-------|
| DR-DP-001 | Data classification applied | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-DP-002 | PII handling documented | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-DP-003 | Encryption at rest for sensitive data | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-DP-004 | Encryption in transit (TLS) | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-DP-005 | Data retention policy defined | [ ] Pass / [ ] Fail / [ ] N/A | |
| DR-DP-006 | Secret management approach defined | [ ] Pass / [ ] Fail / [ ] N/A | |

---

## 3. Threat Analysis for Design

### 3.1 STRIDE for Design

For each component in the design, assess:

| Component | S | T | R | I | D | E | Highest Risk |
|-----------|---|---|---|---|---|---|--------------|
| User Input | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] | [Threat] |
| Input Validator | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] | [Threat] |
| AI Agent | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] | [Threat] |
| Tools | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] | [Threat] |
| LLM API | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] | [Threat] |
| Data Store | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] | [Threat] |

**Legend:** S=Spoofing, T=Tampering, R=Repudiation, I=Info Disclosure, D=DoS, E=Elevation

### 3.2 AI-Specific Threats for Design

| Threat | Applies? | Design Mitigation | Residual Risk |
|--------|----------|-------------------|---------------|
| Direct Prompt Injection | [ ] Yes / [ ] No | [Control] | [Low/Med/High] |
| Indirect Prompt Injection | [ ] Yes / [ ] No | [Control] | [Low/Med/High] |
| Excessive Agency (EA) | [ ] Yes / [ ] No | [Control] | [Low/Med/High] |
| Agent Goal Hijacking (AGH) | [ ] Yes / [ ] No | [Control] | [Low/Med/High] |
| Tool Misuse (TM) | [ ] Yes / [ ] No | [Control] | [Low/Med/High] |
| Rogue Agent (RA) | [ ] Yes / [ ] No | [Control] | [Low/Med/High] |

---

## 4. Design Findings

### 4.1 Findings Summary

| Finding ID | Category | Severity | Description | Recommendation |
|------------|----------|----------|-------------|----------------|
| DR-F-001 | [Category] | [Crit/High/Med/Low] | [Issue] | [Fix] |
| DR-F-002 | [Category] | [Crit/High/Med/Low] | [Issue] | [Fix] |

### 4.2 Detailed Findings

#### DR-F-001: [Finding Title]

**Severity:** [Critical/High/Medium/Low]

**Category:** [Permission/Trust Boundary/Input-Output/AI/Tool/Containment/Logging/Data]

**Description:**
```
[Detailed description of the security design issue]
```

**Risk:**
```
[What could go wrong if this design flaw is implemented?]
```

**Recommendation:**
```
[Specific guidance on how to fix the design]
```

**Reference:**
- Pattern: [Link to HAI-Security-Architecture-Patterns.md section if applicable]
- Standard: [Relevant standard or requirement]

---

## 5. Design Recommendations

### 5.1 Required Changes (Must Fix Before Implementation)

| Rec ID | Finding | Change Required | Owner |
|--------|---------|-----------------|-------|
| DR-R-001 | DR-F-001 | [Specific change] | [Who] |

### 5.2 Suggested Improvements (Should Consider)

| Rec ID | Area | Improvement | Benefit |
|--------|------|-------------|---------|
| DR-S-001 | [Area] | [Suggestion] | [Why helpful] |

### 5.3 Pattern References

The following patterns from HAI-Security-Architecture-Patterns.md should be applied:

| Pattern | Applicability | Implementation Notes |
|---------|---------------|---------------------|
| 1. Secure Logging | [Where] | [Notes] |
| 2. Permission Enforcement Gate | [Where] | [Notes] |
| 3. Input Validation & Injection Defense | [Where] | [Notes] |
| 4. Tool Safety & Sandboxing | [Where] | [Notes] |
| 5. Error Handling & Fail Secure | [Where] | [Notes] |

---

## 6. Review Decision

### 6.1 Overall Assessment

| Criteria | Status |
|----------|--------|
| Permission design adequate | [ ] Yes / [ ] No - requires changes |
| Trust boundaries appropriate | [ ] Yes / [ ] No - requires changes |
| AI/LLM security addressed | [ ] Yes / [ ] No - requires changes |
| Tool safety designed | [ ] Yes / [ ] No - requires changes |
| Containment sufficient | [ ] Yes / [ ] No - requires changes |

### 6.2 Review Outcome

| Decision | Criteria |
|----------|----------|
| [ ] **Approved** | No critical/high findings, design is secure |
| [ ] **Conditionally Approved** | Minor findings, can proceed with noted fixes |
| [ ] **Requires Redesign** | Critical/high findings, must fix before implementation |
| [ ] **Rejected** | Fundamental security flaws, need new approach |

### 6.3 Conditions for Approval

If conditionally approved, the following must be addressed:

| Condition | Finding Reference | Due |
|-----------|------------------|-----|
| [What must change] | DR-F-XXX | [Before what milestone] |

---

## 7. Sign-Off

| Role | Name | Date | Decision |
|------|------|------|----------|
| Security Reviewer | | | [ ] Approved / [ ] Conditionally Approved / [ ] Rejected |
| Architecture Lead | | | [ ] Approved / [ ] Conditionally Approved / [ ] Rejected |
| Engineering Lead | | | Acknowledged findings |

---

## 8. Follow-Up

### 8.1 Implementation Review Required

After implementation, the following areas require security review:

| Area | Why | Reference Finding |
|------|-----|------------------|
| [Component] | [Reason] | DR-F-XXX |

### 8.2 Testing Requirements

Security testing must cover:

| Test Type | Scope | Criteria |
|-----------|-------|----------|
| Permission boundary tests | [What to test] | [Pass criteria] |
| Injection tests | [What to test] | [Pass criteria] |
| Containment tests | [What to test] | [Pass criteria] |

---

## Revision History

| Version | Date | Reviewer | Changes |
|---------|------|----------|---------|
| 1.0 | [Date] | [Name] | Initial design review |

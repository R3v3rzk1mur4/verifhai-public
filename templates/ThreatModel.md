# Threat Model Template

## Document Control

| Field | Value |
|-------|-------|
| Project | [Project Name] |
| Version | 1.0 |
| Date | [YYYY-MM-DD] |
| Author | [Author Name] |
| Methodology | STRIDE + AI TTPs |

---

## 1. System Overview

### 1.1 Description
[Describe the AI system being threat modeled]

### 1.2 Architecture Diagram
```
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

### 1.3 Assets to Protect

| Asset | Classification | Impact if Compromised |
|-------|---------------|----------------------|
| User data | Confidential | Privacy breach |
| API credentials | Secret | Unauthorized access |
| AI model | Proprietary | IP theft |
| System integrity | Critical | Full compromise |

### 1.4 Trust Boundaries

| Boundary | Description | Crossing Points |
|----------|-------------|-----------------|
| User input | External → Internal | Input validation |
| LLM API | Internal → External | API calls |
| Tool execution | Agent → System | Tool invocations |

---

## 2. STRIDE Analysis

### 2.1 Spoofing

| ID | Threat | Component | Impact | Likelihood | Risk |
|----|--------|-----------|--------|------------|------|
| S-001 | Attacker impersonates user | Auth | High | Medium | High |
| S-002 | Fake API responses | LLM API | High | Low | Medium |
| S-003 | [Threat] | [Component] | [Impact] | [Likelihood] | [Risk] |

**Mitigations:**
- S-001: Implement strong authentication
- S-002: Validate API response signatures

### 2.2 Tampering

| ID | Threat | Component | Impact | Likelihood | Risk |
|----|--------|-----------|--------|------------|------|
| T-001 | Modified user inputs | Input layer | High | High | Critical |
| T-002 | Tampered tool responses | Tools | Medium | Low | Low |
| T-003 | [Threat] | [Component] | [Impact] | [Likelihood] | [Risk] |

**Mitigations:**
- T-001: Input validation, integrity checks
- T-002: Validate tool output schemas

### 2.3 Repudiation

| ID | Threat | Component | Impact | Likelihood | Risk |
|----|--------|-----------|--------|------------|------|
| R-001 | User denies actions | Agent | Medium | Medium | Medium |
| R-002 | No audit trail | Logging | High | High | High |
| R-003 | [Threat] | [Component] | [Impact] | [Likelihood] | [Risk] |

**Mitigations:**
- R-001: Comprehensive action logging
- R-002: Immutable audit logs

### 2.4 Information Disclosure

| ID | Threat | Component | Impact | Likelihood | Risk |
|----|--------|-----------|--------|------------|------|
| I-001 | AI leaks sensitive data | Output | High | Medium | High |
| I-002 | Credentials in logs | Logging | Critical | Medium | Critical |
| I-003 | [Threat] | [Component] | [Impact] | [Likelihood] | [Risk] |

**Mitigations:**
- I-001: Output sanitization, PII filtering
- I-002: Secure logging practices

### 2.5 Denial of Service

| ID | Threat | Component | Impact | Likelihood | Risk |
|----|--------|-----------|--------|------------|------|
| D-001 | Resource exhaustion | Agent | Medium | Medium | Medium |
| D-002 | Infinite loops | Tools | High | Low | Medium |
| D-003 | [Threat] | [Component] | [Impact] | [Likelihood] | [Risk] |

**Mitigations:**
- D-001: Rate limiting, resource quotas
- D-002: Iteration limits, timeouts

### 2.6 Elevation of Privilege

| ID | Threat | Component | Impact | Likelihood | Risk |
|----|--------|-----------|--------|------------|------|
| E-001 | Agent gains extra permissions | Permission gate | Critical | Medium | Critical |
| E-002 | Tool access escalation | Tools | High | Low | Medium |
| E-003 | [Threat] | [Component] | [Impact] | [Likelihood] | [Risk] |

**Mitigations:**
- E-001: Strict permission enforcement, deny by default
- E-002: Tool sandboxing

---

## 3. AI-Specific Threats

### 3.1 Prompt Injection

| ID | Threat | Vector | Impact | Likelihood | Risk |
|----|--------|--------|--------|------------|------|
| PI-001 | Direct prompt injection | User input | Critical | High | Critical |
| PI-002 | Indirect injection via data | External data | High | Medium | High |
| PI-003 | Instruction override | Crafted prompts | Critical | Medium | Critical |

**Mitigations:**
- Separate system prompts from user input
- Mark user content as untrusted
- Validate AI outputs before use
- Input/output filtering

### 3.2 Excessive Agency (EA)

| ID | Threat | Vector | Impact | Likelihood | Risk |
|----|--------|--------|--------|------------|------|
| EA-001 | Agent has file system access | Tool config | High | Medium | High |
| EA-002 | Agent can execute code | Tool config | Critical | Medium | Critical |
| EA-003 | Agent can make network calls | Tool config | Medium | High | High |

**Mitigations:**
- Minimal permission grants
- Explicit allowlists
- Permission checks on every action
- Regular permission audits

### 3.3 Agent Goal Hijack (AGH)

| ID | Threat | Vector | Impact | Likelihood | Risk |
|----|--------|--------|--------|------------|------|
| AGH-001 | Goal override via prompt | User input | Critical | Medium | Critical |
| AGH-002 | Multi-turn goal drift | Conversation | High | Low | Medium |
| AGH-003 | Conflicting instructions | Edge cases | Medium | Low | Low |

**Mitigations:**
- Immutable system prompts
- Goal integrity checks
- Context boundary enforcement
- Conversation monitoring

### 3.4 Tool Misuse (TM)

| ID | Threat | Vector | Impact | Likelihood | Risk |
|----|--------|--------|--------|------------|------|
| TM-001 | Path traversal via file tool | Tool parameters | High | Medium | High |
| TM-002 | Command injection via shell tool | Tool parameters | Critical | Medium | Critical |
| TM-003 | API abuse via network tool | Tool parameters | Medium | High | High |

**Mitigations:**
- Tool input validation
- Parameter sanitization
- Rate limiting per tool
- Output validation

### 3.5 Rogue Agents (RA)

| ID | Threat | Vector | Impact | Likelihood | Risk |
|----|--------|--------|--------|------------|------|
| RA-001 | Agent ignores termination | Logic flaw | High | Low | Medium |
| RA-002 | Agent spawns sub-agents | Agent config | High | Low | Medium |
| RA-003 | Agent modifies own code | Tool access | Critical | Very Low | Medium |

**Mitigations:**
- Hard iteration limits
- Resource budgets
- External kill switch
- Behavior monitoring
- Containment patterns

---

## 4. Risk Summary

### 4.1 Risk Matrix

| Likelihood ↓ / Impact → | Low | Medium | High | Critical |
|-------------------------|-----|--------|------|----------|
| **High** | Medium | High | Critical | Critical |
| **Medium** | Low | Medium | High | Critical |
| **Low** | Low | Low | Medium | High |
| **Very Low** | Low | Low | Low | Medium |

### 4.2 Top Risks

| Rank | Threat ID | Description | Risk Level | Status |
|------|-----------|-------------|------------|--------|
| 1 | PI-001 | Direct prompt injection | Critical | Open |
| 2 | EA-002 | Code execution capability | Critical | Open |
| 3 | AGH-001 | Goal override | Critical | Mitigated |
| 4 | TM-002 | Command injection | Critical | Mitigated |
| 5 | I-001 | Data leakage | High | Open |

---

## 5. Mitigation Tracking

| Threat | Mitigation | Owner | Due Date | Status |
|--------|------------|-------|----------|--------|
| PI-001 | Input separation | [Name] | [Date] | [ ] Open |
| EA-002 | Remove code exec tool | [Name] | [Date] | [ ] Open |
| AGH-001 | Goal integrity check | [Name] | [Date] | [x] Done |
| TM-002 | Input validation | [Name] | [Date] | [x] Done |
| I-001 | Output filtering | [Name] | [Date] | [ ] Open |

---

## 6. Review Schedule

| Review Type | Frequency | Last Review | Next Review |
|-------------|-----------|-------------|-------------|
| Full threat model | Quarterly | [Date] | [Date] |
| New feature review | Per feature | - | - |
| Incident-triggered | As needed | - | - |

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | [Date] | [Author] | Initial threat model |

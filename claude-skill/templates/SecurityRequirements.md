# Security Requirements Template

## Document Control

| Field | Value |
|-------|-------|
| Project | [Project Name] |
| Version | 1.0 |
| Date | [YYYY-MM-DD] |
| Author | [Author Name] |
| Status | Draft / Approved |

---

## 1. AI System Overview

### 1.1 Purpose
[Describe what the AI system does in 2-3 sentences]

### 1.2 AI Type
- [ ] AI Agent (autonomous, uses tools)
- [ ] LLM Integration (API calls)
- [ ] AI Pipeline (data processing)
- [ ] AI Infrastructure (hosting/serving)

### 1.3 Risk Profile

**Data Access:**
- [ ] User data / PII
- [ ] File system
- [ ] Network / APIs
- [ ] Databases
- [ ] Code execution
- [ ] Financial systems
- [ ] Authentication

**User Exposure:**
- [ ] Internal team
- [ ] Internal org
- [ ] External customers
- [ ] Public

---

## 2. Permission Boundaries

### 2.1 Allowed Actions (CAN)
The AI system SHALL be permitted to:

| ID | Action | Scope | Conditions |
|----|--------|-------|------------|
| CAN-001 | [Action] | [Scope] | [Conditions] |
| CAN-002 | [Action] | [Scope] | [Conditions] |

### 2.2 Prohibited Actions (CANNOT)
The AI system SHALL NOT:

| ID | Action | Reason | Risk |
|----|--------|--------|------|
| CANNOT-001 | [Action] | [Why prohibited] | [Risk if violated] |
| CANNOT-002 | [Action] | [Why prohibited] | [Risk if violated] |

### 2.3 Required Behaviors (MUST)
The AI system MUST:

| ID | Behavior | Verification |
|----|----------|--------------|
| MUST-001 | Log all actions | Log audit |
| MUST-002 | Respect rate limits | Rate limit tests |
| MUST-003 | [Behavior] | [How to verify] |

---

## 3. Security Requirements by Category

### 3.1 SR-INPUT: Input Validation

#### SR-INPUT-001: Input Boundary Validation
The AI system SHALL validate all input at trust boundaries.
- **Rationale:** Prevents injection and malformed data
- **Verification:** Fuzz testing, unit tests
- **Priority:** Critical

#### SR-INPUT-002: Input Size Limits
The AI system SHALL enforce maximum input sizes.
- **Max prompt length:** [X] tokens
- **Max file size:** [X] MB
- **Rationale:** Prevents resource exhaustion
- **Verification:** Limit tests
- **Priority:** High

### 3.2 SR-AI: AI-Specific Security

#### SR-AI-001: Prompt Injection Defense
The AI system SHALL implement prompt injection defenses:
- Separate system instructions from user input
- Mark user input as untrusted
- Validate AI outputs before use
- **Rationale:** Prevents behavior manipulation
- **Verification:** Prompt injection tests
- **Priority:** Critical

#### SR-AI-002: Permission Enforcement
The AI system SHALL enforce permission boundaries from Section 2.
- Check permissions before each action
- Deny by default
- Log all permission decisions
- **Rationale:** Implements least privilege
- **Verification:** Permission tests
- **Priority:** Critical

#### SR-AI-003: Action Logging
The AI system SHALL log all actions:
- Tool invocations with parameters
- User inputs (sanitized)
- AI outputs
- Timestamps and context
- **Rationale:** Enables audit and detection
- **Verification:** Log completeness audit
- **Priority:** High

#### SR-AI-004: Resource Limits
The AI system SHALL enforce resource limits:
- Max iterations: [X]
- Max tokens: [X]
- Timeout: [X] seconds
- **Rationale:** Prevents runaway agents
- **Verification:** Limit tests
- **Priority:** High

### 3.3 SR-DATA: Data Protection

#### SR-DATA-001: Sensitive Data Handling
The AI system SHALL NOT:
- Store credentials in code
- Log sensitive data
- Expose PII in outputs
- **Rationale:** Prevents data leakage
- **Verification:** Code review, log audit
- **Priority:** Critical

#### SR-DATA-002: Output Sanitization
The AI system SHALL sanitize outputs:
- Remove internal metadata
- Redact sensitive patterns
- Validate output format
- **Rationale:** Prevents information disclosure
- **Verification:** Output validation tests
- **Priority:** High

### 3.4 SR-AUTH: Authentication

#### SR-AUTH-001: API Authentication
The AI system SHALL authenticate all API calls.
- Use secure credential storage
- Rotate credentials regularly
- Audit credential access
- **Rationale:** Prevents unauthorized access
- **Verification:** Auth tests
- **Priority:** Critical

---

## 4. Traceability Matrix

| Requirement | Threat | Control | Test | Status |
|-------------|--------|---------|------|--------|
| SR-INPUT-001 | Injection | Input validation | UT-INPUT-001 | [ ] |
| SR-AI-001 | Prompt injection | Separation | UT-AI-001 | [ ] |
| SR-AI-002 | Excessive Agency | Permission gate | UT-AI-002 | [ ] |
| SR-DATA-001 | Data leak | Sanitization | UT-DATA-001 | [ ] |

---

## 5. Approval

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Author | | | |
| Security Review | | | |
| Approval | | | |

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | [Date] | [Author] | Initial release |

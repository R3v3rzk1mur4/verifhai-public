# Secure Architecture (SA) Template

## Document Control

| Field | Value |
|-------|-------|
| Project | [Project Name] |
| Version | 1.0 |
| Date | [YYYY-MM-DD] |
| Author | [Author Name] |
| Status | Draft / Approved |

---

## 1. Secure Architecture Overview

### 1.1 Purpose

This document defines the secure architecture patterns and design principles for HAI (Human-Assisted Intelligence) systems, including:

- Defense-in-depth architecture
- Permission boundary design
- Trust boundary enforcement
- Containment mechanisms
- Fail-secure patterns

### 1.2 Architecture Principles

| Principle | Description | Implementation |
|-----------|-------------|----------------|
| Defense in Depth | Multiple security layers | Input → Permission → Tool → Output validation |
| Least Privilege | Minimal necessary permissions | Deny-by-default, explicit allowlists |
| Fail Secure | Safe state on failure | Block action, log, alert |
| Zero Trust | Never trust, always verify | Validate at every boundary |
| Separation of Concerns | Isolated components | Sandboxed tools, separate contexts |

---

## 2. System Architecture

### 2.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         HAI SYSTEM ARCHITECTURE                          │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                      TRUST BOUNDARY                              │    │
│  │                                                                  │    │
│  │  ┌──────────────┐                                               │    │
│  │  │  User Input  │ ◄─── UNTRUSTED                                │    │
│  │  │  (External)  │                                               │    │
│  │  └──────┬───────┘                                               │    │
│  │         │                                                        │    │
│  │         ▼                                                        │    │
│  │  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │    │
│  │  │    INPUT     │    │  PERMISSION  │    │    TOOL      │       │    │
│  │  │  VALIDATION  │───▶│    GATE      │───▶│  EXECUTOR    │       │    │
│  │  │    LAYER     │    │    LAYER     │    │    LAYER     │       │    │
│  │  └──────────────┘    └──────────────┘    └──────────────┘       │    │
│  │         │                   │                   │                │    │
│  │         │                   │                   │                │    │
│  │         ▼                   ▼                   ▼                │    │
│  │  ┌──────────────────────────────────────────────────────┐       │    │
│  │  │                   AI AGENT CORE                       │       │    │
│  │  │  ┌────────────┐  ┌────────────┐  ┌────────────┐      │       │    │
│  │  │  │   System   │  │   Goal     │  │  Context   │      │       │    │
│  │  │  │   Prompt   │  │  Manager   │  │  Manager   │      │       │    │
│  │  │  └────────────┘  └────────────┘  └────────────┘      │       │    │
│  │  └──────────────────────────────────────────────────────┘       │    │
│  │         │                                                        │    │
│  │         ▼                                                        │    │
│  │  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │    │
│  │  │   OUTPUT     │    │   LOGGING    │    │  CONTAINMENT │       │    │
│  │  │  VALIDATION  │───▶│   & AUDIT    │───▶│   CONTROLS   │       │    │
│  │  │    LAYER     │    │    LAYER     │    │    LAYER     │       │    │
│  │  └──────────────┘    └──────────────┘    └──────────────┘       │    │
│  │                                                                  │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                    EXTERNAL SERVICES                             │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │    │
│  │  │   LLM API    │  │  Data Store  │  │  External    │           │    │
│  │  │  (Anthropic) │  │  (Database)  │  │    APIs      │           │    │
│  │  └──────────────┘  └──────────────┘  └──────────────┘           │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Component Descriptions

| Component | Purpose | Security Function |
|-----------|---------|-------------------|
| Input Validation Layer | Validate and sanitize all inputs | Injection detection, format validation |
| Permission Gate Layer | Enforce access control | Allowlist/denylist, rate limiting |
| Tool Executor Layer | Execute approved tool calls | Sandboxing, timeout enforcement |
| AI Agent Core | Process requests, generate responses | Goal management, context isolation |
| Output Validation Layer | Validate AI outputs | Content filtering, format enforcement |
| Logging & Audit Layer | Record all security events | Tamper-evident logs, PII sanitization |
| Containment Controls | Limit agent behavior | Iteration limits, kill switch |

---

## 3. Security Layers

### 3.1 Layer 1: Input Validation

```
┌─────────────────────────────────────────────────────────────┐
│                  INPUT VALIDATION LAYER                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Input ──▶ [Size Check] ──▶ [Format Validation] ──▶         │
│                                                              │
│        ──▶ [Encoding Validation] ──▶ [Injection Detection]  │
│                                                              │
│        ──▶ [Risk Scoring] ──▶ [Sanitization] ──▶ Output     │
│                                                              │
│  Decision: ALLOW (score < 0.3)                               │
│           ALERT (0.3 ≤ score < 0.7)                         │
│           BLOCK (score ≥ 0.7)                               │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Controls:**
| Control | Implementation | Bypass Prevention |
|---------|----------------|-------------------|
| Size limits | Max 10,000 chars default | Reject oversized before processing |
| Format validation | Schema validation (JSON/text) | Strict parsing, no fallback |
| Encoding check | UTF-8 only, no null bytes | Reject invalid encoding |
| Injection detection | 15+ pattern categories | Multi-layer, semantic analysis |
| Risk scoring | Weighted pattern matching | Cumulative scoring |

### 3.2 Layer 2: Permission Gate

```
┌─────────────────────────────────────────────────────────────┐
│                  PERMISSION GATE LAYER                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Request ──▶ [Extract Action + Resource]                    │
│                                                              │
│          ──▶ [Check Denylist] ──▶ BLOCK if matched          │
│                                                              │
│          ──▶ [Check Allowlist] ──▶ BLOCK if not matched     │
│                                                              │
│          ──▶ [Check Scope] ──▶ Validate resource bounds     │
│                                                              │
│          ──▶ [Check Rate Limit] ──▶ BLOCK if exceeded       │
│                                                              │
│          ──▶ [Log Decision] ──▶ ALLOW                       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Permission Model:**
```yaml
permissions:
  # What the agent CAN do
  allowed:
    - action: "file_read"
      scope: ["/data/**", "/config/*.json"]
      conditions: ["size < 10MB"]
    - action: "web_search"
      scope: ["*.example.com"]
      rate_limit: "10/minute"

  # What the agent CANNOT do (checked first)
  denied:
    - action: "file_write"
      scope: ["/etc/**", "/sys/**", "**/.env"]
      reason: "System files protected"
    - action: "code_execute"
      scope: ["*"]
      reason: "Code execution disabled"

  # What the agent MUST do
  required:
    - action: "log_action"
      when: "always"
    - action: "validate_output"
      when: "before_response"
```

### 3.3 Layer 3: Tool Executor

```
┌─────────────────────────────────────────────────────────────┐
│                   TOOL EXECUTOR LAYER                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Tool Call ──▶ [Schema Validation]                          │
│                                                              │
│            ──▶ [Parameter Sanitization]                     │
│                                                              │
│            ──▶ [Sandbox Execution]                          │
│                 - Timeout: 30s default                      │
│                 - Memory: 256MB limit                       │
│                 - Network: Allowlist only                   │
│                                                              │
│            ──▶ [Output Validation]                          │
│                                                              │
│            ──▶ [Result Sanitization] ──▶ Return             │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Tool Safety Configuration:**
| Tool | Risk Level | Timeout | Rate Limit | Requires Confirmation |
|------|------------|---------|------------|----------------------|
| file_read | Medium | 10s | 100/min | No |
| file_write | High | 10s | 10/min | Yes |
| web_fetch | Medium | 30s | 20/min | No |
| code_execute | Critical | 60s | 5/min | Yes |
| database_query | High | 30s | 50/min | No |
| send_email | High | 10s | 5/hour | Yes |

### 3.4 Layer 4: Output Validation

```
┌─────────────────────────────────────────────────────────────┐
│                  OUTPUT VALIDATION LAYER                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  AI Output ──▶ [Format Validation]                          │
│                 - JSON structure check                      │
│                 - Required fields present                   │
│                                                              │
│            ──▶ [Content Filtering]                          │
│                 - PII detection & redaction                 │
│                 - Harmful content check                     │
│                 - Secret detection                          │
│                                                              │
│            ──▶ [Action Verification]                        │
│                 - Matches requested action                  │
│                 - Within permission bounds                  │
│                                                              │
│            ──▶ [Sanitization] ──▶ Safe Output               │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 3.5 Layer 5: Containment Controls

```
┌─────────────────────────────────────────────────────────────┐
│                  CONTAINMENT CONTROLS                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────┐  ┌─────────────────┐                   │
│  │ Iteration Limit │  │ Token Budget    │                   │
│  │   Max: 50       │  │   Max: 100K     │                   │
│  │   Warn: 40      │  │   Warn: 80K     │                   │
│  └─────────────────┘  └─────────────────┘                   │
│                                                              │
│  ┌─────────────────┐  ┌─────────────────┐                   │
│  │ Time Budget     │  │ Resource Limits │                   │
│  │   Max: 5min     │  │   CPU: 2 cores  │                   │
│  │   Warn: 4min    │  │   Memory: 1GB   │                   │
│  └─────────────────┘  └─────────────────┘                   │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐│
│  │                    KILL SWITCH                          ││
│  │  Triggers: Manual | Auto (limits exceeded) | Alert      ││
│  │  Action: Stop agent, preserve state, log, alert         ││
│  └─────────────────────────────────────────────────────────┘│
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Containment Parameters:**
| Parameter | Default | Warning | Hard Limit | On Exceed |
|-----------|---------|---------|------------|-----------|
| Iterations | - | 40 | 50 | Terminate |
| Tokens | - | 80,000 | 100,000 | Terminate |
| Duration | - | 4 min | 5 min | Terminate |
| Tool calls | - | 80 | 100 | Terminate |
| Errors | - | 5 | 10 | Terminate |

---

## 4. Trust Boundaries

### 4.1 Trust Boundary Map

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                          │
│   UNTRUSTED ZONE                                                        │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │  • User inputs                                                   │   │
│   │  • External API responses                                        │   │
│   │  • Web content                                                   │   │
│   │  • Uploaded files                                                │   │
│   │  • Third-party tool outputs                                      │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                    │                                     │
│                                    ▼                                     │
│   ══════════════════════ TRUST BOUNDARY ════════════════════════════    │
│                                    │                                     │
│                                    ▼                                     │
│   VALIDATION ZONE                                                        │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │  • Input validation                                              │   │
│   │  • Schema enforcement                                            │   │
│   │  • Injection detection                                           │   │
│   │  • Permission checking                                           │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                    │                                     │
│                                    ▼                                     │
│   TRUSTED ZONE                                                           │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │  • System prompts                                                │   │
│   │  • Internal configuration                                        │   │
│   │  • Permission definitions                                        │   │
│   │  • Core agent logic                                              │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 4.2 Trust Boundary Controls

| Boundary Crossing | From | To | Required Controls |
|-------------------|------|-----|-------------------|
| User → Agent | Untrusted | Validation | Input validation, injection detection |
| Agent → Tool | Trusted | Untrusted | Permission check, parameter validation |
| Tool → Agent | Untrusted | Validation | Output validation, sanitization |
| Agent → LLM API | Trusted | External | Prompt isolation, output validation |
| Agent → Database | Trusted | Internal | Query validation, access control |
| Agent → User | Trusted | Untrusted | Output filtering, PII redaction |

### 4.3 Data Classification

| Classification | Description | Handling Requirements |
|----------------|-------------|----------------------|
| Public | Non-sensitive data | Standard logging |
| Internal | Business data | Access control, audit logging |
| Confidential | Sensitive business data | Encryption, restricted access |
| Restricted | PII, secrets, credentials | Encryption, no logging, minimal access |

---

## 5. Prompt Architecture

### 5.1 Prompt Structure

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         PROMPT ARCHITECTURE                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ SYSTEM PROMPT (Protected, Immutable)                              │  │
│  │ ─────────────────────────────────────────────────────────────────│  │
│  │ • Core identity and purpose                                       │  │
│  │ • Permission boundaries (CAN/CANNOT/MUST)                         │  │
│  │ • Security constraints                                            │  │
│  │ • Output format requirements                                      │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ CONTEXT (Validated, Sandboxed)                                    │  │
│  │ ─────────────────────────────────────────────────────────────────│  │
│  │ • Session history (sanitized)                                     │  │
│  │ • Retrieved documents (validated)                                 │  │
│  │ • Tool results (sanitized)                                        │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ USER INPUT (Untrusted, Delimited)                                 │  │
│  │ ─────────────────────────────────────────────────────────────────│  │
│  │ <<<USER_INPUT>>>                                                  │  │
│  │ [User's message - treated as untrusted data]                      │  │
│  │ <<<END_USER_INPUT>>>                                              │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ INSTRUCTION (Protected, Final)                                    │  │
│  │ ─────────────────────────────────────────────────────────────────│  │
│  │ • Reminder of constraints                                         │  │
│  │ • Output format enforcement                                       │  │
│  │ • Final instruction that cannot be overridden                     │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Prompt Security Requirements

| Requirement | Implementation | Verification |
|-------------|----------------|--------------|
| System prompt isolation | Separate from user content | Cannot be extracted by user |
| User input delimiting | Clear boundary markers | Parser enforces boundaries |
| Instruction protection | Final instruction block | Cannot be overridden |
| Context sanitization | Validate before inclusion | No injection payloads |
| Output format | Structured JSON | Schema validation |

---

## 6. Error Handling Architecture

### 6.1 Fail-Secure Pattern

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      FAIL-SECURE ARCHITECTURE                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Normal Flow:                                                            │
│  Request ──▶ Validate ──▶ Process ──▶ Respond                           │
│                                                                          │
│  Error Flow:                                                             │
│  Request ──▶ Validate ──▶ ERROR ──▶ [Fail-Secure Handler]               │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │ FAIL-SECURE HANDLER                                             │    │
│  │                                                                  │    │
│  │  1. BLOCK the action (don't proceed)                            │    │
│  │  2. LOG full error details (internal only)                      │    │
│  │  3. RETURN safe error message (no internals)                    │    │
│  │  4. ALERT if severity warrants                                  │    │
│  │  5. PRESERVE state for investigation                            │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  Error Categories:                                                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │ VALIDATION  │  │ PERMISSION  │  │   TIMEOUT   │  │  INTERNAL   │    │
│  │   ERROR     │  │   DENIED    │  │    ERROR    │  │    ERROR    │    │
│  │             │  │             │  │             │  │             │    │
│  │ Block +     │  │ Block +     │  │ Terminate + │  │ Block +     │    │
│  │ Safe msg    │  │ Log + Alert │  │ Log + Alert │  │ Alert       │    │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 6.2 Error Response Rules

| Error Type | User Message | Internal Logging | Alert |
|------------|--------------|------------------|-------|
| Validation | "Invalid input format" | Full details + input | No |
| Permission | "Action not permitted" | Full details + context | Yes |
| Injection | "Request could not be processed" | Full payload + patterns | Yes |
| Timeout | "Request timed out" | Duration + state | Medium priority |
| Rate limit | "Too many requests" | Count + window | High priority |
| Internal | "An error occurred" | Full stack trace | Yes |

---

## 7. Deployment Architecture

### 7.1 Infrastructure Security

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    DEPLOYMENT ARCHITECTURE                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │ NETWORK LAYER                                                    │    │
│  │  • TLS 1.3 for all connections                                  │    │
│  │  • Network segmentation                                          │    │
│  │  • Firewall rules (allowlist)                                   │    │
│  │  • DDoS protection                                               │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │ CONTAINER LAYER                                                  │    │
│  │  • Read-only root filesystem                                     │    │
│  │  • Non-root user                                                 │    │
│  │  • Resource limits (CPU, memory)                                 │    │
│  │  • No privileged capabilities                                    │    │
│  │  • Seccomp/AppArmor profiles                                     │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │ APPLICATION LAYER                                                │    │
│  │  • Secrets from vault (never in code)                           │    │
│  │  • Environment-based config                                      │    │
│  │  • Health checks                                                 │    │
│  │  • Graceful shutdown                                             │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │ DATA LAYER                                                       │    │
│  │  • Encryption at rest (AES-256)                                 │    │
│  │  • Encryption in transit (TLS)                                   │    │
│  │  • Access logging                                                │    │
│  │  • Backup encryption                                             │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 7.2 Secret Management

| Secret Type | Storage | Rotation | Access |
|-------------|---------|----------|--------|
| API keys | Vault/KMS | 90 days | Application only |
| Database credentials | Vault/KMS | 30 days | Application only |
| Encryption keys | HSM/KMS | Annually | Automated only |
| Service tokens | Vault/KMS | 24 hours | Service-to-service |
| User tokens | Secure cookie | Session | User session |

---

## 8. Architecture Patterns Reference

### 8.1 HAI Security Patterns

| Pattern | Purpose | Reference |
|---------|---------|-----------|
| Pattern 1: Secure Logging | Tamper-evident audit trail | HAI-Security-Architecture-Patterns.md |
| Pattern 2: Permission Gate | Access control enforcement | HAI-Security-Architecture-Patterns.md |
| Pattern 3: Input Validation | Injection defense | HAI-Security-Architecture-Patterns.md |
| Pattern 4: Tool Sandboxing | Safe tool execution | HAI-Security-Architecture-Patterns.md |
| Pattern 5: Fail Secure | Safe error handling | HAI-Security-Architecture-Patterns.md |

### 8.2 Pattern Application Matrix

| Component | Pattern 1 | Pattern 2 | Pattern 3 | Pattern 4 | Pattern 5 |
|-----------|-----------|-----------|-----------|-----------|-----------|
| Input Layer | | | ✓ | | ✓ |
| Permission Layer | ✓ | ✓ | | | ✓ |
| Tool Layer | ✓ | ✓ | ✓ | ✓ | ✓ |
| Output Layer | ✓ | | ✓ | | ✓ |
| Agent Core | ✓ | ✓ | | | ✓ |

---

## 9. Architecture Review Checklist

### 9.1 Level 1: Foundational

```
[ ] Defense-in-depth layers identified
[ ] Permission boundaries defined (CAN/CANNOT/MUST)
[ ] Trust boundaries mapped
[ ] Basic input validation in place
[ ] Error handling follows fail-secure
[ ] Secrets not in code
```

### 9.2 Level 2: Comprehensive

```
[ ] All five security layers implemented
[ ] Tool sandboxing configured
[ ] Containment controls active
[ ] Prompt architecture follows template
[ ] Output validation implemented
[ ] Logging integrated at all layers
[ ] Infrastructure security hardened
```

### 9.3 Level 3: Industry-Leading

```
[ ] Zero-trust architecture verified
[ ] All patterns from reference implemented
[ ] Automated security testing in CI/CD
[ ] Red team tested
[ ] Continuous monitoring active
[ ] Architecture regularly reviewed
[ ] Threat model updated with architecture changes
```

---

## 10. HAIAMM Practice Mapping

| Practice | SA Contribution |
|----------|-----------------|
| SR (Security Requirements) | Architecture implements requirements |
| TA (Threat Assessment) | Architecture addresses identified threats |
| DR (Design Review) | Architecture reviewed against this template |
| IR (Implementation Review) | Code reviewed against architecture |
| ST (Security Testing) | Architecture tested for vulnerabilities |
| EH (Environment Hardening) | Deployment architecture applied |
| ML (Monitoring & Logging) | Logging architecture integrated |

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | [Date] | [Author] | Initial secure architecture template |

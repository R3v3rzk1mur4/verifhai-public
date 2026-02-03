# Security Review Checklist Template

## Review Information

| Field | Value |
|-------|-------|
| Review ID | [REV-YYYY-NNN] |
| Date | [YYYY-MM-DD] |
| Reviewer | [Name] |
| Review Type | Code / Config / Architecture |
| Scope | [Files/Components reviewed] |

---

## 1. AI Agent Security

### 1.1 Permission Boundaries
- [ ] Agent has defined allowed actions list
- [ ] Prohibited actions are explicitly listed
- [ ] Permissions follow least privilege principle
- [ ] Permission checks are enforced (not just documented)
- [ ] Permission bypass is not possible

**Findings:**
| ID | Location | Issue | Severity | Status |
|----|----------|-------|----------|--------|
| | | | | |

### 1.2 Tool Safety
- [ ] Tool inputs are validated against schema
- [ ] Tool inputs are sanitized
- [ ] Tool outputs are validated
- [ ] Rate limits are enforced per tool
- [ ] Timeouts prevent runaway operations
- [ ] Dangerous tools require confirmation

**Findings:**
| ID | Location | Issue | Severity | Status |
|----|----------|-------|----------|--------|
| | | | | |

### 1.3 Prompt Security
- [ ] System prompts are immutable
- [ ] User input is clearly delimited from instructions
- [ ] Instructions cannot be overridden by user input
- [ ] Output format is validated
- [ ] Prompt injection defenses are in place

**Findings:**
| ID | Location | Issue | Severity | Status |
|----|----------|-------|----------|--------|
| | | | | |

### 1.4 Goal Integrity
- [ ] Agent goals are protected from manipulation
- [ ] Multi-turn goal drift is detected
- [ ] Conflicting instructions are handled safely
- [ ] Goal changes are logged

**Findings:**
| ID | Location | Issue | Severity | Status |
|----|----------|-------|----------|--------|
| | | | | |

### 1.5 Action Logging
- [ ] All tool invocations are logged
- [ ] User inputs are logged (sanitized)
- [ ] Decisions/reasoning are captured
- [ ] Logs include timestamp and context
- [ ] Logs are tamper-resistant

**Findings:**
| ID | Location | Issue | Severity | Status |
|----|----------|-------|----------|--------|
| | | | | |

### 1.6 Containment
- [ ] Agent has iteration/step limits
- [ ] Token/resource budgets are enforced
- [ ] Escape paths are closed
- [ ] Failure modes are safe
- [ ] Kill switch exists

**Findings:**
| ID | Location | Issue | Severity | Status |
|----|----------|-------|----------|--------|
| | | | | |

---

## 2. Standard Security (OWASP)

### 2.1 Injection
- [ ] All inputs are validated
- [ ] Parameterized queries are used
- [ ] No command injection vectors
- [ ] No LDAP/XPath injection
- [ ] Template injection prevented

**Findings:**
| ID | Location | Issue | Severity | Status |
|----|----------|-------|----------|--------|
| | | | | |

### 2.2 Broken Authentication
- [ ] Strong password requirements
- [ ] Secure session management
- [ ] Multi-factor available for sensitive ops
- [ ] Account lockout after failures
- [ ] Credential storage is secure

**Findings:**
| ID | Location | Issue | Severity | Status |
|----|----------|-------|----------|--------|
| | | | | |

### 2.3 Sensitive Data Exposure
- [ ] No hardcoded credentials
- [ ] Secrets loaded from secure storage
- [ ] PII is protected
- [ ] Encryption at rest for sensitive data
- [ ] TLS for data in transit

**Findings:**
| ID | Location | Issue | Severity | Status |
|----|----------|-------|----------|--------|
| | | | | |

### 2.4 Broken Access Control
- [ ] Authorization checks on all endpoints
- [ ] Default deny policy
- [ ] CORS configured correctly
- [ ] Rate limiting in place
- [ ] No IDOR vulnerabilities

**Findings:**
| ID | Location | Issue | Severity | Status |
|----|----------|-------|----------|--------|
| | | | | |

### 2.5 Security Misconfiguration
- [ ] Debug mode disabled in production
- [ ] Error messages don't leak info
- [ ] Security headers configured
- [ ] Unnecessary features disabled
- [ ] Default credentials changed

**Findings:**
| ID | Location | Issue | Severity | Status |
|----|----------|-------|----------|--------|
| | | | | |

### 2.6 XSS (Cross-Site Scripting)
- [ ] Output encoding applied
- [ ] Content-Security-Policy set
- [ ] User input not in script contexts
- [ ] DOM-based XSS prevented
- [ ] HttpOnly cookies used

**Findings:**
| ID | Location | Issue | Severity | Status |
|----|----------|-------|----------|--------|
| | | | | |

### 2.7 Insecure Dependencies
- [ ] Dependencies are up to date
- [ ] No known vulnerable packages
- [ ] Lockfile is maintained
- [ ] Dependency scanning in CI/CD
- [ ] Unused dependencies removed

**Findings:**
| ID | Location | Issue | Severity | Status |
|----|----------|-------|----------|--------|
| | | | | |

### 2.8 Logging & Monitoring
- [ ] Security events are logged
- [ ] Logs don't contain sensitive data
- [ ] Log level appropriate for production
- [ ] Alerting configured
- [ ] Log retention policy defined

**Findings:**
| ID | Location | Issue | Severity | Status |
|----|----------|-------|----------|--------|
| | | | | |

---

## 3. Configuration Security

### 3.1 Secrets Management
- [ ] No secrets in source code
- [ ] Environment variables or vault used
- [ ] API keys have minimal scope
- [ ] Secrets are rotated regularly
- [ ] .env files are gitignored

**Findings:**
| ID | Location | Issue | Severity | Status |
|----|----------|-------|----------|--------|
| | | | | |

### 3.2 Deployment Security
- [ ] HTTPS enforced
- [ ] Minimum privileges for runtime
- [ ] Container security if applicable
- [ ] Network isolation appropriate
- [ ] Secrets injection at runtime

**Findings:**
| ID | Location | Issue | Severity | Status |
|----|----------|-------|----------|--------|
| | | | | |

---

## 4. Review Summary

### 4.1 Finding Counts

| Severity | Count | Fixed | Open |
|----------|-------|-------|------|
| Critical | | | |
| High | | | |
| Medium | | | |
| Low | | | |
| Info | | | |
| **Total** | | | |

### 4.2 Good Practices Observed
- [ ] [Practice 1]
- [ ] [Practice 2]
- [ ] [Practice 3]

### 4.3 Recommendations
1. [Highest priority recommendation]
2. [Second priority recommendation]
3. [Third priority recommendation]

---

## 5. Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Reviewer | | | |
| Developer | | | |
| Security Lead | | | |

---

## Revision History

| Version | Date | Reviewer | Changes |
|---------|------|----------|---------|
| 1.0 | [Date] | [Name] | Initial review |

# ReviewCode - Security Code Review for HAI Systems

AI-assisted security review of code, configuration, and architecture for Human-Assisted Intelligence systems.

## Trigger

User says: "/verifhai review", "review this code for security", "check for vulnerabilities", "security review"

## Workflow

### Step 1: Identify Review Scope

```
Let's do a security review. What would you like me to review?

1. **Code in context** - Review code you've shared or files in current directory
2. **Specific file(s)** - Point me to specific files to review
3. **Architecture** - Review system design and boundaries
4. **Configuration** - Review config files for security issues
5. **Agent/Tool** - Review AI agent or tool implementation

Which type of review?
```

### Step 2: Perform Review

Based on review type, analyze for:

#### Standard Security Issues (OWASP)
- **Injection** - SQL, command, LDAP, XPath injection
- **Broken Authentication** - Weak auth, session issues
- **Sensitive Data Exposure** - Credentials, PII leaks
- **XXE** - XML external entity processing
- **Broken Access Control** - Authorization bypass
- **Security Misconfiguration** - Insecure defaults
- **XSS** - Cross-site scripting
- **Insecure Deserialization** - Object manipulation
- **Using Components with Known Vulnerabilities** - Outdated deps
- **Insufficient Logging** - Missing audit trails

#### AI-Specific Security Issues
- **Excessive Agency (EA)** - Overly broad permissions
- **Agent Goal Hijack (AGH)** - Goal manipulation vulnerabilities
- **Tool Misuse (TM)** - Unsafe tool invocations
- **Rogue Agents (RA)** - Insufficient containment
- **Prompt Injection** - User input affecting system prompts
- **Data Leakage** - AI exposing sensitive data
- **Model Manipulation** - Training data poisoning

### Step 3: Report Findings

```
## Security Review Report

**File(s) Reviewed:** [files]
**Review Date:** [date]
**Review Type:** [Code/Architecture/Config]

### Summary

| Severity | Count |
|----------|-------|
| Critical | X |
| High | X |
| Medium | X |
| Low | X |
| Info | X |

### Critical Findings

#### [CRITICAL] Finding 1: [Title]
**Location:** `file.py:45`
**Issue:** [Description of the vulnerability]
**Impact:** [What could happen if exploited]
**Code:**
```python
# Vulnerable code
vulnerable_line_here
```
**Recommendation:**
```python
# Fixed code
secure_line_here
```
**References:** [CWE-XXX, OWASP Top 10]

### High Findings
[...]

### Medium Findings
[...]

### Good Practices Observed
[List of security practices done well]

### Recommendations
1. [Priority action 1]
2. [Priority action 2]
3. [Priority action 3]
```

---

## Review Checklists

### AI Agent Code Review Checklist

```
**Permission Boundaries:**
[ ] Agent has defined allowed actions list
[ ] Prohibited actions are enforced
[ ] Permissions are minimized (least privilege)
[ ] Permission checks cannot be bypassed

**Tool Safety:**
[ ] Tool inputs are validated against schema
[ ] Tool outputs are sanitized
[ ] Rate limits are enforced
[ ] Timeouts prevent runaway tools
[ ] Dangerous tools require confirmation

**Prompt Security:**
[ ] System prompts are immutable
[ ] User input is clearly delimited
[ ] Instructions cannot be overridden by user input
[ ] Output format is validated

**Goal Integrity:**
[ ] Agent goals are protected from manipulation
[ ] Multi-turn goal drift is detected
[ ] Conflicting instructions are handled safely

**Action Logging:**
[ ] All tool invocations are logged
[ ] User inputs are logged (sanitized)
[ ] Decisions/reasoning are captured
[ ] Logs include timestamp and context

**Containment:**
[ ] Agent has iteration/step limits
[ ] Token/resource budgets enforced
[ ] Escape paths are closed
[ ] Failure modes are safe
```

### LLM Integration Review Checklist

```
**Input Handling:**
[ ] User input is validated before sending to LLM
[ ] Input length limits are enforced
[ ] Special characters are handled safely
[ ] Input is clearly marked as untrusted

**Prompt Construction:**
[ ] System prompt is separate from user input
[ ] User input cannot override system instructions
[ ] Prompt injection defenses in place
[ ] Dynamic prompt parts are sanitized

**Output Handling:**
[ ] LLM output is validated before use
[ ] Output is not directly executed as code
[ ] Sensitive data is not echoed back
[ ] Output length limits are enforced

**API Security:**
[ ] API keys are not hardcoded
[ ] Keys are loaded from secure storage
[ ] Rate limiting protects against abuse
[ ] Errors don't expose sensitive info
```

### Configuration Review Checklist

```
**Secrets Management:**
[ ] No hardcoded credentials
[ ] Secrets in environment variables or vault
[ ] No secrets in version control
[ ] API keys have appropriate scope

**Secure Defaults:**
[ ] Debug mode disabled in production
[ ] Verbose errors disabled
[ ] Unnecessary features disabled
[ ] Security headers configured

**Dependencies:**
[ ] Dependencies are up to date
[ ] No known vulnerable packages
[ ] Lockfile in use
[ ] Dependency audit in CI/CD

**Deployment:**
[ ] HTTPS enforced
[ ] Minimum privileges for runtime
[ ] Network isolation appropriate
[ ] Logging configured
```

---

## Review Templates

### Quick Review (5-10 min)
Focus on critical issues only:
1. Hardcoded secrets
2. Injection vulnerabilities
3. Permission bypass
4. Prompt injection

### Standard Review (30-60 min)
Full security review:
1. All OWASP categories
2. All AI-specific issues
3. Configuration review
4. Dependency check

### Deep Review (2-4 hours)
Comprehensive analysis:
1. Full code review
2. Architecture review
3. Threat modeling
4. Security testing recommendations

---

## AI-Assisted Review Prompts

### For Agent Code:
```
Review this AI agent code for security issues, focusing on:
1. Excessive Agency - Does the agent have too many permissions?
2. Tool Misuse - Can tools be abused or bypassed?
3. Goal Hijacking - Can the agent's goals be manipulated?
4. Prompt Injection - Can user input affect system behavior?
5. Action Logging - Are all actions properly logged?

Code:
[paste code here]
```

### For LLM Integration:
```
Review this LLM integration for security issues:
1. Prompt injection vulnerabilities
2. Input validation gaps
3. Output handling risks
4. API key exposure
5. Rate limiting

Code:
[paste code here]
```

---

## Post-Review Actions

After review is complete:

```
**Review Complete**

I found [X] issues across [Y] files.

**Next Steps:**

1. **Fix Critical Issues First**
   - [List critical issues with file:line references]

2. **Create Issues/Tasks**
   Would you like me to help create GitHub issues for these findings?

3. **Re-Review After Fixes**
   Run `/verifhai review` again after making fixes.

4. **Track in Issue Management (IM)**
   Add findings to your security issue tracker.

**Practice Progress:**
Implementation Review (IR): Activity completed
- Consider running `/verifhai practice ir` to formalize your review process.
```

---

## Integration with Security Testing

After code review, recommend security testing:

```
Based on review findings, recommend these security tests:

**Prompt Injection Tests:**
Test inputs identified as potentially vulnerable

**Permission Boundary Tests:**
Test that permission controls work as designed

**Tool Safety Tests:**
Test tool input validation and rate limiting

Run `/verifhai practice st` to set up these tests.
```

# Vibe Coding Security Guide

## Securing AI-Assisted Development with HAIAMM

**Version:** 1.0.0
**Last Updated:** January 2026
**HAIAMM Version:** 2.2

---

## Purpose

This guide provides **security practices for vibe coding** - the AI-assisted development approach where developers describe intent to Large Language Models (LLMs) rather than writing code manually. It maps the HAIAMM framework to vibe coding workflows, helping developers maintain security while leveraging AI productivity gains.

**This guide covers:**
- Understanding vibe coding risks (with 2025 research data)
- HAIAMM practice mapping to vibe coding stages
- Practical security checklists
- Integration with VerifHAI tools
- Code review patterns for AI-generated code

---

## Table of Contents

1. [What is Vibe Coding?](#1-what-is-vibe-coding)
2. [The Security Problem](#2-the-security-problem)
3. [HAIAMM for Vibe Coding](#3-haiamm-for-vibe-coding)
4. [Vibe Coding Workflow Security](#4-vibe-coding-workflow-security)
5. [Security Checklists](#5-security-checklists)
6. [Code Review Patterns](#6-code-review-patterns)
7. [Tool Configuration](#7-tool-configuration)
8. [VerifHAI Integration](#8-verifhai-integration)
9. [Maturity Progression](#9-maturity-progression)
10. [Resources](#10-resources)

---

# 1. What is Vibe Coding?

## 1.1 Definition

**Vibe coding** is a software development approach coined by **Andrej Karpathy** (OpenAI co-founder, former Tesla AI lead) in February 2025. It describes coding by:

> "Fully giving in to the vibes, embracing exponentials, and forgetting that the code even exists."

In practice, this means:
- Describing desired functionality in natural language
- Letting AI generate the implementation
- Iterating through conversation rather than direct editing
- Accepting code without deep understanding of every line

```
┌────────────────────────────────────────────────────────────────────────────┐
│                     TRADITIONAL VS VIBE CODING                              │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  TRADITIONAL CODING                   VIBE CODING                          │
│  ─────────────────                    ───────────                          │
│                                                                             │
│  ┌─────────────────┐                  ┌─────────────────┐                  │
│  │  Developer      │                  │  Developer      │                  │
│  │  understands    │                  │  describes      │                  │
│  │  every line     │                  │  intent         │                  │
│  └────────┬────────┘                  └────────┬────────┘                  │
│           │                                    │                           │
│           ▼                                    ▼                           │
│  ┌─────────────────┐                  ┌─────────────────┐                  │
│  │  Manual         │                  │  LLM generates  │                  │
│  │  implementation │                  │  code           │                  │
│  └────────┬────────┘                  └────────┬────────┘                  │
│           │                                    │                           │
│           ▼                                    ▼                           │
│  ┌─────────────────┐                  ┌─────────────────┐                  │
│  │  Test & debug   │                  │  "Does it work?"│                  │
│  │  with full      │                  │  Accept or      │                  │
│  │  understanding  │                  │  iterate        │                  │
│  └─────────────────┘                  └─────────────────┘                  │
│                                                                             │
│  Time: Hours                          Time: Minutes                        │
│  Understanding: Deep                  Understanding: Shallow               │
│  Security: Manual review              Security: ???                        │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

## 1.2 Tools Enabling Vibe Coding

| Tool | Type | Primary Use |
|------|------|-------------|
| **Claude Code** | CLI Agent | Full development workflow with file access |
| **GitHub Copilot** | IDE Integration | Inline code completion |
| **Cursor** | IDE | AI-first development environment |
| **Windsurf** | IDE | AI-native development |
| **Lovable** | App Builder | Full application generation |
| **v0** | UI Generator | React component generation |
| **Bolt** | Full-stack | Complete application scaffolding |

## 1.3 Adoption Reality

- **Collins Dictionary Word of the Year 2025**: "Vibe coding"
- **Capgemini UK CTO**: "2026 will be the year AI-native engineering goes mainstream"
- **Enterprise adoption**: Growing but with significant security concerns

---

# 2. The Security Problem

## 2.1 Research Findings (2025)

The security research on AI-generated code is concerning:

```
┌────────────────────────────────────────────────────────────────────────────┐
│                    AI-GENERATED CODE SECURITY STATISTICS                    │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌────────────────────────────────────────────────────────────┐            │
│  │                                                            │            │
│  │   45%    of AI-generated code contains security flaws     │            │
│  │          (Veracode 2025 GenAI Code Security Report)       │            │
│  │                                                            │            │
│  └────────────────────────────────────────────────────────────┘            │
│                                                                             │
│  ┌────────────────────────────────────────────────────────────┐            │
│  │                                                            │            │
│  │   80%    of functionally correct AI code has              │            │
│  │          security vulnerabilities                          │            │
│  │          (SusVibes Benchmark, arXiv Dec 2025)             │            │
│  │                                                            │            │
│  └────────────────────────────────────────────────────────────┘            │
│                                                                             │
│  ┌────────────────────────────────────────────────────────────┐            │
│  │                                                            │            │
│  │   ~50%   of the time, LLMs choose insecure methods        │            │
│  │          when given a choice                               │            │
│  │          (Multiple security research studies)             │            │
│  │                                                            │            │
│  └────────────────────────────────────────────────────────────┘            │
│                                                                             │
│  ┌────────────────────────────────────────────────────────────┐            │
│  │                                                            │            │
│  │   170    Lovable-generated apps with exposed PII          │            │
│  │          out of 1,645 examined (May 2025)                 │            │
│  │                                                            │            │
│  └────────────────────────────────────────────────────────────┘            │
│                                                                             │
│  ┌────────────────────────────────────────────────────────────┐            │
│  │                                                            │            │
│  │   SHARED   Predictable JWT secrets and DB passwords       │            │
│  │   SECRETS  across hundreds of vibe-coded applications     │            │
│  │            (CSET study of 20,000 apps)                    │            │
│  │                                                            │            │
│  └────────────────────────────────────────────────────────────┘            │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

## 2.2 Why AI Generates Insecure Code

| Root Cause | Explanation | Example |
|------------|-------------|---------|
| **Training data bias** | LLMs learn from Stack Overflow, tutorials with bad practices | Using MD5 for passwords |
| **Functional priority** | AI optimizes for "it works" not "it's secure" | SQL concatenation over prepared statements |
| **Pattern replication** | Common patterns in training = commonly insecure | Hardcoded secrets |
| **Context blindness** | AI doesn't know your threat model | Generic auth for high-risk app |
| **Outdated knowledge** | Training cutoff misses recent CVEs | Using vulnerable library versions |

## 2.3 The Understanding Gap

```
┌────────────────────────────────────────────────────────────────────────────┐
│                        THE UNDERSTANDING GAP                                │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Developer's View:           Reality:                                       │
│  ─────────────────           ────────                                       │
│                                                                             │
│  "It works!"                 ┌─────────────────────────────────┐            │
│       │                      │  function login(user, pass) {   │            │
│       │                      │    const q = `SELECT * FROM     │            │
│       │                      │      users WHERE name='${user}' │ ← SQL     │
│       ▼                      │      AND pass='${pass}'`;       │   Injection│
│  ┌─────────┐                 │    const token = jwt.sign(      │            │
│  │  SHIP   │                 │      {user}, 'secret123');      │ ← Weak    │
│  │   IT    │                 │    res.cookie('token', token);  │   Secret  │
│  └─────────┘                 │    return db.query(q);          │ ← No      │
│                              │  }                               │   Sanitize│
│                              └─────────────────────────────────┘            │
│                                                                             │
│  The developer accepted AI code without understanding its security         │
│  implications. The code is functional but vulnerable.                       │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

## 2.4 Karpathy's Own Experience

Notably, when Andrej Karpathy released a new project in October 2025, someone asked how much he used vibe coding. His response:

> "AI didn't work well enough and was downright unhelpful. [The project was] basically entirely handwritten."

This illustrates that even vibe coding's inventor recognizes its limitations for serious projects.

## 2.5 Productivity vs. Security Tradeoff

Research from CodeRabbit (December 2025) found:

| Metric | Finding |
|--------|---------|
| **Initial productivity** | Higher with AI assistance |
| **Net productivity** | Offset by time fixing bugs and security issues |
| **Experienced developers** | 19% slower on non-trivial tasks due to review overhead |
| **Security debt** | Accumulates rapidly without review processes |

---

# 3. HAIAMM for Vibe Coding

## 3.1 How HAIAMM Addresses Vibe Coding Risks

The HAIAMM framework wasn't designed specifically for vibe coding, but its practices directly address the security gaps that vibe coding creates:

```
┌────────────────────────────────────────────────────────────────────────────┐
│               HAIAMM PRACTICES → VIBE CODING RISKS                          │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  VIBE CODING RISK              HAIAMM PRACTICE         COVERAGE            │
│  ───────────────               ───────────────         ────────            │
│                                                                             │
│  AI generates insecure   ───▶  CR (Code Review)        Direct              │
│  code patterns                 ST (Security Testing)                       │
│                                                                             │
│  Developer doesn't       ───▶  EG (Education &         Direct              │
│  understand the code           Guidance)                                   │
│                                                                             │
│  No security             ───▶  SR (Security            Direct              │
│  requirements defined          Requirements)                               │
│                                                                             │
│  AI tool has excessive   ───▶  EA (Excessive Agency)   Exact Match         │
│  permissions                                                               │
│                                                                             │
│  AI tools used for       ───▶  TM (Tool Misuse)        Exact Match         │
│  unintended purposes                                                       │
│                                                                             │
│  No threat modeling      ───▶  TA (Threat Assessment)  Direct              │
│  for AI-assisted dev                                                       │
│                                                                             │
│  AI actions not          ───▶  ML (Monitoring &        Direct              │
│  monitored                     Logging)                                    │
│                                                                             │
│  AI operates outside     ───▶  RA (Rogue Agents)       Exact Match         │
│  boundaries                                                                │
│                                                                             │
│  AI goals manipulated    ───▶  AGH (Agent Goal         Exact Match         │
│  via prompts                   Hijack)                                     │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

## 3.2 The Least Agency Principle

HAIAMM v2.2 introduces the **Least Agency Principle** - critical for vibe coding security:

> "Any AI agent should be constrained to the minimum set of authorities necessary for its specific task. Permissions should never exceed the immediate task scope, regardless of broader system capabilities."

**For vibe coding, this means:**
- AI coding tools should only access files they need
- Generated code should request minimal permissions
- Runtime capabilities should match actual requirements

## 3.3 Practice Priority for Vibe Coding

Not all HAIAMM practices are equally critical for vibe coding. Here's the priority order:

| Priority | Practice | Rationale |
|----------|----------|-----------|
| **P0 - Critical** | CR (Code Review) | Must review all AI-generated code |
| **P0 - Critical** | ST (Security Testing) | Automated detection of vulnerabilities |
| **P0 - Critical** | SR (Security Requirements) | Define what AI CAN/CANNOT do |
| **P1 - High** | EA (Excessive Agency) | Control AI tool permissions |
| **P1 - High** | TA (Threat Assessment) | Understand vibe coding risks |
| **P1 - High** | ML (Monitoring & Logging) | Track AI actions and generated code |
| **P2 - Medium** | TM (Tool Misuse) | Prevent misuse of coding tools |
| **P2 - Medium** | SA (Secure Architecture) | Design patterns for AI-generated code |
| **P2 - Medium** | EG (Education & Guidance) | Train developers on secure vibe coding |
| **P3 - Standard** | IM (Issue Management) | Track vulnerabilities in AI code |
| **P3 - Standard** | DR (Design Review) | Review AI-suggested architectures |
| **P3 - Standard** | EH (Environment Hardening) | Secure development environments |

---

# 4. Vibe Coding Workflow Security

## 4.1 The Secure Vibe Coding Workflow

```
┌────────────────────────────────────────────────────────────────────────────┐
│                    SECURE VIBE CODING WORKFLOW                              │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  STAGE 1: PREPARE           STAGE 2: GENERATE          STAGE 3: REVIEW     │
│  ─────────────────          ────────────────           ───────────────     │
│                                                                             │
│  ┌─────────────────┐        ┌─────────────────┐        ┌─────────────────┐ │
│  │ Define Security │        │ AI Generates    │        │ Security        │ │
│  │ Requirements    │───────▶│ Code            │───────▶│ Review          │ │
│  │ (SR)            │        │                 │        │ (CR)            │ │
│  └────────┬────────┘        └────────┬────────┘        └────────┬────────┘ │
│           │                          │                          │          │
│  ┌────────▼────────┐        ┌────────▼────────┐        ┌────────▼────────┐ │
│  │ Threat Model    │        │ Monitor AI      │        │ Security        │ │
│  │ for Feature     │        │ Actions         │        │ Testing         │ │
│  │ (TA)            │        │ (ML)            │        │ (ST)            │ │
│  └────────┬────────┘        └────────┬────────┘        └────────┬────────┘ │
│           │                          │                          │          │
│  ┌────────▼────────┐        ┌────────▼────────┐        ┌────────▼────────┐ │
│  │ Configure Tool  │        │ Verify Scope    │        │ Fix Findings    │ │
│  │ Permissions     │        │ Compliance      │        │ or Reject       │ │
│  │ (EA)            │        │ (EA, TM)        │        │ (IM)            │ │
│  └─────────────────┘        └─────────────────┘        └─────────────────┘ │
│                                                                             │
│  STAGE 4: INTEGRATE         STAGE 5: DEPLOY           STAGE 6: MONITOR    │
│  ──────────────────         ──────────────            ────────────────    │
│                                                                             │
│  ┌─────────────────┐        ┌─────────────────┐        ┌─────────────────┐ │
│  │ Merge with      │        │ Environment     │        │ Runtime         │ │
│  │ Review          │───────▶│ Hardening       │───────▶│ Monitoring      │ │
│  │ Approval        │        │ (EH)            │        │ (ML)            │ │
│  └────────┬────────┘        └────────┬────────┘        └────────┬────────┘ │
│           │                          │                          │          │
│  ┌────────▼────────┐        ┌────────▼────────┐        ┌────────▼────────┐ │
│  │ CI/CD Security  │        │ Verify No       │        │ Detect          │ │
│  │ Gates           │        │ Excessive       │        │ Anomalies       │ │
│  │ (ST)            │        │ Permissions     │        │ (RA, AGH)       │ │
│  └─────────────────┘        └─────────────────┘        └─────────────────┘ │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

## 4.2 Stage 1: Prepare (Before AI Generates Code)

### Security Requirements (SR)

Before asking AI to generate code, define boundaries:

```markdown
## Feature: User Authentication

### CAN (Permitted Actions)
- Hash passwords using bcrypt with cost factor 12+
- Generate JWT tokens with RS256 signing
- Set HttpOnly, Secure, SameSite cookies
- Log authentication attempts (without passwords)

### CANNOT (Prohibited Actions)
- Store passwords in plaintext
- Use MD5, SHA1, or unsalted hashing
- Include secrets in source code
- Expose user enumeration via error messages

### MUST (Required Controls)
- Rate limit login attempts (5/minute per IP)
- Require HTTPS for all auth endpoints
- Validate input length and format
- Use prepared statements for all queries
```

**VerifHAI Command:**
```bash
/verifhai practice sr
```

### Threat Assessment (TA)

Model threats specific to the feature:

| Threat | Attack Vector | Mitigation |
|--------|---------------|------------|
| Credential stuffing | Automated login attempts | Rate limiting, CAPTCHA |
| Session hijacking | Token theft | HttpOnly cookies, short expiry |
| SQL injection | Malformed username | Prepared statements |
| Brute force | Password guessing | Account lockout |

**VerifHAI Command:**
```bash
/verifhai practice ta
```

### Configure Tool Permissions (EA)

Limit what the AI tool can access:

```json
// Claude Code permission scope example
{
  "allowed_paths": [
    "src/auth/**",
    "tests/auth/**"
  ],
  "denied_paths": [
    ".env*",
    "secrets/**",
    "*.pem",
    "*.key"
  ],
  "allowed_commands": [
    "npm test",
    "npm run lint"
  ],
  "denied_commands": [
    "npm publish",
    "git push"
  ]
}
```

## 4.3 Stage 2: Generate (While AI Creates Code)

### Monitor AI Actions (ML)

Track what the AI does during generation:

```typescript
// Example: Logging AI code generation actions
interface AIActionLog {
  timestamp: string;
  action: 'file_read' | 'file_write' | 'command_run' | 'web_fetch';
  target: string;
  approved: boolean;
  user: string;
  session_id: string;
}

// Log every AI action for audit
function logAIAction(action: AIActionLog): void {
  console.log(JSON.stringify({
    ...action,
    event_type: 'ai_coding_action',
    tool: 'claude_code',
  }));
}
```

### Verify Scope Compliance (EA, TM)

During generation, watch for:

| Warning Sign | Risk | Action |
|--------------|------|--------|
| AI requests access to `.env` | Secret exposure | Deny, review necessity |
| AI wants to run `curl` to external URL | Data exfiltration | Deny, investigate |
| AI generates code accessing unrelated files | Scope creep | Review carefully |
| AI suggests `sudo` commands | Privilege escalation | Hard deny |

## 4.4 Stage 3: Review (After AI Generates Code)

### Security Code Review (CR)

Every piece of AI-generated code must be reviewed. Focus areas:

```
┌────────────────────────────────────────────────────────────────────────────┐
│                 AI CODE REVIEW FOCUS AREAS                                  │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  CATEGORY              WHAT TO CHECK                   COMMON AI MISTAKES  │
│  ────────              ─────────────                   ──────────────────  │
│                                                                             │
│  Authentication        - Password hashing algorithm    MD5, SHA1, no salt  │
│                        - Token generation              Weak secrets         │
│                        - Session management            No expiry            │
│                                                                             │
│  Input Validation      - SQL query construction        String concatenation │
│                        - Command execution             Shell injection      │
│                        - File path handling            Path traversal       │
│                                                                             │
│  Secret Handling       - API keys in code              Hardcoded secrets   │
│                        - Database credentials          Plaintext in config │
│                        - Private keys                  Committed to repo   │
│                                                                             │
│  Data Exposure         - Error messages                Stack traces leaked │
│                        - API responses                 Too much data       │
│                        - Logging                       PII in logs         │
│                                                                             │
│  Dependencies          - Package versions              Outdated/vulnerable │
│                        - Import sources                Typosquatting       │
│                        - License compliance            GPL in commercial   │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

**VerifHAI Command:**
```bash
/verifhai review
```

### Security Testing (ST)

Automated testing for AI-generated code:

```bash
# SAST - Static Analysis
semgrep --config=auto src/

# Dependency scanning
npm audit
snyk test

# Secret detection
gitleaks detect --source .

# Custom AI code checks (example)
verifhai review --ai-patterns src/
```

## 4.5 Stage 4-6: Integrate, Deploy, Monitor

### CI/CD Security Gates

Enforce security before merge:

```yaml
# .github/workflows/security.yml
name: Security Gate

on: [pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: SAST Scan
        run: semgrep --config=auto --error

      - name: Secret Detection
        run: gitleaks detect --exit-code 1

      - name: Dependency Audit
        run: npm audit --audit-level=high

      - name: AI Code Patterns
        run: |
          # Check for common AI-generated vulnerabilities
          ! grep -r "password.*=.*['\"]" src/
          ! grep -r "secret.*=.*['\"]" src/
          ! grep -r "eval(" src/

      - name: HAIAMM Compliance
        run: verifhai assess --quick --fail-below 1.5
```

### Runtime Monitoring

Monitor AI-generated code in production:

| Metric | Alert Threshold | Indicates |
|--------|-----------------|-----------|
| Authentication failures | >10/min from same IP | Brute force attempt |
| Database query errors | >5/min | Possible injection attempts |
| Unexpected API calls | Any to unknown hosts | Data exfiltration |
| Permission denied events | >3/session | Privilege escalation attempt |

---

# 5. Security Checklists

## 5.1 Pre-Generation Checklist

Before asking AI to generate code:

```markdown
## Pre-Generation Security Checklist

### Requirements Definition
- [ ] Security requirements documented (CAN/CANNOT/MUST)
- [ ] Threat model created for feature
- [ ] Data classification identified (PII, secrets, public)
- [ ] Compliance requirements noted (GDPR, HIPAA, etc.)

### Tool Configuration
- [ ] AI tool permissions scoped to necessary files
- [ ] Sensitive paths excluded from AI access
- [ ] Dangerous commands blocked
- [ ] Logging enabled for AI actions

### Context Preparation
- [ ] Relevant security policies shared with AI
- [ ] Existing security patterns referenced
- [ ] Prohibited patterns explicitly stated
- [ ] Example of secure implementation provided
```

## 5.2 Generation Checklist

While AI generates code:

```markdown
## During Generation Security Checklist

### Scope Monitoring
- [ ] AI staying within approved file paths
- [ ] No unexpected external requests
- [ ] No attempts to access secrets/credentials
- [ ] Commands match approved list

### Early Warning Signs
- [ ] AI not suggesting "quick fixes" that bypass security
- [ ] No hardcoded values that look like secrets
- [ ] Dependencies being added are known/trusted
- [ ] Code patterns match your security standards
```

## 5.3 Post-Generation Checklist

After AI generates code:

```markdown
## Post-Generation Security Checklist

### Code Review (CR)
- [ ] All AI-generated code reviewed line-by-line
- [ ] No hardcoded secrets, API keys, or passwords
- [ ] Input validation present for all user inputs
- [ ] Output encoding for all rendered content
- [ ] SQL queries use parameterized statements
- [ ] No dangerous functions (eval, exec, system)
- [ ] Error handling doesn't leak sensitive info
- [ ] Logging doesn't include PII or secrets

### Security Testing (ST)
- [ ] SAST scan completed with no high/critical findings
- [ ] Dependency scan shows no known vulnerabilities
- [ ] Secret detection scan clean
- [ ] Custom security tests pass
- [ ] HAIAMM compliance score acceptable

### Documentation
- [ ] Security decisions documented
- [ ] Threat mitigations noted
- [ ] Known limitations recorded
- [ ] Review approval recorded
```

## 5.4 Quick Reference Card

```
┌────────────────────────────────────────────────────────────────────────────┐
│                  VIBE CODING SECURITY QUICK REFERENCE                       │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  BEFORE GENERATION                                                          │
│  ─────────────────                                                          │
│  □ Define SR (CAN/CANNOT/MUST)      □ Scope tool permissions (EA)          │
│  □ Threat model the feature (TA)    □ Enable action logging (ML)           │
│                                                                             │
│  DURING GENERATION                                                          │
│  ─────────────────                                                          │
│  □ Monitor for scope violations     □ Watch for secret access              │
│  □ Verify dependencies are safe     □ Flag suspicious patterns             │
│                                                                             │
│  AFTER GENERATION                                                           │
│  ────────────────                                                           │
│  □ Line-by-line code review (CR)    □ Run SAST/dependency scans (ST)       │
│  □ Check for OWASP Top 10           □ Verify no hardcoded secrets          │
│  □ Test security requirements       □ Document review decision             │
│                                                                             │
│  RED FLAGS - STOP AND REVIEW                                                │
│  ──────────────────────────                                                 │
│  ⚠ Hardcoded strings >20 chars      ⚠ eval(), exec(), system()             │
│  ⚠ SQL string concatenation         ⚠ MD5, SHA1 for passwords              │
│  ⚠ console.log with user data       ⚠ Disabled security features           │
│  ⚠ Any "TODO: add security"         ⚠ Catch-all error handlers             │
│                                                                             │
│  VERIFHAI COMMANDS                                                          │
│  ─────────────────                                                          │
│  /verifhai start    - Begin secure journey                                 │
│  /verifhai practice sr - Build security requirements                       │
│  /verifhai practice ta - Threat assessment                                 │
│  /verifhai review   - Security code review                                 │
│  /verifhai assess   - Quick maturity check                                 │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

---

# 6. Code Review Patterns

## 6.1 Common AI-Generated Vulnerabilities

### Pattern 1: SQL Injection

**AI Often Generates:**
```typescript
// VULNERABLE - String concatenation
const query = `SELECT * FROM users WHERE email = '${email}'`;
const result = await db.query(query);
```

**Secure Alternative:**
```typescript
// SECURE - Parameterized query
const query = 'SELECT * FROM users WHERE email = $1';
const result = await db.query(query, [email]);
```

**Detection Regex:**
```regex
(SELECT|INSERT|UPDATE|DELETE).*\$\{.*\}
```

### Pattern 2: Hardcoded Secrets

**AI Often Generates:**
```typescript
// VULNERABLE - Hardcoded secret
const JWT_SECRET = 'super-secret-key-123';
const API_KEY = 'sk-proj-abc123def456';
```

**Secure Alternative:**
```typescript
// SECURE - Environment variables
const JWT_SECRET = process.env.JWT_SECRET;
const API_KEY = process.env.API_KEY;

if (!JWT_SECRET || !API_KEY) {
  throw new Error('Required secrets not configured');
}
```

**Detection Regex:**
```regex
(secret|password|api_key|token|key)\s*[=:]\s*['"][^'"]{8,}['"]
```

### Pattern 3: Weak Cryptography

**AI Often Generates:**
```typescript
// VULNERABLE - Weak hashing
import { createHash } from 'crypto';
const hashedPassword = createHash('md5').update(password).digest('hex');
```

**Secure Alternative:**
```typescript
// SECURE - bcrypt with appropriate cost
import bcrypt from 'bcrypt';
const SALT_ROUNDS = 12;
const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
```

**Detection Regex:**
```regex
createHash\s*\(\s*['"](?:md5|sha1)['"]
```

### Pattern 4: Command Injection

**AI Often Generates:**
```typescript
// VULNERABLE - Shell injection
import { exec } from 'child_process';
exec(`convert ${inputFile} ${outputFile}`, callback);
```

**Secure Alternative:**
```typescript
// SECURE - execFile with argument array
import { execFile } from 'child_process';
execFile('convert', [inputFile, outputFile], callback);
```

**Detection Regex:**
```regex
exec\s*\(\s*`[^`]*\$\{
```

### Pattern 5: Path Traversal

**AI Often Generates:**
```typescript
// VULNERABLE - No path validation
const filePath = `./uploads/${req.params.filename}`;
const content = fs.readFileSync(filePath);
```

**Secure Alternative:**
```typescript
// SECURE - Path validation
import path from 'path';

const UPLOAD_DIR = path.resolve('./uploads');
const filename = path.basename(req.params.filename); // Strip path components
const filePath = path.join(UPLOAD_DIR, filename);

// Verify path is within allowed directory
if (!filePath.startsWith(UPLOAD_DIR)) {
  throw new Error('Invalid file path');
}

const content = fs.readFileSync(filePath);
```

### Pattern 6: Information Disclosure

**AI Often Generates:**
```typescript
// VULNERABLE - Exposes stack trace
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack,
    query: req.query,
  });
});
```

**Secure Alternative:**
```typescript
// SECURE - Generic error response
app.use((err, req, res, next) => {
  // Log full error internally
  logger.error('Unhandled error', {
    error: err.message,
    stack: err.stack,
    requestId: req.id
  });

  // Return generic message to client
  res.status(500).json({
    error: 'An internal error occurred',
    requestId: req.id,
  });
});
```

## 6.2 Review Automation Script

```typescript
// scripts/ai-code-review.ts
// Automated checks for common AI-generated vulnerabilities

import { readFileSync, readdirSync, statSync } from 'fs';
import { join } from 'path';

interface Finding {
  file: string;
  line: number;
  pattern: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  message: string;
}

const PATTERNS = [
  {
    name: 'SQL Injection',
    regex: /(SELECT|INSERT|UPDATE|DELETE)[^;]*\$\{[^}]+\}/gi,
    severity: 'critical' as const,
    message: 'Possible SQL injection via template literal',
  },
  {
    name: 'Hardcoded Secret',
    regex: /(secret|password|api_key|token|key)\s*[=:]\s*['"][^'"]{8,}['"]/gi,
    severity: 'critical' as const,
    message: 'Possible hardcoded secret',
  },
  {
    name: 'Weak Hash',
    regex: /createHash\s*\(\s*['"](?:md5|sha1)['"]/gi,
    severity: 'high' as const,
    message: 'Weak hashing algorithm (use bcrypt for passwords)',
  },
  {
    name: 'Command Injection',
    regex: /exec\s*\(\s*`[^`]*\$\{/gi,
    severity: 'critical' as const,
    message: 'Possible command injection via template literal',
  },
  {
    name: 'Eval Usage',
    regex: /\beval\s*\(/gi,
    severity: 'high' as const,
    message: 'Dangerous eval() usage',
  },
  {
    name: 'Console Log PII',
    regex: /console\.log\s*\([^)]*(?:password|email|ssn|credit)/gi,
    severity: 'medium' as const,
    message: 'Possible PII in console.log',
  },
];

function scanFile(filePath: string): Finding[] {
  const findings: Finding[] = [];
  const content = readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');

  for (const pattern of PATTERNS) {
    for (let i = 0; i < lines.length; i++) {
      if (pattern.regex.test(lines[i])) {
        findings.push({
          file: filePath,
          line: i + 1,
          pattern: pattern.name,
          severity: pattern.severity,
          message: pattern.message,
        });
      }
      // Reset regex state
      pattern.regex.lastIndex = 0;
    }
  }

  return findings;
}

function scanDirectory(dir: string): Finding[] {
  const findings: Finding[] = [];
  const entries = readdirSync(dir);

  for (const entry of entries) {
    const fullPath = join(dir, entry);
    const stat = statSync(fullPath);

    if (stat.isDirectory() && !entry.startsWith('.') && entry !== 'node_modules') {
      findings.push(...scanDirectory(fullPath));
    } else if (stat.isFile() && /\.(ts|js|tsx|jsx)$/.test(entry)) {
      findings.push(...scanFile(fullPath));
    }
  }

  return findings;
}

// Run scan
const findings = scanDirectory('./src');

// Report
console.log('\n=== AI Code Security Scan Results ===\n');

const critical = findings.filter(f => f.severity === 'critical');
const high = findings.filter(f => f.severity === 'high');
const medium = findings.filter(f => f.severity === 'medium');

if (critical.length > 0) {
  console.log(`CRITICAL (${critical.length}):`);
  critical.forEach(f => console.log(`  ${f.file}:${f.line} - ${f.message}`));
}

if (high.length > 0) {
  console.log(`HIGH (${high.length}):`);
  high.forEach(f => console.log(`  ${f.file}:${f.line} - ${f.message}`));
}

if (medium.length > 0) {
  console.log(`MEDIUM (${medium.length}):`);
  medium.forEach(f => console.log(`  ${f.file}:${f.line} - ${f.message}`));
}

if (findings.length === 0) {
  console.log('No issues found!');
}

// Exit with error if critical findings
process.exit(critical.length > 0 ? 1 : 0);
```

---

# 7. Tool Configuration

## 7.1 Claude Code Security Configuration

```json
// .claude/settings.json
{
  "permissions": {
    "allow_file_read": ["src/**", "tests/**", "docs/**"],
    "deny_file_read": [".env*", "secrets/**", "*.pem", "*.key", "credentials*"],
    "allow_file_write": ["src/**", "tests/**"],
    "deny_file_write": ["package.json", "package-lock.json", ".github/**"],
    "allow_commands": [
      "npm test",
      "npm run lint",
      "npm run build",
      "git status",
      "git diff"
    ],
    "deny_commands": [
      "npm publish",
      "git push",
      "rm -rf",
      "curl",
      "wget"
    ]
  },
  "security": {
    "require_approval_for_new_files": true,
    "require_approval_for_deletions": true,
    "log_all_actions": true,
    "max_file_size_bytes": 1000000
  }
}
```

## 7.2 GitHub Copilot Security Settings

```json
// .github/copilot-settings.json
{
  "suggestions": {
    "block_patterns": [
      "password\\s*=\\s*['\"]",
      "api_key\\s*=\\s*['\"]",
      "secret\\s*=\\s*['\"]"
    ]
  },
  "context": {
    "exclude_files": [
      ".env*",
      "secrets/**",
      "*.pem"
    ]
  }
}
```

## 7.3 Pre-commit Hooks for AI Code

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks

  - repo: https://github.com/returntocorp/semgrep
    rev: v1.50.0
    hooks:
      - id: semgrep
        args: ['--config', 'auto', '--error']

  - repo: local
    hooks:
      - id: ai-code-patterns
        name: AI Code Security Patterns
        entry: npx ts-node scripts/ai-code-review.ts
        language: system
        pass_filenames: false
```

---

# 8. VerifHAI Integration

## 8.1 Vibe Coding Workflow with VerifHAI

```
┌────────────────────────────────────────────────────────────────────────────┐
│              VERIFHAI-INTEGRATED VIBE CODING WORKFLOW                       │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  STEP 1: /verifhai start                                            │   │
│  │  ─────────────────────────                                          │   │
│  │  "I'm building a user authentication feature with Claude Code"       │   │
│  │                                                                      │   │
│  │  VerifHAI Response:                                                  │   │
│  │  - Identifies high-risk feature (authentication)                    │   │
│  │  - Recommends SR, TA, CR practices                                  │   │
│  │  - Generates security journey for auth features                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│                              ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  STEP 2: /verifhai practice sr                                      │   │
│  │  ────────────────────────────                                       │   │
│  │  VerifHAI guides you through:                                        │   │
│  │  - Defining CAN/CANNOT/MUST for auth feature                        │   │
│  │  - Specifying password requirements                                  │   │
│  │  - Setting session management rules                                  │   │
│  │  - Output: SecurityRequirements.md for auth                         │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│                              ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  STEP 3: Generate with AI                                           │   │
│  │  ────────────────────────                                           │   │
│  │  Share SR document with Claude Code:                                 │   │
│  │  "Generate auth following these security requirements..."            │   │
│  │                                                                      │   │
│  │  AI generates code with security context                            │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│                              ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  STEP 4: /verifhai review                                           │   │
│  │  ────────────────────────                                           │   │
│  │  VerifHAI reviews AI-generated code for:                            │   │
│  │  - Compliance with SR document                                       │   │
│  │  - OWASP Top 10 vulnerabilities                                     │   │
│  │  - AI-specific patterns (hardcoded secrets, weak crypto)            │   │
│  │  - EA/TM/AGH/RA threat vectors                                      │   │
│  │  Output: Findings and fix recommendations                           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│                              ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  STEP 5: /verifhai assess                                           │   │
│  │  ────────────────────────                                           │   │
│  │  Quick check before merge:                                           │   │
│  │  - Are all findings addressed?                                       │   │
│  │  - Maturity score for this feature                                  │   │
│  │  - Ready for production?                                             │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

## 8.2 VerifHAI Commands for Vibe Coding

| Stage | Command | Purpose |
|-------|---------|---------|
| **Setup** | `/verifhai start` | Initialize security journey for feature |
| **Requirements** | `/verifhai practice sr` | Define security requirements |
| **Threat Model** | `/verifhai practice ta` | Assess threats for feature |
| **Review** | `/verifhai review` | Security review of generated code |
| **Assess** | `/verifhai assess` | Quick maturity check |
| **Measure** | `/verifhai measure` | Full assessment with scoring |
| **Status** | `/verifhai status` | Track progress |

## 8.3 Example Session

```
User: /verifhai start

VerifHAI: Welcome! What are you building?

User: A file upload feature using Claude Code

VerifHAI: File uploads are HIGH RISK. Key threats:
- Path traversal (attackers accessing arbitrary files)
- Malicious file upload (code execution)
- Denial of service (large files)
- Content type spoofing

Recommended security journey:
1. SR - Define allowed file types, size limits, storage location
2. TA - Model specific attack scenarios
3. SA - Design secure upload architecture
4. After generation: CR, ST

Shall I start with Security Requirements?

User: Yes

VerifHAI: [Guides through SR practice for file uploads...]

[Later, after AI generates code]

User: /verifhai review

VerifHAI: Analyzing AI-generated file upload code...

FINDINGS:
1. CRITICAL: No file type validation
   Line 45: accepts any file extension
   Fix: Validate against allowlist from SR

2. HIGH: Path constructed from user input
   Line 67: potential path traversal
   Fix: Use path.basename() and validate

3. MEDIUM: No file size check before upload
   Line 34: could allow DoS
   Fix: Add size limit from SR

Compliance with SR: 60% (3 requirements not met)

Would you like me to show the fixes?
```

---

# 9. Maturity Progression

## 9.1 Vibe Coding Security Maturity Levels

```
┌────────────────────────────────────────────────────────────────────────────┐
│              VIBE CODING SECURITY MATURITY PROGRESSION                      │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  LEVEL 1: FOUNDATIONAL (Score 0.5-1.4)                                     │
│  ─────────────────────────────────────                                     │
│  Minimum viable security for vibe coding                                    │
│                                                                             │
│  ✓ Basic code review of all AI output                                      │
│  ✓ Secret detection in CI/CD                                               │
│  ✓ SAST scanning enabled                                                   │
│  ✓ AI tool permissions somewhat restricted                                 │
│  ✓ Basic security training for developers                                  │
│                                                                             │
│  Risk: Still vulnerable to sophisticated attacks                           │
│  Suitable for: Internal tools, prototypes, low-risk features              │
│                                                                             │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  LEVEL 2: COMPREHENSIVE (Score 1.5-2.4)                                    │
│  ──────────────────────────────────────                                    │
│  Structured security program for AI-assisted development                   │
│                                                                             │
│  ✓ Security requirements defined before generation (SR)                    │
│  ✓ Threat modeling for high-risk features (TA)                            │
│  ✓ Comprehensive code review checklist (CR)                               │
│  ✓ AI tool permissions tightly scoped (EA)                                │
│  ✓ AI action logging and monitoring (ML)                                  │
│  ✓ Automated security gates in CI/CD (ST)                                 │
│  ✓ Regular security training on AI risks (EG)                             │
│                                                                             │
│  Risk: Reduced but not eliminated                                          │
│  Suitable for: Production features, customer-facing applications          │
│                                                                             │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  LEVEL 3: INDUSTRY-LEADING (Score 2.5-3.0)                                 │
│  ─────────────────────────────────────────                                 │
│  Optimized security for organizations heavily using AI coding              │
│                                                                             │
│  ✓ Security requirements in every AI prompt (SR)                          │
│  ✓ Real-time AI action monitoring with alerts (ML)                        │
│  ✓ AI-specific threat modeling integrated (TA, EA, TM, RA, AGH)           │
│  ✓ Custom SAST rules for AI patterns (ST)                                 │
│  ✓ Metrics tracking AI code security over time (SM)                       │
│  ✓ Incident response plan for AI-related issues (IM)                      │
│  ✓ Continuous improvement based on findings (SM)                          │
│  ✓ Policy defining acceptable AI coding use cases (PC)                    │
│                                                                             │
│  Risk: Minimized through continuous improvement                            │
│  Suitable for: Regulated industries, security-critical systems            │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

## 9.2 Maturity Assessment Questions

### Level 1 Questions

| Practice | Question | Yes/Partial/No |
|----------|----------|----------------|
| CR | Do you review all AI-generated code before merging? | |
| ST | Do you run SAST scans on AI-generated code? | |
| ST | Do you run secret detection on all commits? | |
| EA | Have you restricted AI tool access to sensitive files? | |
| EG | Have developers received basic AI security training? | |

### Level 2 Questions

| Practice | Question | Yes/Partial/No |
|----------|----------|----------------|
| SR | Do you define security requirements before AI generation? | |
| TA | Do you threat model high-risk features before AI generation? | |
| CR | Do you have a checklist for AI code review? | |
| EA | Are AI tool permissions scoped per-project? | |
| ML | Do you log AI tool actions? | |
| ST | Are security gates enforced in CI/CD? | |
| EG | Is there regular training on AI-specific vulnerabilities? | |

### Level 3 Questions

| Practice | Question | Yes/Partial/No |
|----------|----------|----------------|
| SR | Are security requirements included in every AI prompt? | |
| ML | Do you have real-time monitoring with alerts for AI actions? | |
| TA | Is AI-specific threat modeling (EA/TM/RA/AGH) integrated? | |
| ST | Do you have custom SAST rules for AI code patterns? | |
| SM | Do you track metrics on AI code security over time? | |
| IM | Do you have incident response plans for AI-related issues? | |
| PC | Is there policy defining acceptable AI coding use cases? | |

## 9.3 Improvement Roadmap

```
┌────────────────────────────────────────────────────────────────────────────┐
│                    VIBE CODING SECURITY ROADMAP                             │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  PHASE 1: FOUNDATION (Weeks 1-2)                                           │
│  ───────────────────────────────                                           │
│                                                                             │
│  □ Enable SAST scanning in CI/CD                                           │
│  □ Add secret detection (gitleaks/trufflehog)                              │
│  □ Create basic AI code review checklist                                   │
│  □ Restrict AI tool access to .env and secrets/                            │
│  □ Brief team on AI code security basics                                   │
│                                                                             │
│  Milestone: All AI code scanned before merge                               │
│                                                                             │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  PHASE 2: STRUCTURE (Weeks 3-6)                                            │
│  ──────────────────────────────                                            │
│                                                                             │
│  □ Create security requirements templates                                   │
│  □ Implement threat modeling for high-risk features                        │
│  □ Scope AI tool permissions per-project                                   │
│  □ Enable AI action logging                                                │
│  □ Add custom SAST rules for AI patterns                                   │
│  □ Conduct AI security training workshop                                   │
│                                                                             │
│  Milestone: Security requirements exist for new features                   │
│                                                                             │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  PHASE 3: OPTIMIZATION (Weeks 7-12)                                        │
│  ──────────────────────────────────                                        │
│                                                                             │
│  □ Integrate security requirements into AI prompts                         │
│  □ Implement real-time AI action monitoring                                │
│  □ Add AI-specific threat categories (EA/TM/RA/AGH)                       │
│  □ Track AI code security metrics                                          │
│  □ Create incident response plan for AI issues                             │
│  □ Define AI coding policy                                                 │
│  □ Establish continuous improvement process                                │
│                                                                             │
│  Milestone: Mature, measured, continuously improving                       │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

---

# 10. Resources

## 10.1 Related VerifHAI Documents

| Document | Location | Purpose |
|----------|----------|---------|
| HAI Security Architecture Patterns | `docs/security-patterns/HAI-Security-Architecture-Patterns.md` | Implementation patterns |
| Security Requirements Template | `claude-skill/templates/SecurityRequirements.md` | SR template |
| Threat Model Template | `claude-skill/templates/ThreatModel.md` | TA template |
| Review Checklist | `claude-skill/templates/ReviewChecklist.md` | CR checklist |

## 10.2 External Resources

### Research & Statistics
- [Veracode 2025 GenAI Code Security Report](https://www.veracode.com/)
- [SusVibes Benchmark (arXiv)](https://arxiv.org/)
- [CSET Study on Vibe Coding Security](https://cset.georgetown.edu/)

### Frameworks
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP Agentic AI Security](https://owasp.org/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [SAFE-MCP Framework](https://github.com/anthropics/safe-mcp)

### Tools
- [Semgrep](https://semgrep.dev/) - SAST scanning
- [Gitleaks](https://github.com/gitleaks/gitleaks) - Secret detection
- [Snyk](https://snyk.io/) - Dependency scanning

## 10.3 HAIAMM Framework Reference

Full HAIAMM v2.2 documentation available at:
- `verifhai-public/docs/haiamm.md` (coming soon)
- Desktop application: `verifhai` (formal assessments)
- Claude Skill: `/verifhai` commands

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | January 2026 | Initial release |

---

**Build secure AI-assisted code with VerifHAI.**

*This guide is part of the VerifHAI project. Contributions welcome.*

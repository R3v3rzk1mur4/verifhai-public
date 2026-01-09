# BuildPractice - Work on Specific Security Practices

Interactive guidance for building and improving specific HAIAMM security practices.

## Trigger

User says: "/verifhai practice [id]", "work on security requirements", "build threat assessment", "help with [practice name]"

## Supported Practices

| ID | Practice | Shortcut |
|----|----------|----------|
| SM | Strategy & Metrics | `/verifhai practice sm` |
| PC | Policy & Compliance | `/verifhai practice pc` |
| EG | Education & Guidance | `/verifhai practice eg` |
| TA | Threat Assessment | `/verifhai practice ta` |
| SR | Security Requirements | `/verifhai practice sr` |
| SA | Secure Architecture | `/verifhai practice sa` |
| DR | Design Review | `/verifhai practice dr` |
| IR | Implementation Review | `/verifhai practice ir` |
| ST | Security Testing | `/verifhai practice st` |
| EH | Environment Hardening | `/verifhai practice eh` |
| IM | Issue Management | `/verifhai practice im` |
| ML | Monitoring & Logging | `/verifhai practice ml` |

---

## Security Architecture Patterns Reference

For implementation-ready code patterns, refer to **`docs/security-patterns/HAI-Security-Architecture-Patterns.md`** which provides:

| Pattern | Supports Practices | Description |
|---------|-------------------|-------------|
| 1. Secure Logging & Monitoring | SR, SA, IR, ST, ML | HMAC hash chain, PII sanitization, rotation |
| 2. Permission Enforcement Gate | SR, SA, IR, ST | Allowlist/denylist, deny-by-default, rate limiting |
| 3. Input Validation & Prompt Injection Defense | SR, SA, IR, ST | 15+ injection patterns, risk scoring |
| 4. Tool Safety & Sandboxing | SR, SA, IR, ST | Schema validation, timeout enforcement |
| 5. Error Handling & Fail Secure | SR, SA, IR, ST | Safe error messages, internal logging |

---

## Practice Workflows

### SM: Strategy & Metrics

```
Let's establish Strategy & Metrics for your HAI security program.

**Current Level Check:**
Do you have a security strategy for your AI systems?
[ ] None  [ ] Informal  [ ] Documented  [ ] Measured

**Level 1 Activity: Define Security Strategy**

Step 1: Define your security vision
> What is your long-term security goal for HAI systems?

Example: "Our AI agents operate within defined boundaries with full
transparency, protecting user data while enabling powerful automation."

Step 2: Set strategic objectives
Key objectives to consider:
- HAIAMM maturity target (e.g., Level 2 across all practices)
- Zero critical AI security incidents
- 100% agent action logging
- Prompt injection detection rate

Step 3: Define key metrics (KPIs)
Essential metrics for HAI security:

| Metric | Formula | Target |
|--------|---------|--------|
| Permission boundary coverage | Tools with permissions / Total tools | 100% |
| Action logging completeness | Logged actions / Total actions | 100% |
| Prompt injection test coverage | Injection tests / Attack patterns | 90%+ |
| Mean time to detect anomaly | Avg detection time | < 5 min |

Step 4: Set up governance
- Who owns HAI security decisions?
- Review cadence (weekly, quarterly, annual)
- Escalation matrix

**Template:** `templates/StrategyMetrics.md`
**Output:** `docs/security/security-strategy.md`
```

### PC: Policy & Compliance

```
Let's establish Policy & Compliance for your HAI system.

**Current Level Check:**
Do you have security policies for AI systems?
[ ] None  [ ] General IT policies  [ ] AI-specific  [ ] Audited

**Level 1 Activity: Define HAI Security Policy**

Step 1: Create policy statement
Example: "All HAI systems MUST operate within defined permission
boundaries, log all actions, and protect user data."

Step 2: Define mandatory requirements

**Permission Requirements:**
- PC-PB-001: Explicit permission model (CAN/CANNOT/MUST)
- PC-PB-002: Deny by default
- PC-PB-003: Least privilege
- PC-PB-004: Permission verification before each action

**AI-Specific Requirements:**
- PC-AI-001: Prompt injection defense
- PC-AI-002: Tool safety controls
- PC-AI-003: Agent containment
- PC-AI-004: Action logging

Step 3: Map to compliance frameworks
Relevant frameworks:
- OWASP Top 10 for LLM
- MITRE ATLAS
- EU AI Act (if applicable)
- NIST AI RMF

Step 4: Define exception process
- How to request policy exceptions
- Who approves
- Documentation requirements
- Review schedule

**Template:** `templates/PolicyCompliance.md`
**Output:** `docs/security/security-policy.md`
```

### EG: Education & Guidance

```
Let's establish Education & Guidance for your HAI team.

**Current Level Check:**
What HAI security training exists?
[ ] None  [ ] General security  [ ] Some AI-specific  [ ] Comprehensive

**Level 1 Activity: Define Training Program**

Step 1: Identify audiences
| Audience | Training Needs |
|----------|----------------|
| AI/ML Engineers | Deep technical, secure coding |
| Backend Engineers | API security, data protection |
| DevOps/SRE | Containment, monitoring |
| Product Managers | Risk awareness |
| Leadership | Governance |

Step 2: Core curriculum
**HAI Security Fundamentals (All Staff - 2 hours):**
- What is HAI and why it's different
- The four HAI threats (EA, AGH, TM, RA)
- Prompt injection basics
- Your role in security

**Secure HAI Development (Engineers - 4 hours):**
- Permission architecture
- Secure coding patterns (see HAI-Security-Architecture-Patterns.md)
- Prompt security
- Testing & validation

Step 3: Create quick reference guides
- HAI Security Checklist (pre-commit)
- Common Mistakes Guide
- Incident Response Card

Step 4: Set up ongoing awareness
- Monthly security newsletter
- Lunch & learn sessions
- Bug bounty updates

**Template:** `templates/EducationGuidance.md`
**Output:** Training curriculum, quick reference guides
```

### SR: Security Requirements

```
Let's build Security Requirements for your HAI system.

**Current Level Check:**
Do you have any documented security requirements?
[ ] None  [ ] Informal  [ ] Documented

**Level 1 Activity: Define Core Requirements**

Step 1: Describe your AI's purpose
> What does your AI system do in one paragraph?

Step 2: Define permission boundaries
Based on your description:
- **CAN do:** [Allowed actions]
- **CANNOT do:** [Prohibited actions]
- **MUST do:** [Required behaviors]

Step 3: Generate requirements document
I'll create a requirements document following the format:

```markdown
## SR-AI-001: Permission Boundaries
The AI agent SHALL only perform actions in the Allowed list.
SHALL NOT perform actions in the Prohibited list.

**Allowed Actions:**
- [list]

**Prohibited Actions:**
- [list]
```

**Output:** `docs/security/security-requirements.md`
```

### TA: Threat Assessment

```
Let's create a Threat Assessment for your HAI system.

**Current Level Check:**
Have you done any threat modeling?
[ ] None  [ ] Informal  [ ] STRIDE/PASTA  [ ] AI-specific

**Level 1 Activity: Basic Threat Model**

Step 1: Define system boundaries
> Draw the trust boundary - what's inside vs outside your AI system?

Step 2: Identify assets
> What are you protecting? (Data, capabilities, reputation)

Step 3: STRIDE for AI
For each component, assess:
- **S**poofing: Can someone impersonate the AI or users?
- **T**ampering: Can inputs/outputs be modified?
- **R**epudiation: Are actions logged and attributable?
- **I**nformation Disclosure: Can the AI leak data?
- **D**enial of Service: Can the AI be overwhelmed?
- **E**levation of Privilege: Can the AI exceed permissions?

Step 4: AI-Specific Threats
- **Prompt Injection:** Can user input manipulate AI behavior?
- **Excessive Agency (EA):** Does the AI have too many permissions?
- **Goal Hijacking (AGH):** Can the AI's goals be manipulated?
- **Tool Misuse (TM):** Can tools be abused?
- **Rogue Agents (RA):** Can the AI act unexpectedly?

**Output:** `docs/security/threat-model.md`
```

### SA: Secure Architecture

```
Let's design Secure Architecture for your HAI system.

**Current Level Check:**
Do you have documented security architecture?
[ ] None  [ ] Informal  [ ] Documented  [ ] Reviewed

**Level 1 Activity: Permission Boundaries**

Step 1: Define layers
1. User Input Layer - Where does input come from?
2. Processing Layer - Where does AI logic run?
3. Tool Layer - What tools/APIs can AI access?
4. Data Layer - What data can AI access?

Step 2: Apply security patterns
For each layer:
- **Least Privilege:** Minimum necessary permissions
- **Defense in Depth:** Multiple security controls
- **Fail Secure:** Safe behavior on errors
- **Separation of Duties:** Split critical operations

Step 3: Design permission enforcement
```
┌─────────────────────────────────────────┐
│              User Input                  │
│         (Validate + Sanitize)           │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│           Permission Gate                │
│    (Check against allowed actions)       │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│              AI Agent                    │
│    (Constrained to allowed scope)       │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│            Tool Sandbox                  │
│   (Rate limits, input validation)       │
└─────────────────────────────────────────┘
```

**Output:** Architecture diagram with security controls
```

### DR: Design Review

```
Let's establish Design Review for your HAI system.

**Current Level Check:**
How do you review HAI designs for security?
[ ] None  [ ] Ad-hoc  [ ] Checklist  [ ] Formal process

**Level 1 Activity: Security Design Review**

Step 1: Document the design
Before review, ensure you have:
- Architecture diagram
- Data flow diagram
- Component inventory
- Trust boundary identification

Step 2: Apply design review checklist

**Permission Design:**
[ ] Permission boundaries explicitly defined
[ ] Allowed actions documented with scope
[ ] Prohibited actions explicitly listed
[ ] Deny-by-default architecture
[ ] Permission enforcement layer present

**AI/LLM Design:**
[ ] System prompt isolation designed
[ ] User input clearly delimited
[ ] Prompt injection defenses planned
[ ] AI output validation designed
[ ] Goal integrity protection planned

**Tool Integration Design:**
[ ] Each tool has defined purpose
[ ] Tool input schemas defined
[ ] Tool output validation planned
[ ] Rate limits per tool defined
[ ] Timeouts configured per tool

**Containment Design:**
[ ] Iteration limits designed
[ ] Resource budgets planned
[ ] Timeout protection designed
[ ] Kill switch mechanism planned
[ ] Fail-secure behavior defined

Step 3: Threat analysis for design
Apply STRIDE + AI-specific threats to each component.

Step 4: Document findings
- Required changes (must fix before implementation)
- Suggested improvements
- Pattern references from HAI-Security-Architecture-Patterns.md

**Template:** `templates/DesignReview.md`
**Output:** Design review report with findings and recommendations
```

### IR: Implementation Review

```
Let's set up Implementation Review for your HAI system.

**Current Level Check:**
How do you review code for security?
[ ] None  [ ] Ad-hoc  [ ] Checklist  [ ] Automated

**Level 1 Activity: Security Review Checklist**

Step 1: Define review scope
> What code should be reviewed? (AI logic, tool integrations, prompts)

Step 2: Create review checklist
For AI code, check:

**Standard Security:**
[ ] Input validation at boundaries
[ ] No hardcoded secrets
[ ] Parameterized queries
[ ] Error handling doesn't leak info

**AI-Specific Security:**
[ ] Permission enforcement
[ ] Tool input validation
[ ] Prompt injection defenses
[ ] Rate limiting
[ ] Action logging
[ ] Goal integrity checks

Step 3: Set up review process
- When to review: Before merge, before deploy
- Who reviews: Security-aware developer
- How to track: PR comments, issue tracker

**Would you like me to review code now?**
Provide code or point to files, and I'll analyze for security issues.

**Output:** Security review checklist, initial review findings
```

### ST: Security Testing

```
Let's establish Security Testing for your HAI system.

**Current Level Check:**
What security testing do you do?
[ ] None  [ ] Manual  [ ] Some automated  [ ] Comprehensive

**Level 1 Activity: Basic Security Tests**

Step 1: Identify test targets
> What should we test? (Inputs, permissions, tools, outputs)

Step 2: Create test cases

**Prompt Injection Tests:**
```python
def test_prompt_injection():
    malicious_inputs = [
        "Ignore previous instructions and...",
        "System: You are now...",
        "``` Execute: rm -rf / ```",
    ]
    for input in malicious_inputs:
        result = ai_agent.process(input)
        assert not result.contains_system_commands()
```

**Permission Boundary Tests:**
```python
def test_permission_boundaries():
    # Test agent cannot access prohibited resources
    result = ai_agent.access("/etc/passwd")
    assert result.denied()

    # Test agent stays in allowed scope
    result = ai_agent.access("./allowed/file.txt")
    assert result.allowed()
```

**Tool Safety Tests:**
```python
def test_tool_input_validation():
    # Test malicious tool inputs are rejected
    result = ai_agent.call_tool("file_read", path="../../../etc/passwd")
    assert result.rejected()
```

Step 3: Integrate into CI/CD
Add security tests to your pipeline.

**Output:** Security test suite, CI/CD integration guide
```

### EH: Environment Hardening

```
Let's establish Environment Hardening for your HAI system.

**Current Level Check:**
What environment hardening exists?
[ ] None  [ ] Basic  [ ] Documented baseline  [ ] Verified

**Level 1 Activity: Hardening Baseline**

Step 1: Inventory your environment
- Operating system and version
- Container runtime (Docker/Kubernetes)
- AI frameworks and dependencies
- Network configuration

Step 2: Apply OS/Platform hardening

**Container Security:**
[ ] Use minimal base images (distroless/alpine)
[ ] Run as non-root user
[ ] Read-only filesystem where possible
[ ] No privileged containers
[ ] Drop all capabilities
[ ] Limit resources (memory, CPU)
[ ] Scan images for vulnerabilities

**Kubernetes (if applicable):**
[ ] Pod Security Standards enforced
[ ] Network Policies configured
[ ] RBAC properly configured
[ ] Secrets encrypted at rest

Step 3: Apply AI runtime containment

**Agent Containment:**
[ ] Iteration limits enforced
[ ] Token budget limits set
[ ] Timeout protection configured
[ ] Memory limits set
[ ] Kill switch accessible
[ ] Subprocess restrictions
[ ] File system restrictions
[ ] Network egress restrictions

Step 4: Configure secrets management
[ ] No secrets in code
[ ] Secrets manager used
[ ] Rotation automated
[ ] Access audited

Step 5: Set up network hardening
[ ] TLS 1.3 enforced
[ ] WAF configured
[ ] Rate limiting at edge
[ ] Egress filtering

**Template:** `templates/EnvironmentHardening.md`
**Output:** Hardening checklist, configuration documentation
```

### IM: Issue Management

```
Let's establish Issue Management for your HAI system.

**Current Level Check:**
How do you manage security issues?
[ ] None  [ ] Ad-hoc  [ ] Defined process  [ ] Metrics-driven

**Level 1 Activity: Define Issue Process**

Step 1: Define severity levels

| Severity | Definition | SLA |
|----------|------------|-----|
| Critical | Active exploitation, data breach | 4 hours |
| High | Exploitable vulnerability | 24 hours |
| Medium | Moderate risk | 7 days |
| Low | Minor issue | 30 days |

Step 2: Define AI-specific categories

| Category | Code | Description |
|----------|------|-------------|
| Prompt Injection | PI | Attempts to manipulate AI |
| Excessive Agency | EA | AI exceeds permissions |
| Goal Hijacking | AGH | AI goals manipulated |
| Tool Misuse | TM | Tools used inappropriately |
| Rogue Agent | RA | Unexpected AI behavior |
| Data Leakage | DL | Sensitive data exposed |

Step 3: Define issue lifecycle
1. **Detect** - Discovery and reporting
2. **Triage** - Validate, classify, assign
3. **Contain** - Stop ongoing harm
4. **Fix** - Root cause and remediation
5. **Verify** - Confirm fix effectiveness
6. **Close** - Document and update KB
7. **Learn** - Post-mortem and improve

Step 4: Create incident response procedure

**AI Agent Incident Response:**
1. Activate agent kill switch
2. Stop all agent execution
3. Capture agent state and logs
4. Review all agent actions since anomaly
5. Identify scope of unauthorized actions
6. Analyze attack vector
7. Implement additional controls
8. Carefully restart with monitoring

Step 5: Set up escalation matrix
- Who to contact for each severity
- Escalation timeframes
- Communication templates

**Template:** `templates/IssueManagement.md`
**Output:** Issue management process, incident response procedure
```

### ML: Monitoring & Logging

```
Let's set up Monitoring & Logging for your HAI system.

**Current Level Check:**
What monitoring do you have?
[ ] None  [ ] Basic logs  [ ] Structured  [ ] Alerts

**Level 1 Activity: Essential Logging**

Step 1: Define what to log
For AI systems, log:
- All tool invocations (what, when, parameters)
- User inputs (sanitized)
- AI outputs (for audit)
- Permission checks (allowed/denied)
- Errors and anomalies
- Resource usage (tokens, iterations)

Step 2: Structured log format
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "event_type": "tool_invocation",
  "agent_id": "agent-123",
  "user_id": "user-456",
  "tool": "file_read",
  "parameters": {"path": "/allowed/file.txt"},
  "result": "success",
  "duration_ms": 150
}
```

Step 3: Set up basic alerts
Alert on:
- Permission denied events (potential attack)
- Unusual tool usage patterns
- Error rate spikes
- Rate limit triggers

**Output:** Logging configuration, alert rules
```

---

## Maturity Progression

Each practice has 3 maturity levels:

### Level 1: Foundational
- Basic practice in place
- Ad-hoc or informal
- Key activities performed

**Activities:** Define basics, create checklists, perform initial activities

### Level 2: Comprehensive
- Documented process
- Consistent execution
- Integrated into workflow

**Activities:** Formalize process, automate where possible, track metrics

### Level 3: Industry-Leading
- Measured and improved
- Customized for context
- Proactive and predictive

**Activities:** Optimize based on data, continuous improvement, share learnings

---

## Progress Tracking

After completing activities:

```
**Practice Progress Updated**

Security Requirements (SR): Level 1 -> Level 2

**What you completed:**
[x] Documented permission boundaries
[x] Created security-requirements.md
[x] Requirements are testable

**Next for Level 3:**
[ ] Requirements derived from threat model
[ ] Automated requirement verification
[ ] Metrics on requirement compliance

Type `/verifhai status` to see full progress.
```

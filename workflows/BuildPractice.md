# BuildPractice - Work on Specific Security Practices

Interactive guidance for building and improving specific HAIAMM security practices.

## Trigger

User says: "/verifhai practice [id]", "work on security requirements", "build threat assessment", "help with [practice name]"

## HAIAMM Context Loading

When working on a specific practice, load context from:
1. **One-Pager:** `${HAIAMM_PATH}/docs/practices/{PRACTICE}-Software-OnePager.md`
2. **Questionnaire (if exists):** `${HAIAMM_PATH}/docs/questionnaires/{PRACTICE}-Software-Questionnaire.md`

Use the one-pager to provide domain-specific activities and success criteria.

> **Note:** Set `HAIAMM_PATH` to your local HAIAMM repository path (e.g., `~/projects/HAIAMM`).

## State Management

Before starting:
1. Check if `.verifhai/progress.json` exists
2. If exists, load current practice status
3. Show user their current level for this practice

After completing activities:
1. Update `.verifhai/progress.json` with new level
2. Record evidence artifacts created
3. Add session to history

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

## Practice Workflows

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

### SM: Strategy & Metrics

```
Let's establish Strategy & Metrics for your HAI security program.

**Current Level Check:**
Do you have documented security strategy and metrics?
[ ] None  [ ] Informal goals  [ ] Documented strategy  [ ] Metrics dashboard

**Level 1 Activity: Define Security Goals**

Step 1: Define your HAI security objectives
> What are your top 3 security goals for your AI system?
> (Examples: Prevent data leakage, contain agent actions, detect misuse)

Step 2: Establish baseline metrics
Define measurable indicators:
- **Risk Metrics:** # of identified threats, % mitigated
- **Compliance Metrics:** % requirements met, audit findings
- **Operational Metrics:** Security incidents, MTTR, false positive rate
- **Coverage Metrics:** % code reviewed, % tests automated

Step 3: Create strategy document
```markdown
## HAI Security Strategy

### Vision
[One sentence describing security end state]

### Goals (12 months)
1. [Goal 1] - Metric: [how measured]
2. [Goal 2] - Metric: [how measured]
3. [Goal 3] - Metric: [how measured]

### Priorities
- Q1: [Focus area]
- Q2: [Focus area]
- Q3: [Focus area]
- Q4: [Focus area]
```

**Level 2: Metrics Dashboard & Threat Intelligence**
- Establish automated metrics collection
- Integrate threat intelligence feeds relevant to AI/LLM
- Quarterly strategy reviews

**Level 3: Industry Benchmarking**
- Compare against industry peers
- Publish security research
- Contribute to standards (OWASP, NIST)

**Output:** `docs/security/security-strategy.md`, metrics tracking setup
```

### PC: Policy & Compliance

```
Let's establish Policy & Compliance for your HAI system.

**Current Level Check:**
Do you have AI-specific security policies?
[ ] None  [ ] General IT policies  [ ] AI-specific policies  [ ] Compliance mapping

**Level 1 Activity: Create AI Acceptable Use Policy**

Step 1: Define policy scope
> What AI systems does this policy cover?
> Who needs to follow this policy? (developers, users, operators)

Step 2: Draft core policy sections
```markdown
## AI Acceptable Use Policy

### Purpose
This policy establishes security requirements for AI/HAI systems.

### Scope
Applies to: [systems, teams, users]

### Requirements

#### Data Handling
- AI systems SHALL NOT process data beyond their authorized scope
- PII SHALL be minimized and anonymized where possible
- Data retention SHALL follow [retention policy]

#### Permission Controls
- AI systems SHALL operate under least privilege
- All tool access SHALL be explicitly authorized
- Human approval required for: [list critical actions]

#### Monitoring
- All AI actions SHALL be logged
- Anomaly detection SHALL be enabled
- Incident response procedures SHALL be documented

### Compliance
- [GDPR/CCPA/HIPAA mapping if applicable]
- Review frequency: [quarterly/annually]
```

Step 3: Define compliance requirements
Map to relevant regulations based on your industry.

**Level 2: Formal Compliance Program**
- Regulatory mapping (GDPR, HIPAA, SOX)
- Regular compliance audits
- Exception tracking process

**Level 3: Automated Compliance**
- Policy-as-code implementation
- Continuous compliance monitoring
- Regulatory change tracking

**Output:** `docs/security/ai-acceptable-use-policy.md`, compliance matrix
```

### EG: Education & Guidance

```
Let's establish Education & Guidance for your HAI security.

**Current Level Check:**
What security training do your teams have?
[ ] None  [ ] General security  [ ] Some AI security  [ ] Role-based AI security

**Level 1 Activity: Create AI Security Awareness Materials**

Step 1: Identify target audiences
> Who interacts with your AI systems?
- Developers building AI features
- Operators managing AI systems
- End users interacting with AI
- Security team reviewing AI

Step 2: Define key messages per audience

**For Developers:**
- Prompt injection risks and defenses
- Secure tool implementation patterns
- Permission boundary enforcement
- Logging and monitoring requirements

**For Operators:**
- Incident detection patterns
- Response procedures for AI anomalies
- Monitoring dashboards and alerts
- Escalation paths

**For End Users:**
- What the AI can and cannot do
- How to report suspicious behavior
- Data handling expectations

Step 3: Create quick reference guide
```markdown
## HAI Security Quick Reference

### For Developers
- [ ] Validate all inputs before AI processing
- [ ] Implement permission checks before tool calls
- [ ] Log all AI actions with context
- [ ] Test for prompt injection
- [ ] Review AI code for security before merge

### For Operators
- [ ] Monitor for permission denied spikes
- [ ] Alert on unusual tool usage patterns
- [ ] Review AI logs daily
- [ ] Know escalation procedures

### For Users
- [ ] Report unexpected AI behavior
- [ ] Don't share sensitive data unnecessarily
- [ ] Verify AI outputs for critical decisions
```

**Level 2: Role-Based Training Program**
- Formal training curriculum
- Completion tracking
- Regular refresh training

**Level 3: Security Champions Program**
- Embedded security experts per team
- AI security office hours
- Internal knowledge sharing

**Output:** `docs/security/ai-security-training.md`, role-based guides
```

### DR: Design Review

```
Let's establish Design Review for your HAI system.

**Current Level Check:**
Do you review designs for security before building?
[ ] None  [ ] Informal  [ ] Checklist-based  [ ] Formal with sign-off

**Level 1 Activity: Create Security Design Checklist**

Step 1: Define what triggers a design review
> At what points should security review designs?
- New AI feature
- New tool integration
- Permission scope changes
- Data access changes
- External API integrations

Step 2: Create design review checklist
```markdown
## HAI Design Security Review Checklist

### Trust Boundaries
[ ] Trust boundaries clearly defined
[ ] Data flows across boundaries documented
[ ] Authentication at each boundary

### Permission Model
[ ] Least privilege applied
[ ] Permission scope explicitly defined
[ ] Escalation paths require human approval
[ ] Permission denials are logged

### Data Security
[ ] Data classification identified
[ ] Sensitive data minimized
[ ] Encryption requirements met
[ ] Retention/deletion defined

### AI-Specific
[ ] Prompt injection considered
[ ] Output sanitization planned
[ ] Tool input validation designed
[ ] Agent containment measures
[ ] Failure modes identified

### Monitoring
[ ] Logging requirements defined
[ ] Alerting thresholds set
[ ] Audit trail complete
```

Step 3: Define review process
- Who reviews: Security engineer or security-trained developer
- When: Before implementation begins
- Output: Approved design or list of required changes

**Level 2: Formal Design Review Process**
- Mandatory sign-off before implementation
- Design review board for high-risk changes
- Architecture decision records (ADRs)

**Level 3: Threat-Driven Design Reviews**
- Integrated threat modeling in design phase
- Attack tree analysis for critical features
- Red team input on designs

**Output:** Design review checklist, review process documentation
```

### EH: Environment Hardening

```
Let's establish Environment Hardening for your HAI system.

**Current Level Check:**
How hardened is your AI deployment environment?
[ ] Default configs  [ ] Basic hardening  [ ] Hardened baseline  [ ] Continuous validation

**Level 1 Activity: Secure Baseline Configuration**

Step 1: Inventory your AI environment
> What components need hardening?
- AI model hosting (cloud, on-prem, edge)
- API endpoints
- Data stores
- Network configuration
- Container/VM infrastructure

Step 2: Apply baseline hardening

**Compute Environment:**
- [ ] Minimal base image (no unnecessary packages)
- [ ] Non-root execution
- [ ] Read-only filesystem where possible
- [ ] Resource limits (CPU, memory, network)

**Network Security:**
- [ ] AI endpoints not directly internet-exposed
- [ ] Network segmentation for AI components
- [ ] Encrypted connections (TLS 1.2+)
- [ ] Egress filtering (AI can only reach approved destinations)

**Access Controls:**
- [ ] Service accounts with minimal permissions
- [ ] No shared credentials
- [ ] Secrets in vault (not in code/config)
- [ ] MFA for administrative access

**AI-Specific Hardening:**
- [ ] Model files integrity verified
- [ ] Inference endpoints rate-limited
- [ ] Input size limits enforced
- [ ] Output filtering enabled

Step 3: Document secure baseline
Create runbook or IaC for consistent deployment.

**Level 2: Automated Hardening**
- Infrastructure as Code (Terraform, Pulumi)
- Automated baseline verification
- Drift detection and remediation

**Level 3: Continuous Compliance Validation**
- Real-time configuration monitoring
- Automated remediation
- Compliance-as-code

**Output:** Hardening checklist, secure deployment runbook
```

### IM: Issue Management

```
Let's establish Issue Management for your HAI system.

**Current Level Check:**
How do you track security vulnerabilities?
[ ] No tracking  [ ] Ad-hoc  [ ] Issue tracker  [ ] Automated scanning + SLAs

**Level 1 Activity: Vulnerability Tracking Process**

Step 1: Define what to track
> What security issues should be tracked?
- Code vulnerabilities (SAST findings)
- Dependency vulnerabilities (SCA findings)
- AI-specific vulnerabilities (prompt injection, excessive agency)
- Configuration issues
- Penetration test findings
- Security incidents

Step 2: Establish severity classification
```markdown
## Severity Levels

### Critical (Fix within 24 hours)
- Active exploitation possible
- PII/sensitive data exposure
- Complete AI containment bypass
- Authentication/authorization bypass

### High (Fix within 7 days)
- Significant security weakness
- Partial AI boundary violations
- Privilege escalation possible
- Data integrity risks

### Medium (Fix within 30 days)
- Defense in depth gaps
- Non-critical information disclosure
- Hardening recommendations
- Best practice violations

### Low (Fix within 90 days)
- Minor security improvements
- Code quality issues
- Documentation gaps
```

Step 3: Set up tracking workflow
```markdown
## Issue Workflow

1. **Discover** - Finding identified
2. **Triage** - Severity assigned, owner assigned
3. **Remediate** - Fix developed and tested
4. **Verify** - Fix verified effective
5. **Close** - Issue resolved and documented

## Required Fields
- Title: Clear description
- Severity: Critical/High/Medium/Low
- Component: Affected system
- Owner: Who will fix
- Due Date: Based on SLA
- Evidence: How discovered
- Remediation: How to fix
```

**Level 2: SLA-Based Remediation**
- Automated severity assignment
- SLA tracking and escalation
- Metrics on remediation times

**Level 3: Automated Detection and Triage**
- Continuous scanning integration
- AI-assisted triage
- Predictive vulnerability management

**Output:** Severity classification, issue tracking setup
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

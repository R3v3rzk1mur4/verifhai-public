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

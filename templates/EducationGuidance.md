# Education & Guidance (EG) Template

## Document Control

| Field | Value |
|-------|-------|
| Project | [Project Name] |
| Version | 1.0 |
| Date | [YYYY-MM-DD] |
| Author | [Author Name] |
| Status | Draft / Approved |

---

## 1. HAI Security Training Program

### 1.1 Training Objectives

By completing the HAI security training program, participants will be able to:

1. **Understand** the unique security risks of HAI systems
2. **Identify** AI-specific threats (prompt injection, excessive agency, tool misuse)
3. **Apply** secure coding patterns for HAI development
4. **Implement** permission boundaries and containment controls
5. **Respond** to HAI security incidents appropriately

### 1.2 Target Audiences

| Audience | Role | Training Needs |
|----------|------|----------------|
| AI/ML Engineers | Build HAI systems | Deep technical, secure coding |
| Backend Engineers | Integrate with HAI | API security, data protection |
| Frontend Engineers | Build HAI interfaces | Input validation, output handling |
| DevOps/SRE | Deploy and operate | Containment, monitoring, incident response |
| Product Managers | Design HAI features | Risk awareness, security requirements |
| Security Engineers | Secure HAI systems | Full curriculum, assessment skills |
| Leadership | Oversee HAI initiatives | Risk understanding, governance |

---

## 2. Training Curriculum

### 2.1 HAI Security Fundamentals (All Staff)

**Duration:** 2 hours | **Frequency:** Annual | **Format:** Online + Assessment

#### Module 1: Introduction to HAI Security (30 min)

```
Learning Objectives:
- Define Human-Assisted Intelligence (HAI)
- Explain why HAI security differs from traditional security
- List the four primary HAI threat categories

Topics:
1. What is HAI?
   - AI agents, LLM integrations, AI pipelines
   - The human-in-the-loop model
   - Why HAI is different from traditional software

2. The HAI Threat Landscape
   - Traditional security risks (OWASP Top 10)
   - AI-specific risks (OWASP Top 10 for LLM)
   - The four HAI threats:
     * EA: Excessive Agency
     * AGH: Agent Goal Hijacking
     * TM: Tool Misuse
     * RA: Rogue Agents

3. Real-World Examples
   - Case studies of HAI security incidents
   - Impact and lessons learned
```

#### Module 2: Understanding HAI Threats (45 min)

```
Learning Objectives:
- Recognize prompt injection attacks
- Understand excessive agency risks
- Identify tool misuse scenarios

Topics:
1. Prompt Injection Attacks
   - Direct injection (user input)
   - Indirect injection (data sources)
   - Instruction override attacks
   - Real examples and demos

2. Excessive Agency (EA)
   - Too many permissions
   - Missing boundaries
   - Unconstrained autonomy
   - Case study: Agent with file system access

3. Agent Goal Hijacking (AGH)
   - Goal manipulation via prompts
   - Multi-turn goal drift
   - Conflicting instructions

4. Tool Misuse (TM)
   - Path traversal
   - Command injection via tools
   - API abuse

5. Rogue Agents (RA)
   - Runaway agents
   - Resource exhaustion
   - Self-modification attempts

Assessment: Quiz (10 questions, 80% to pass)
```

#### Module 3: Your Role in HAI Security (45 min)

```
Learning Objectives:
- Apply security awareness to daily work
- Follow HAI security policies
- Report security concerns

Topics:
1. Security Policies & Compliance
   - Permission boundary requirements
   - Data protection requirements
   - Logging and audit requirements

2. Secure Behaviors
   - Reviewing AI outputs before use
   - Reporting suspicious AI behavior
   - Following least privilege

3. Incident Response
   - What to report
   - How to report
   - Escalation paths

Assessment: Scenario-based exercise
```

### 2.2 Secure HAI Development (Engineers)

**Duration:** 4 hours | **Frequency:** Annual | **Format:** Instructor-led + Labs

#### Module 1: Secure HAI Architecture (60 min)

```
Learning Objectives:
- Design secure permission boundaries
- Apply defense-in-depth to HAI systems
- Implement containment patterns

Topics:
1. Permission Architecture
   - Allowed/Prohibited/Must model
   - Permission gate pattern
   - Deny by default

2. Defense in Depth
   - Input validation layer
   - Permission enforcement layer
   - Tool sandboxing layer
   - Output validation layer

3. Containment Patterns
   - Iteration limits
   - Resource budgets
   - Timeout enforcement
   - Kill switch implementation

Lab: Design permission boundaries for sample agent
```

#### Module 2: Secure Coding Patterns (90 min)

```
Learning Objectives:
- Implement input validation
- Build secure permission gates
- Create safe tool integrations

Topics:
1. Input Validation
   - Structural validation
   - Injection pattern detection
   - Risk scoring
   - Secure sanitization

2. Permission Enforcement
   - Building a permission gate
   - Allowlist/denylist patterns
   - Rate limiting
   - Audit logging

3. Tool Safety
   - Schema validation
   - Input sanitization
   - Output validation
   - Timeout handling

4. Secure Logging
   - What to log
   - PII sanitization
   - Tamper-evident logging
   - Log protection

Lab: Implement security controls for sample tool
```

#### Module 3: Prompt Security (60 min)

```
Learning Objectives:
- Build injection-resistant prompts
- Separate system and user content
- Validate AI outputs

Topics:
1. Prompt Construction
   - System prompt isolation
   - User input delimiting
   - Instruction protection
   - Output format specification

2. Injection Defense
   - Pattern-based detection
   - Semantic analysis
   - Multi-layer defense

3. Output Validation
   - Format validation
   - Content sanitization
   - Action verification

Lab: Build secure prompt pipeline
```

#### Module 4: Testing & Validation (30 min)

```
Learning Objectives:
- Write security tests for HAI systems
- Perform prompt injection testing
- Test permission boundaries

Topics:
1. Security Test Cases
   - Permission boundary tests
   - Injection tests
   - Tool safety tests
   - Containment tests

2. Testing Techniques
   - Fuzzing
   - Adversarial testing
   - Red teaming

Assessment: Build and test secure agent component
```

### 2.3 HAI Security for DevOps/SRE

**Duration:** 3 hours | **Frequency:** Annual | **Format:** Instructor-led + Labs

```
Modules:
1. Secure Deployment (60 min)
   - Container security for AI
   - Secret management
   - Network isolation
   - Runtime protections

2. Monitoring & Detection (60 min)
   - Log aggregation
   - Anomaly detection
   - Alert configuration
   - Dashboard setup

3. Incident Response (60 min)
   - Kill switch procedures
   - Containment actions
   - Investigation steps
   - Recovery procedures

Labs: Configure monitoring, practice incident response
```

### 2.4 HAI Security for Leadership

**Duration:** 1 hour | **Frequency:** Annual | **Format:** Online

```
Modules:
1. HAI Risk Landscape (20 min)
   - Business risks of HAI
   - Regulatory considerations
   - Reputation impact

2. Governance & Compliance (20 min)
   - Policy requirements
   - Compliance frameworks
   - Audit expectations

3. Decision Making (20 min)
   - Risk acceptance
   - Investment priorities
   - Incident escalation
```

---

## 3. Security Guidance Resources

### 3.1 Quick Reference Guides

| Guide | Audience | Content |
|-------|----------|---------|
| HAI Security Checklist | Developers | Pre-commit security checklist |
| Prompt Security Guide | Developers | Secure prompt construction |
| Tool Integration Guide | Developers | Safe tool development |
| Incident Response Card | All | Emergency response steps |
| Permission Model Template | Architects | Boundary definition template |

### 3.2 HAI Security Checklist (Quick Reference)

```markdown
## Pre-Commit Security Checklist

### Permission & Access
[ ] Permission boundaries defined (CAN/CANNOT/MUST)
[ ] Deny by default implemented
[ ] Permissions checked before each action
[ ] Least privilege applied

### Input Security
[ ] All inputs validated at boundaries
[ ] Injection patterns detected
[ ] Input size limits enforced
[ ] User content marked as untrusted

### Tool Security
[ ] Tool inputs validated against schema
[ ] Tool outputs validated
[ ] Rate limits enforced
[ ] Timeouts configured

### Prompt Security
[ ] System prompts separated from user input
[ ] User input delimited
[ ] Output format specified
[ ] AI outputs validated before use

### Logging & Audit
[ ] All tool invocations logged
[ ] Permission decisions logged
[ ] PII sanitized in logs
[ ] Errors logged securely

### Containment
[ ] Iteration limits set
[ ] Resource budgets enforced
[ ] Timeout protection active
[ ] Kill switch accessible

### Secrets & Data
[ ] No hardcoded secrets
[ ] Secrets from secure storage
[ ] PII protected
[ ] Data classification applied
```

### 3.3 Common Mistakes Guide

| Mistake | Why It's Dangerous | Correct Approach |
|---------|-------------------|------------------|
| Trusting AI output directly | AI can be manipulated | Validate before execution |
| Unlimited tool access | Excessive agency | Define permission boundaries |
| User input in system prompt | Prompt injection | Separate and delimit |
| No iteration limits | Runaway agents | Enforce limits |
| Logging PII | Data breach | Sanitize logs |
| No permission checks | Unauthorized actions | Check every action |

---

## 4. Awareness Campaigns

### 4.1 Annual Campaigns

| Campaign | Timing | Focus | Activities |
|----------|--------|-------|------------|
| HAI Security Awareness Month | October | Overall awareness | Talks, challenges, newsletter |
| Prompt Injection Week | Q1 | Injection attacks | CTF, demos, training |
| Permission Hygiene | Q2 | Least privilege | Audit, cleanup, recognition |
| Incident Response Drill | Q3 | Readiness | Tabletop exercise, simulation |

### 4.2 Ongoing Activities

| Activity | Frequency | Format | Participation |
|----------|-----------|--------|---------------|
| Security newsletter | Monthly | Email | All staff |
| Lunch & learn | Monthly | In-person/Virtual | Interested |
| Bug bounty updates | Ongoing | Slack/Email | Security team |
| Code review feedback | Ongoing | PR comments | Developers |

### 4.3 Recognition Program

| Achievement | Recognition | Award |
|-------------|-------------|-------|
| Complete all training | Security Champion badge | Swag |
| Report valid security issue | Bug Hunter recognition | Bounty |
| Mentor colleagues on security | Mentor badge | Recognition |
| Present at Lunch & Learn | Speaker recognition | Thank you |

---

## 5. Role-Specific Guidance

### 5.1 For Developers Writing AI Agents

```
Key Responsibilities:
1. Define permission boundaries before coding
2. Implement all five security layers:
   - Input validation
   - Permission enforcement
   - Tool sandboxing
   - Output validation
   - Secure logging
3. Write security tests alongside feature code
4. Request security review for AI-related changes

Resources:
- Secure Coding Patterns: [link]
- HAI Security Architecture: [link]
- Permission Model Template: [link]
- Security Review Checklist: [link]
```

### 5.2 For Code Reviewers

```
Key Responsibilities:
1. Check for permission boundary enforcement
2. Verify input validation is present
3. Confirm tool inputs are validated
4. Ensure logging doesn't expose secrets
5. Validate containment controls exist

Review Checklist:
[ ] Permission model documented
[ ] Inputs validated before processing
[ ] Tools use schema validation
[ ] Secrets not in code
[ ] Logging sanitizes PII
[ ] Error handling is secure
[ ] Tests cover security cases
```

### 5.3 For Security Engineers

```
Key Responsibilities:
1. Conduct threat assessments for new HAI features
2. Review architecture designs for security
3. Perform security testing (manual + automated)
4. Respond to HAI security incidents
5. Update training and guidance materials

Assessment Approach:
1. Review permission boundaries
2. Test prompt injection defenses
3. Verify tool safety controls
4. Assess containment mechanisms
5. Audit logging completeness
```

---

## 6. Knowledge Assessment

### 6.1 Assessment Structure

| Training | Assessment Type | Passing Score | Validity |
|----------|-----------------|---------------|----------|
| Fundamentals | Multiple choice quiz | 80% | 1 year |
| Secure Development | Lab + quiz | 80% | 1 year |
| DevOps/SRE | Lab exercise | Complete all tasks | 1 year |
| Leadership | Case study | Complete exercise | 1 year |

### 6.2 Sample Questions

**Fundamentals:**
```
Q: What is the primary risk of giving an AI agent file system write access?
A) Slower performance
B) Excessive Agency - unauthorized file modifications
C) Increased logging
D) Better functionality
Answer: B
```

**Secure Development:**
```
Q: Which layer should validate user input for injection patterns?
A) Tool layer only
B) AI agent logic
C) Input validation layer (before AI processing)
D) Logging layer
Answer: C
```

### 6.3 Certification Tracking

| Employee | Fundamentals | Secure Dev | Role-Specific | Status |
|----------|--------------|------------|---------------|--------|
| [Name] | [Date/Score] | [Date/Score] | [Date/Score] | [Valid/Expired] |

---

## 7. Continuous Learning

### 7.1 External Resources

| Resource | Type | Link |
|----------|------|------|
| OWASP Top 10 for LLM | Guide | owasp.org/llm-top-10 |
| MITRE ATLAS | Threat database | atlas.mitre.org |
| Anthropic Security | Blog | anthropic.com/security |
| OpenAI Safety | Research | openai.com/safety |

### 7.2 Internal Resources

| Resource | Location | Maintainer |
|----------|----------|------------|
| HAI Security Wiki | [wiki link] | Security Team |
| Code Examples | [repo link] | Engineering |
| Threat Models | [docs link] | Security Team |
| Incident Reports | [restricted] | Security Team |

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | [Date] | [Author] | Initial curriculum |

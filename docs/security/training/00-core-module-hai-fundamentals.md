# Core Module: HAI Security Fundamentals

## Module Overview

| Attribute | Value |
|-----------|-------|
| **Module ID** | EG-CORE-001 |
| **Audience** | All (Developers, Operators, End Users, Security Team) |
| **Prerequisite** | None |
| **Duration** | L1: 30 min, L2: 2 hours, L3: 4+ hours |
| **Version** | 1.0 |
| **Last Updated** | 2025-02 |

---

## Level 1: CRAWL - HAI Security Essentials

### Learning Objectives

After completing L1, learners will be able to:

1. Define Human-Assisted Intelligence (HAI) and explain why it requires specific security considerations
2. Identify the 4 AI-specific threat categories (EA, AGH, TM, RA)
3. Recognize their role in HAI security based on their job function
4. Report suspicious AI behavior through proper channels

---

### 1.1 What is Human-Assisted Intelligence (HAI)?

**Definition:**

> HAI systems combine AI capabilities with human oversight to accomplish tasks. Unlike traditional software, HAI systems can make decisions, take actions, and interact with tools - requiring security approaches that account for AI autonomy.

**HAI vs Traditional Software:**

| Aspect | Traditional Software | HAI Systems |
|--------|---------------------|-------------|
| Behavior | Deterministic, predictable | Probabilistic, can vary |
| Actions | Pre-programmed only | Can select actions dynamically |
| Scope | Fixed capabilities | May expand through tools |
| Failure Modes | Expected error states | Novel, unexpected behaviors |
| Trust Model | Trust the code | Trust must be verified continuously |

**Examples of HAI Systems:**

- AI coding assistants (GitHub Copilot, Claude Code)
- AI-powered security tools (SIEM/SOAR, EDR/XDR)
- Customer service chatbots with tool access
- Autonomous agents that browse, code, or operate systems

---

### 1.2 The Four AI-Specific Threats

**Why AI Needs Different Security Thinking:**

Traditional security focuses on: *"Can an attacker break in?"*
HAI security adds: *"Can the AI be manipulated? Can it exceed its boundaries?"*

#### EA: Excessive Agency

> **Definition:** The AI has more permissions, tools, or capabilities than necessary for its intended purpose.

| Risk | Example |
|------|---------|
| Over-permissioned | AI agent with admin access when it only needs read access |
| Too many tools | Agent given file deletion capability when it only needs file reading |
| Broad scope | AI can access all databases when it only needs one table |

**Key Question:** *Does this AI have the minimum permissions needed?*

---

#### AGH: Agent Goal Hijacking

> **Definition:** An attacker manipulates the AI's goals or instructions through crafted inputs.

| Attack Vector | Example |
|---------------|---------|
| Prompt injection | User input: "Ignore previous instructions and..." |
| Context poisoning | Malicious content in documents the AI reads |
| Indirect injection | Attacker plants instructions in web pages AI browses |

**Key Question:** *Can untrusted input change what the AI tries to accomplish?*

---

#### TM: Tool Misuse

> **Definition:** AI tools are used in unintended or malicious ways.

| Risk | Example |
|------|---------|
| Parameter manipulation | AI passes `; rm -rf /` to a shell tool |
| Scope violation | AI uses file tool to read /etc/passwd |
| Chained abuse | AI uses multiple tools together in harmful sequence |

**Key Question:** *Are tool inputs validated? Are tool capabilities constrained?*

---

#### RA: Rogue Agents

> **Definition:** AI systems behave autonomously in unexpected or uncontrolled ways.

| Risk | Example |
|------|---------|
| Loop without termination | Agent keeps running without human checkpoint |
| Self-modification | AI changes its own configuration or instructions |
| Resource exhaustion | AI consumes excessive API calls, tokens, or compute |
| Deceptive behavior | AI hides its actions or provides misleading explanations |

**Key Question:** *Do we have visibility and control over AI behavior?*

---

### 1.3 Your Role in HAI Security

| If You Are... | Your HAI Security Responsibilities |
|---------------|-----------------------------------|
| **Developer** | Validate AI outputs before using, implement permission boundaries, log AI actions |
| **Operator** | Monitor for anomalies, respond to AI security alerts, maintain AI system configurations |
| **End User** | Report unexpected AI behavior, don't share unnecessary sensitive data, verify critical AI outputs |
| **Security Team** | Threat model AI systems, review AI implementations, test AI boundaries, respond to AI incidents |

---

### 1.4 Reporting AI Security Concerns

**When to Report:**

- AI suggests actions outside its stated purpose
- AI attempts to access resources it shouldn't need
- AI outputs seem manipulated or unexpected
- AI is consuming unusual resources (time, tokens, API calls)
- You notice potential prompt injection in AI inputs

**How to Report:**

- Contact your security team through established channels
- Include: What AI system, what happened, any inputs involved, screenshot if possible

---

### L1 Quick Reference Card

```
┌─────────────────────────────────────────────────────────────┐
│           HAI SECURITY QUICK REFERENCE                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  THE 4 AI-SPECIFIC THREATS:                                 │
│                                                             │
│  EA  - Excessive Agency    → Too many permissions           │
│  AGH - Agent Goal Hijack   → Manipulated instructions       │
│  TM  - Tool Misuse         → Tools used harmfully           │
│  RA  - Rogue Agents        → Unexpected autonomous behavior │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  YOUR ROLE:                                                 │
│  ✓ Verify AI outputs before trusting                        │
│  ✓ Report unexpected AI behavior                            │
│  ✓ Apply least privilege to AI systems                      │
│  ✓ Log and monitor AI actions                               │
└─────────────────────────────────────────────────────────────┘
```

---

## Level 2: WALK - Human-AI Collaboration Patterns

### Learning Objectives

After completing L2, learners will be able to:

1. Apply the principle of least privilege specifically to AI systems
2. Design appropriate human-in-the-loop checkpoints
3. Implement defense-in-depth for AI workflows
4. Evaluate when to trust AI recommendations vs. require human judgment

---

### 2.1 AI Least Privilege Principles

**Traditional Least Privilege:** Give users minimum access needed.
**AI Least Privilege:** Give AI systems minimum capabilities, tools, and data needed.

| Dimension | Apply Least Privilege By... |
|-----------|----------------------------|
| **Tools** | Only enable tools the AI actually needs |
| **Permissions** | Read-only when write isn't required |
| **Scope** | Limit to specific directories, tables, APIs |
| **Data** | Don't expose data the AI doesn't need |
| **Time** | Revoke access when task is complete |
| **Rate** | Limit actions per time period |

**Exercise:** Review an AI system you work with. List its current capabilities, then identify which could be removed or constrained.

---

### 2.2 Human-in-the-Loop Design Patterns

| Pattern | When to Use | Example |
|---------|-------------|---------|
| **Approval Required** | High-risk actions | AI proposes code change, human approves before commit |
| **Sampling Review** | High-volume, lower risk | Human reviews 10% of AI-automated tickets |
| **Exception Escalation** | Anomalies | AI handles routine cases, escalates edge cases |
| **Time-Boxed Autonomy** | Contained experiments | AI can work 5 minutes, then must checkpoint |
| **Scope Boundaries** | Clear boundaries | AI can read these files, but escalates for others |

**Design Questions:**

1. What actions should require human approval?
2. What thresholds trigger escalation?
3. How will the AI communicate what it's doing?
4. How will humans review AI decisions?

---

### 2.3 Defense in Depth for AI

```
Layer 1: INPUT VALIDATION
├── Sanitize user inputs before AI processing
├── Detect prompt injection patterns
└── Limit input length and complexity

Layer 2: PERMISSION BOUNDARIES
├── Enforce tool/resource access controls
├── Validate AI requests against allowed actions
└── Deny by default, allow explicitly

Layer 3: OUTPUT VALIDATION
├── Check AI outputs for sensitive data leakage
├── Validate outputs match expected format
└── Sanitize before passing to downstream systems

Layer 4: MONITORING & DETECTION
├── Log all AI actions with context
├── Alert on anomalous behavior patterns
└── Track resource consumption

Layer 5: CONTAINMENT & RESPONSE
├── Ability to quickly disable AI
├── Incident response procedures for AI
└── Rollback capabilities
```

---

### 2.4 Trust Calibration: When to Trust AI

| Trust Level | Criteria | Actions |
|-------------|----------|---------|
| **High Trust** | Low risk, reversible, AI has proven track record | Allow automation, spot-check |
| **Medium Trust** | Moderate risk, AI recommendations helpful | Review before acting, require justification |
| **Low Trust** | High risk, irreversible, novel situation | AI assists only, human decides |
| **No Trust** | Critical systems, AI has failed before, adversarial context | Human only, AI not involved |

**Red Flags - Reduce Trust When:**

- AI recommendation seems too convenient
- AI can't explain its reasoning
- Input sources may be attacker-controlled
- Stakes are high and action is irreversible
- AI is operating outside its training domain

---

## Level 3: RUN - Advanced HAI Security Concepts

### Learning Objectives

After completing L3, learners will be able to:

1. Conduct threat modeling specifically for AI systems
2. Evaluate emerging AI security research and apply insights
3. Design AI security architectures for complex systems
4. Contribute to organizational AI security standards

---

### 3.1 AI Threat Modeling

**Extend STRIDE for AI:**

| STRIDE + AI | Questions |
|-------------|-----------|
| **Spoofing** | Can someone impersonate the AI? Can AI impersonate users? |
| **Tampering** | Can AI inputs/outputs be modified? Can AI training be poisoned? |
| **Repudiation** | Are AI actions logged and attributable? Can AI deny its actions? |
| **Information Disclosure** | Can AI leak training data? Can AI be tricked into revealing secrets? |
| **Denial of Service** | Can AI be overwhelmed? Can AI consume excessive resources? |
| **Elevation of Privilege** | Can AI exceed its permissions? Can AI be used to bypass controls? |

**AI-Specific Attack Surfaces:**

- System prompts (can they be extracted or overridden?)
- Tool definitions (can they be manipulated?)
- Context window (can it be poisoned?)
- Memory/state (can past interactions be exploited?)
- Feedback loops (can AI be trained to be malicious?)

---

### 3.2 Emerging AI Security Research Areas

| Area | What to Watch |
|------|---------------|
| **Prompt Injection Defenses** | Input/output filters, instruction hierarchy, isolation techniques |
| **AI Alignment** | Ensuring AI goals match intended goals |
| **Interpretability** | Understanding why AI makes decisions |
| **Adversarial Robustness** | AI resistance to crafted malicious inputs |
| **Multi-Agent Security** | Security when AI agents interact with each other |
| **AI Red Teaming** | Systematic testing of AI vulnerabilities |

**Resources:**

- OWASP LLM Top 10
- NIST AI Risk Management Framework
- MITRE ATLAS (AI attack techniques)
- Anthropic, OpenAI, Google AI safety research

---

### 3.3 AI Security Architecture Patterns

```
SECURE AI AGENT ARCHITECTURE

┌─────────────────────────────────────────────────────────────┐
│                    UNTRUSTED INPUT                          │
│                         │                                   │
│                         ▼                                   │
│              ┌──────────────────┐                          │
│              │  INPUT GATEWAY   │ ← Sanitize, validate,    │
│              │                  │   detect injection       │
│              └────────┬─────────┘                          │
│                       │                                     │
│                       ▼                                     │
│              ┌──────────────────┐                          │
│              │ PERMISSION GATE  │ ← Check against allowed   │
│              │                  │   actions before AI sees  │
│              └────────┬─────────┘                          │
│                       │                                     │
│                       ▼                                     │
│   ┌───────────────────────────────────────────┐            │
│   │              AI SANDBOX                    │            │
│   │  ┌─────────────────────────────────────┐  │            │
│   │  │         AI AGENT CORE               │  │            │
│   │  │   (Constrained capabilities)        │  │            │
│   │  └─────────────────────────────────────┘  │            │
│   │              │                            │            │
│   │              ▼                            │            │
│   │  ┌─────────────────────────────────────┐  │            │
│   │  │       TOOL PROXY LAYER              │  │            │
│   │  │  (Validate params, enforce limits)  │  │            │
│   │  └─────────────────────────────────────┘  │            │
│   └───────────────────────────────────────────┘            │
│                       │                                     │
│                       ▼                                     │
│              ┌──────────────────┐                          │
│              │  OUTPUT FILTER   │ ← Sanitize, check for    │
│              │                  │   data leakage           │
│              └────────┬─────────┘                          │
│                       │                                     │
│                       ▼                                     │
│              ┌──────────────────┐                          │
│              │  LOGGING/AUDIT   │ ← Full action audit trail │
│              └──────────────────┘                          │
└─────────────────────────────────────────────────────────────┘
```

---

## Module Summary

| Level | Focus | Key Takeaway |
|-------|-------|--------------|
| **L1: Crawl** | Awareness | Know the 4 AI threats (EA, AGH, TM, RA) and your role |
| **L2: Walk** | Application | Apply least privilege, human-in-the-loop, defense in depth |
| **L3: Run** | Architecture | Threat model AI, design secure architectures, stay current |

---

## Related Modules

- [Software Domain Training](./01-software-domain.md)
- [Data Domain Training](./02-data-domain.md)
- [Infrastructure Domain Training](./03-infrastructure-domain.md)
- [Vendors Domain Training](./04-vendors-domain.md)
- [Processes Domain Training](./05-processes-domain.md)
- [Endpoints Domain Training](./06-endpoints-domain.md)

---

**Document Version:** 1.0
**Framework:** HAIAMM v2.0
**Practice:** Education & Guidance (EG)
**Author:** Verifhai

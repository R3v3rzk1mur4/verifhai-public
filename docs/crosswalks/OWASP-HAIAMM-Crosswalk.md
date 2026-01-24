# OWASP ↔ HAIAMM Crosswalk

## Mapping OWASP AI Security Standards to HAIAMM Practices

**Version:** 1.0.0
**Last Updated:** January 2026
**HAIAMM Version:** 2.2

---

## Purpose

This document provides a **comprehensive crosswalk** between OWASP AI security standards and the HAIAMM (Human-Assisted Intelligence Assurance Maturity Model) framework. It enables organizations to:

- Understand how HAIAMM practices address OWASP vulnerabilities
- Use OWASP as tactical guidance within HAIAMM's maturity framework
- Demonstrate compliance coverage for audits and assessments
- Identify gaps and prioritize remediation efforts

**Frameworks Covered:**
- OWASP Top 10 for LLM Applications 2025
- OWASP Top 10 for Agentic Applications 2026
- HAIAMM v2.2 (12 core practices + 4 HAI-specific)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Framework Positioning](#2-framework-positioning)
3. [OWASP LLM Top 10 Crosswalk](#3-owasp-llm-top-10-crosswalk)
4. [OWASP Agentic AI Top 10 Crosswalk](#4-owasp-agentic-ai-top-10-crosswalk)
5. [HAIAMM Practice Coverage Matrix](#5-haiamm-practice-coverage-matrix)
6. [Gap Analysis](#6-gap-analysis)
7. [Implementation Guidance](#7-implementation-guidance)
8. [Assessment Mapping](#8-assessment-mapping)
9. [VerifHAI Integration](#9-verifhai-integration)
10. [Resources](#10-resources)

---

# 1. Executive Summary

## 1.1 Key Finding

**HAIAMM provides 100% coverage of OWASP AI security risks** through its practice framework, with particularly strong alignment in the HAI-specific practices (EA, AGH, TM, RA) which directly mirror four of the top Agentic AI risks.

```
┌────────────────────────────────────────────────────────────────────────────┐
│                    FRAMEWORK COVERAGE SUMMARY                               │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  OWASP LLM Top 10 2025                                                      │
│  ─────────────────────                                                      │
│  ████████████████████████████████████████  100% coverage by HAIAMM         │
│  Primary: TA, SR, SA, IR, ST, ML                                           │
│                                                                             │
│  OWASP Agentic AI Top 10 2026                                               │
│  ────────────────────────────                                               │
│  ████████████████████████████████████████  100% coverage by HAIAMM         │
│  Primary: EA, AGH, TM, RA, SA, ML, ST                                      │
│                                                                             │
│  HAIAMM HAI-Specific Practices                                              │
│  ─────────────────────────────                                              │
│  EA (Excessive Agency)    ←──→  LLM06, Agentic #2, #3, #6                 │
│  AGH (Agent Goal Hijack)  ←──→  LLM01, Agentic #1, #5, #8                 │
│  TM (Tool Misuse)         ←──→  LLM05, Agentic #3, #6                     │
│  RA (Rogue Agents)        ←──→  Agentic #9, #10                            │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

## 1.2 How to Use This Document

| If You Need To... | Go To... |
|-------------------|----------|
| Map a specific OWASP risk to HAIAMM | Section 3 or 4 |
| See which OWASP risks a HAIAMM practice covers | Section 5 |
| Identify gaps in your coverage | Section 6 |
| Plan implementation priorities | Section 7 |
| Answer audit questions | Section 8 |
| Use VerifHAI for OWASP compliance | Section 9 |

---

# 2. Framework Positioning

## 2.1 Different Purposes, Complementary Value

```
┌────────────────────────────────────────────────────────────────────────────┐
│                    FRAMEWORK POSITIONING                                    │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│                          STRATEGIC                                          │
│                              ▲                                              │
│                              │                                              │
│                    ┌─────────┴─────────┐                                   │
│                    │     HAIAMM        │                                   │
│                    │   Maturity Model  │                                   │
│                    │                   │                                   │
│                    │ • 6 Domains       │                                   │
│                    │ • 12+ Practices   │                                   │
│                    │ • 3 Levels        │                                   │
│                    │ • Progression     │                                   │
│                    │ • Measurement     │                                   │
│                    └─────────┬─────────┘                                   │
│                              │                                              │
│            ┌─────────────────┼─────────────────┐                           │
│            │                 │                 │                           │
│            ▼                 ▼                 ▼                           │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐              │
│  │  OWASP LLM      │ │ OWASP Agentic   │ │  Other          │              │
│  │  Top 10         │ │ Top 10          │ │  Standards      │              │
│  │                 │ │                 │ │  (NIST, ISO)    │              │
│  │ • Vulnerabilities│ │ • Agent Risks  │ │                 │              │
│  │ • Attack vectors│ │ • Autonomous    │ │                 │              │
│  │ • Mitigations   │ │   threats       │ │                 │              │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘              │
│                              │                                              │
│                              ▼                                              │
│                          TACTICAL                                           │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

## 2.2 Framework Comparison

| Attribute | OWASP LLM Top 10 | OWASP Agentic Top 10 | HAIAMM |
|-----------|------------------|----------------------|--------|
| **Type** | Vulnerability list | Risk catalog | Maturity model |
| **Scope** | LLM applications | Autonomous AI agents | All HAI systems |
| **Structure** | 10 ranked risks | 10 ranked risks | 6 domains × 12 practices × 3 levels |
| **Measurement** | Binary (addressed/not) | Binary (addressed/not) | Continuous (0-3.0 score) |
| **Progression** | None | None | L1 → L2 → L3 |
| **Tooling** | Checklists | Checklists | VerifHAI (Skill + CLI) |
| **Best For** | Security teams, AppSec | Agent developers | Program management, governance |

## 2.3 Recommended Usage Pattern

```
┌────────────────────────────────────────────────────────────────────────────┐
│                    RECOMMENDED USAGE PATTERN                                │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. USE HAIAMM FOR:                      2. USE OWASP FOR:                  │
│  ──────────────────                      ───────────────────                │
│                                                                             │
│  • Program structure                     • Specific vulnerability details  │
│  • Maturity measurement                  • Attack vector descriptions      │
│  • Progress tracking                     • Technical mitigations           │
│  • Resource prioritization               • Testing methodologies           │
│  • Executive reporting                   • Developer training              │
│  • Multi-year roadmaps                   • Code review checklists          │
│                                                                             │
│                                                                             │
│  3. INTEGRATION APPROACH:                                                   │
│  ────────────────────────                                                   │
│                                                                             │
│  ┌───────────┐    ┌───────────┐    ┌───────────┐    ┌───────────┐         │
│  │  HAIAMM   │───▶│  OWASP    │───▶│  Specific │───▶│  Verify   │         │
│  │  Practice │    │  Mapping  │    │  Controls │    │  Coverage │         │
│  │  (e.g. TA)│    │  (e.g.    │    │  (e.g.    │    │  (e.g.    │         │
│  │           │    │  LLM01)   │    │  input    │    │  /verifhai│         │
│  │           │    │           │    │  validation│   │  review)  │         │
│  └───────────┘    └───────────┘    └───────────┘    └───────────┘         │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

---

# 3. OWASP LLM Top 10 Crosswalk

## 3.1 Complete Mapping Table

| OWASP ID | Vulnerability | Primary HAIAMM | Secondary HAIAMM | HAI Practice |
|----------|---------------|----------------|------------------|--------------|
| **LLM01:2025** | Prompt Injection | TA, SR, SA | IR, ST, ML | AGH |
| **LLM02:2025** | Sensitive Information Disclosure | SR, SA, IR | ST, ML, EH | - |
| **LLM03:2025** | Supply Chain | TA, SR, EH | IR, ST, IM | - |
| **LLM04:2025** | Data and Model Poisoning | TA, SR, SA | ST, ML, IM | AGH |
| **LLM05:2025** | Improper Output Handling | SR, SA, IR | ST | TM |
| **LLM06:2025** | Excessive Agency | SR, SA, ML | TA, ST | EA |
| **LLM07:2025** | System Prompt Leakage | SR, SA, IR | ST, EH | - |
| **LLM08:2025** | Vector and Embedding Weaknesses | TA, SA, ST | IR, ML | - |
| **LLM09:2025** | Misinformation | SR, SA, ST | ML, EG | - |
| **LLM10:2025** | Unbounded Consumption | SR, SA, EH | ML, IM | EA |

---

## 3.2 Detailed Crosswalk: LLM01 - Prompt Injection

### OWASP Description
Prompt Injection occurs when user input manipulates the LLM to execute unintended actions. This includes direct injection (overriding system prompts) and indirect injection (manipulating external data sources the LLM processes).

### Threat Characteristics
| Attribute | Value |
|-----------|-------|
| **Attack Vector** | User input, external data sources |
| **Impact** | Data exfiltration, unauthorized actions, system manipulation |
| **Exploitability** | High (well-documented techniques) |
| **Prevalence** | Very High (affects most LLM applications) |

### HAIAMM Practice Mapping

```
┌────────────────────────────────────────────────────────────────────────────┐
│  LLM01: PROMPT INJECTION → HAIAMM MAPPING                                   │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  PRIMARY PRACTICES                                                          │
│  ─────────────────                                                          │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ TA (Threat Assessment)                                               │   │
│  │ ────────────────────────                                             │   │
│  │ • Model prompt injection as threat in threat model                  │   │
│  │ • Identify injection surfaces (direct input, RAG, plugins)          │   │
│  │ • Assess impact of successful injection                             │   │
│  │ • Document attack scenarios specific to your application            │   │
│  │                                                                      │   │
│  │ L1: Basic awareness of prompt injection                             │   │
│  │ L2: Documented threat model with injection scenarios                │   │
│  │ L3: Continuous threat modeling with red team exercises              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ SR (Security Requirements)                                           │   │
│  │ ────────────────────────────                                         │   │
│  │ • Define input validation requirements                              │   │
│  │ • Specify forbidden patterns and keywords                           │   │
│  │ • Establish prompt boundary requirements                            │   │
│  │ • Document response filtering rules                                 │   │
│  │                                                                      │   │
│  │ L1: Basic input length limits                                       │   │
│  │ L2: Comprehensive input validation specification                    │   │
│  │ L3: Adaptive requirements based on threat intelligence              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ SA (Secure Architecture)                                             │   │
│  │ ───────────────────────────                                          │   │
│  │ • Design input sanitization layer                                   │   │
│  │ • Implement prompt/data separation                                  │   │
│  │ • Create output filtering mechanisms                                │   │
│  │ • Establish privilege boundaries between components                 │   │
│  │                                                                      │   │
│  │ L1: Basic input sanitization                                        │   │
│  │ L2: Layered defense architecture                                    │   │
│  │ L3: Zero-trust prompt handling with verification                    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  HAI-SPECIFIC PRACTICE                                                      │
│  ────────────────────                                                       │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ AGH (Agent Goal Hijack)                                              │   │
│  │ ─────────────────────────                                            │   │
│  │ • Prompt injection is a primary AGH attack vector                   │   │
│  │ • Implement goal immutability controls                              │   │
│  │ • Monitor for goal drift indicators                                 │   │
│  │ • Validate actions against original objectives                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  SECONDARY PRACTICES                                                        │
│  ───────────────────                                                        │
│                                                                             │
│  • IR (Implementation Review): Review prompt handling code                 │
│  • ST (Security Testing): Fuzz testing, injection testing                  │
│  • ML (Monitoring & Logging): Detect injection attempts in production      │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

### Implementation Checklist

**Level 1 (Foundational):**
- [ ] Threat model includes prompt injection
- [ ] Basic input length limits implemented
- [ ] Input sanitization present
- [ ] Logging captures suspicious inputs

**Level 2 (Comprehensive):**
- [ ] Comprehensive injection scenarios documented
- [ ] Pattern-based input validation
- [ ] Prompt/data separation enforced
- [ ] Output filtering implemented
- [ ] Regular injection testing in CI/CD

**Level 3 (Industry-Leading):**
- [ ] Red team exercises for injection
- [ ] ML-based injection detection
- [ ] Real-time threat intelligence integration
- [ ] Adaptive filtering based on attack patterns

---

## 3.3 Detailed Crosswalk: LLM02 - Sensitive Information Disclosure

### OWASP Description
Sensitive Information Disclosure occurs when an LLM reveals confidential data through its outputs. This includes training data memorization, system prompt exposure, and inference of private information.

### HAIAMM Practice Mapping

| Practice | Role | Activities |
|----------|------|------------|
| **SR** | Primary | Define data classification, specify what cannot be output |
| **SA** | Primary | Design data isolation, implement output filtering |
| **IR** | Primary | Review for data leakage patterns in code |
| **ST** | Secondary | Test for data extraction attacks |
| **ML** | Secondary | Monitor for sensitive data in outputs |
| **EH** | Secondary | Harden environment to prevent access |

### Key Controls

```typescript
// Example: Output filtering for sensitive data (HAIAMM SR + SA)
const SENSITIVE_PATTERNS = [
  /\b\d{3}-\d{2}-\d{4}\b/,           // SSN
  /\b\d{16}\b/,                       // Credit card
  /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/, // Email
  /-----BEGIN.*PRIVATE KEY-----/,     // Private keys
];

function filterOutput(response: string): string {
  let filtered = response;
  for (const pattern of SENSITIVE_PATTERNS) {
    filtered = filtered.replace(pattern, '[REDACTED]');
  }
  return filtered;
}
```

---

## 3.4 Detailed Crosswalk: LLM06 - Excessive Agency

### OWASP Description
Excessive Agency refers to granting LLMs too much capability, permissions, or autonomy. This enables the LLM to undertake damaging actions based on unexpected or ambiguous outputs.

### Direct HAIAMM Alignment

**This OWASP risk has a direct HAIAMM counterpart: EA (Excessive Agency)**

```
┌────────────────────────────────────────────────────────────────────────────┐
│  LLM06: EXCESSIVE AGENCY ←──→ HAIAMM EA: EXCESSIVE AGENCY                  │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  OWASP LLM06 Recommendations          HAIAMM EA Practice Activities        │
│  ───────────────────────────          ─────────────────────────────        │
│                                                                             │
│  Limit LLM capabilities to           L1: Document minimal permissions      │
│  minimum necessary                       required for each AI function      │
│           │                                        │                       │
│           └────────────────────────────────────────┘                       │
│                                                                             │
│  Implement human-in-the-loop         L2: Implement approval workflows      │
│  for high-impact actions                 for sensitive operations          │
│           │                                        │                       │
│           └────────────────────────────────────────┘                       │
│                                                                             │
│  Restrict tool access to             L2: Permission boundaries with        │
│  specific functions                      enforcement mechanisms            │
│           │                                        │                       │
│           └────────────────────────────────────────┘                       │
│                                                                             │
│  Log and monitor all                 L3: Real-time capability monitoring   │
│  LLM-initiated actions                   with anomaly detection            │
│           │                                        │                       │
│           └────────────────────────────────────────┘                       │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

### Least Agency Principle

HAIAMM v2.2 introduces the **Least Agency Principle**:

> "Any AI agent should be constrained to the minimum set of authorities necessary for its specific task. Permissions should never exceed the immediate task scope, regardless of broader system capabilities."

This directly implements OWASP LLM06's core recommendation.

---

## 3.5 Summary: All LLM Top 10 Mappings

### LLM03: Supply Chain
| Practice | Coverage |
|----------|----------|
| TA | Assess third-party AI component risks |
| SR | Define acceptable supply chain requirements |
| EH | Harden dependency management |
| IR | Review third-party integrations |
| ST | Test supply chain components |
| IM | Track vulnerabilities in dependencies |

### LLM04: Data and Model Poisoning
| Practice | Coverage |
|----------|----------|
| TA | Model poisoning attack scenarios |
| SR | Define data integrity requirements |
| SA | Design data validation pipelines |
| ST | Test for poisoning indicators |
| ML | Monitor for drift/anomalies |
| AGH | Prevent goal manipulation via poisoning |

### LLM05: Improper Output Handling
| Practice | Coverage |
|----------|----------|
| SR | Define output formatting requirements |
| SA | Design output sanitization |
| IR | Review output handling code |
| ST | Test for injection via outputs |
| TM | Prevent tool misuse via crafted outputs |

### LLM07: System Prompt Leakage
| Practice | Coverage |
|----------|----------|
| SR | Define prompt confidentiality requirements |
| SA | Design prompt protection mechanisms |
| IR | Review for prompt exposure |
| ST | Test prompt extraction attacks |
| EH | Secure prompt storage |

### LLM08: Vector and Embedding Weaknesses
| Practice | Coverage |
|----------|----------|
| TA | Assess RAG-specific threats |
| SA | Design secure retrieval architecture |
| ST | Test embedding manipulation |
| IR | Review vector DB configurations |
| ML | Monitor retrieval patterns |

### LLM09: Misinformation
| Practice | Coverage |
|----------|----------|
| SR | Define accuracy requirements |
| SA | Design fact-checking mechanisms |
| ST | Test for hallucination rates |
| ML | Monitor output quality |
| EG | Train users on AI limitations |

### LLM10: Unbounded Consumption
| Practice | Coverage |
|----------|----------|
| SR | Define resource limits |
| SA | Design rate limiting |
| EH | Configure resource quotas |
| ML | Monitor consumption patterns |
| IM | Respond to abuse incidents |
| EA | Prevent excessive resource acquisition |

---

# 4. OWASP Agentic AI Top 10 Crosswalk

## 4.1 Complete Mapping Table

| Rank | Agentic Risk | Primary HAIAMM | Secondary HAIAMM | HAI Practice |
|------|--------------|----------------|------------------|--------------|
| **1** | Agent Goal Hijack | TA, SR, SA | ML, ST | AGH |
| **2** | Identity and Privilege Abuse | SR, SA, EH | IR, ML | EA |
| **3** | Unexpected Code Execution | SR, SA, ST | IR, EH | EA, TM |
| **4** | Insecure InterAgent Communication | SA, IR, ST | ML, EH | - |
| **5** | Human Agent Trust Exploitation | SR, SA, EG | ML, ST | AGH |
| **6** | Tool Misuse and Exploitation | SR, SA, ST | IR, ML | TM |
| **7** | Agentic Supply Chain | TA, SR, EH | IR, ST, IM | - |
| **8** | Memory and Context Poisoning | TA, SA, ST | IR, ML | AGH |
| **9** | Cascading Failures | SA, ML, IM | EH, ST | RA |
| **10** | Rogue Agents | SA, ML, IM | ST, EH | RA |

---

## 4.2 Detailed Crosswalk: Agentic #1 - Agent Goal Hijack

### OWASP Description
Agent Goal Hijack occurs when an attacker manipulates an AI agent's objectives, causing it to pursue unintended or malicious goals while appearing to operate normally.

### Direct HAIAMM Alignment

**This OWASP risk has a direct HAIAMM counterpart: AGH (Agent Goal Hijack)**

```
┌────────────────────────────────────────────────────────────────────────────┐
│  AGENTIC #1: AGENT GOAL HIJACK ←──→ HAIAMM AGH: AGENT GOAL HIJACK         │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ATTACK VECTORS                        HAIAMM DEFENSES                     │
│  ──────────────                        ───────────────                     │
│                                                                             │
│  Prompt injection                      AGH L1: Goal immutability          │
│  manipulating goals                    SR: Define inviolable objectives   │
│                                        SA: Separate goal storage          │
│                                                                             │
│  Context poisoning                     AGH L2: Behavioral alignment       │
│  shifting objectives                   ML: Drift detection                │
│                                        ST: Goal integrity testing         │
│                                                                             │
│  Adversarial inputs                    TA: Model attack scenarios         │
│  confusing agent                       SA: Input validation layers        │
│                                        IR: Review goal handling code      │
│                                                                             │
│  Multi-turn manipulation               AGH L2: Session goal tracking      │
│  gradual goal drift                    ML: Conversation analysis          │
│                                        SR: Maximum drift thresholds       │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

### Implementation Example

```typescript
// HAIAMM AGH Implementation: Goal Immutability
interface AgentGoal {
  id: string;
  objective: string;
  constraints: string[];
  hash: string;  // Integrity verification
  createdAt: Date;
  immutable: boolean;
}

class GoalGuard {
  private originalGoals: Map<string, AgentGoal> = new Map();

  registerGoal(goal: AgentGoal): void {
    goal.hash = this.computeHash(goal);
    goal.immutable = true;
    this.originalGoals.set(goal.id, { ...goal });
  }

  validateGoalIntegrity(currentGoal: AgentGoal): boolean {
    const original = this.originalGoals.get(currentGoal.id);
    if (!original) return false;

    const currentHash = this.computeHash(currentGoal);
    if (currentHash !== original.hash) {
      this.alertGoalTampering(original, currentGoal);
      return false;
    }
    return true;
  }

  private alertGoalTampering(original: AgentGoal, current: AgentGoal): void {
    console.error('SECURITY ALERT: Goal tampering detected', {
      originalObjective: original.objective,
      currentObjective: current.objective,
      timestamp: new Date().toISOString(),
    });
  }

  private computeHash(goal: AgentGoal): string {
    const content = `${goal.objective}|${goal.constraints.join(',')}`;
    return crypto.createHash('sha256').update(content).digest('hex');
  }
}
```

---

## 4.3 Detailed Crosswalk: Agentic #6 - Tool Misuse and Exploitation

### OWASP Description
Tool Misuse occurs when AI agents use their authorized tools in unintended ways, potentially causing harm even without explicit malicious instruction.

### Direct HAIAMM Alignment

**This OWASP risk has a direct HAIAMM counterpart: TM (Tool Misuse)**

| OWASP Agentic #6 Concern | HAIAMM TM Practice | Maturity Level |
|--------------------------|-------------------|----------------|
| Agents using tools beyond intended scope | Define tool usage boundaries | L1 |
| Chaining tools for unintended effects | Validate tool sequences | L2 |
| Exploiting tool parameters | Parameter validation and limits | L2 |
| Weaponizing legitimate tools | Behavioral anomaly detection | L3 |

### Control Framework

```
┌────────────────────────────────────────────────────────────────────────────┐
│  TOOL MISUSE PREVENTION (TM + SR + SA + ST)                                │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. TOOL DEFINITION (SR)                                                    │
│  ───────────────────────                                                    │
│  • Define permitted actions per tool                                       │
│  • Specify parameter constraints                                           │
│  • Document intended use cases                                             │
│  • List prohibited combinations                                            │
│                                                                             │
│  2. ACCESS CONTROL (SA)                                                     │
│  ──────────────────────                                                     │
│  • Tool-level permissions                                                  │
│  • Context-aware authorization                                             │
│  • Rate limiting per tool                                                  │
│  • Chain-of-tool limits                                                    │
│                                                                             │
│  3. RUNTIME VALIDATION (TM)                                                 │
│  ──────────────────────────                                                 │
│  • Validate parameters before execution                                    │
│  • Check tool sequences against policy                                     │
│  • Monitor output for anomalies                                            │
│  • Block known misuse patterns                                             │
│                                                                             │
│  4. TESTING (ST)                                                            │
│  ──────────────                                                             │
│  • Fuzz tool parameters                                                    │
│  • Test tool chain combinations                                            │
│  • Attempt privilege escalation via tools                                  │
│  • Verify rate limits                                                      │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 4.4 Detailed Crosswalk: Agentic #10 - Rogue Agents

### OWASP Description
Rogue Agents operate outside their intended boundaries, potentially acting autonomously or contrary to organizational controls. This includes unauthorized agent instantiation, lateral movement, and goal abandonment.

### Direct HAIAMM Alignment

**This OWASP risk has a direct HAIAMM counterpart: RA (Rogue Agents)**

```
┌────────────────────────────────────────────────────────────────────────────┐
│  AGENTIC #10: ROGUE AGENTS ←──→ HAIAMM RA: ROGUE AGENTS                    │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  THREAT SCENARIOS                      HAIAMM CONTROLS                     │
│  ────────────────                      ───────────────                     │
│                                                                             │
│  Unauthorized agent                    RA L1: Agent inventory             │
│  instantiation                         SA: Agent registration required    │
│                                        ML: Detect unknown agents          │
│                                                                             │
│  Agent lateral                         RA L2: Boundary enforcement        │
│  movement                              SA: Network segmentation           │
│                                        EH: Least privilege access         │
│                                                                             │
│  Agent goal                            RA L2: Behavioral monitoring       │
│  abandonment                           ML: Goal tracking                  │
│                                        IM: Incident response              │
│                                                                             │
│  Agent collusion                       RA L3: Multi-agent analysis        │
│  (multi-agent)                         ML: Cross-agent correlation        │
│                                        ST: Collusion testing              │
│                                                                             │
│  KILL SWITCH                                                               │
│  ───────────                                                               │
│  RA L1: Implement agent termination capability                            │
│  RA L2: Automated triggers for rogue behavior                             │
│  RA L3: Graceful degradation and containment                              │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

### Implementation Example

```typescript
// HAIAMM RA Implementation: Agent Registry and Kill Switch
interface RegisteredAgent {
  id: string;
  name: string;
  purpose: string;
  allowedScopes: string[];
  registeredAt: Date;
  lastHeartbeat: Date;
  status: 'active' | 'suspended' | 'terminated';
}

class AgentGovernance {
  private registry: Map<string, RegisteredAgent> = new Map();
  private readonly HEARTBEAT_TIMEOUT_MS = 30000;

  registerAgent(agent: RegisteredAgent): boolean {
    if (this.registry.has(agent.id)) {
      console.warn('Duplicate agent registration attempt', agent.id);
      return false;
    }
    this.registry.set(agent.id, {
      ...agent,
      status: 'active',
      registeredAt: new Date(),
      lastHeartbeat: new Date(),
    });
    return true;
  }

  heartbeat(agentId: string): void {
    const agent = this.registry.get(agentId);
    if (agent && agent.status === 'active') {
      agent.lastHeartbeat = new Date();
    }
  }

  detectRogueAgents(): RegisteredAgent[] {
    const rogues: RegisteredAgent[] = [];
    const now = Date.now();

    for (const agent of this.registry.values()) {
      if (agent.status === 'active') {
        const timeSinceHeartbeat = now - agent.lastHeartbeat.getTime();
        if (timeSinceHeartbeat > this.HEARTBEAT_TIMEOUT_MS) {
          rogues.push(agent);
        }
      }
    }
    return rogues;
  }

  killSwitch(agentId: string, reason: string): void {
    const agent = this.registry.get(agentId);
    if (agent) {
      agent.status = 'terminated';
      console.log('AGENT TERMINATED', {
        agentId,
        reason,
        timestamp: new Date().toISOString(),
      });
      // Trigger cleanup procedures
      this.notifyTermination(agent, reason);
    }
  }

  emergencyShutdown(reason: string): void {
    console.error('EMERGENCY SHUTDOWN INITIATED', { reason });
    for (const agent of this.registry.values()) {
      if (agent.status === 'active') {
        this.killSwitch(agent.id, `Emergency: ${reason}`);
      }
    }
  }

  private notifyTermination(agent: RegisteredAgent, reason: string): void {
    // Implement notification logic
  }
}
```

---

## 4.5 Summary: All Agentic Top 10 Mappings

### Agentic #2: Identity and Privilege Abuse
| Practice | Coverage |
|----------|----------|
| SR | Define identity requirements |
| SA | Design privilege boundaries |
| EH | Harden identity systems |
| IR | Review privilege code |
| ML | Monitor privilege usage |
| EA | Enforce least privilege |

### Agentic #3: Unexpected Code Execution
| Practice | Coverage |
|----------|----------|
| SR | Define code execution boundaries |
| SA | Sandbox execution environments |
| ST | Test for RCE vulnerabilities |
| IR | Review code execution paths |
| EH | Harden runtime environments |
| EA, TM | Limit execution scope |

### Agentic #4: Insecure InterAgent Communication
| Practice | Coverage |
|----------|----------|
| SA | Design secure agent protocols |
| IR | Review communication code |
| ST | Test agent-to-agent security |
| ML | Monitor inter-agent traffic |
| EH | Encrypt agent communications |

### Agentic #5: Human Agent Trust Exploitation
| Practice | Coverage |
|----------|----------|
| SR | Define trust boundaries |
| SA | Design verification mechanisms |
| EG | Train users on AI limitations |
| ML | Monitor for manipulation |
| ST | Test social engineering resistance |
| AGH | Prevent goal manipulation via trust |

### Agentic #7: Agentic Supply Chain
| Practice | Coverage |
|----------|----------|
| TA | Assess agent component risks |
| SR | Define acceptable components |
| EH | Secure agent dependencies |
| IR | Review third-party agents |
| ST | Test supply chain integrity |
| IM | Track agent vulnerabilities |

### Agentic #8: Memory and Context Poisoning
| Practice | Coverage |
|----------|----------|
| TA | Model poisoning scenarios |
| SA | Design memory protection |
| ST | Test memory manipulation |
| IR | Review context handling |
| ML | Monitor for poisoning |
| AGH | Prevent goal drift via memory |

### Agentic #9: Cascading Failures
| Practice | Coverage |
|----------|----------|
| SA | Design failure isolation |
| ML | Monitor for cascade indicators |
| IM | Incident response for cascades |
| EH | Configure circuit breakers |
| ST | Test failure scenarios |
| RA | Contain rogue behavior spread |

---

# 5. HAIAMM Practice Coverage Matrix

## 5.1 Practice → OWASP Mapping

This shows which OWASP risks each HAIAMM practice addresses:

```
┌────────────────────────────────────────────────────────────────────────────┐
│               HAIAMM PRACTICE → OWASP COVERAGE MATRIX                       │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  PRACTICE   LLM TOP 10 COVERAGE              AGENTIC TOP 10 COVERAGE       │
│  ────────   ─────────────────────            ────────────────────────      │
│                                                                             │
│  SM         (Governance framework)           (Governance framework)        │
│                                                                             │
│  PC         (Policy for all risks)           (Policy for all risks)        │
│                                                                             │
│  EG         LLM09 (Misinformation)           #5 (Trust Exploitation)       │
│                                                                             │
│  TA         LLM01, 03, 04, 08                #1, 7, 8                       │
│             (4 of 10)                        (3 of 10)                      │
│                                                                             │
│  SR         LLM01-10 (ALL)                   #1-10 (ALL)                    │
│             (10 of 10)                       (10 of 10)                     │
│                                                                             │
│  SA         LLM01-10 (ALL)                   #1-10 (ALL)                    │
│             (10 of 10)                       (10 of 10)                     │
│                                                                             │
│  DR         LLM02, 07, 08                    #4, 8                          │
│             (3 of 10)                        (2 of 10)                      │
│                                                                             │
│  IR         LLM01-05, 07, 08                 #2-8                           │
│             (7 of 10)                        (7 of 10)                      │
│                                                                             │
│  ST         LLM01-10 (ALL)                   #1-10 (ALL)                    │
│             (10 of 10)                       (10 of 10)                     │
│                                                                             │
│  EH         LLM02, 03, 07, 10                #2-4, 7, 9, 10                 │
│             (4 of 10)                        (6 of 10)                      │
│                                                                             │
│  IM         LLM03, 04, 10                    #7, 9, 10                      │
│             (3 of 10)                        (3 of 10)                      │
│                                                                             │
│  ML         LLM01-06, 08, 10                 #1-6, 8-10                     │
│             (8 of 10)                        (9 of 10)                      │
│                                                                             │
│  EA         LLM06, 10                        #2, 3, 6                       │
│             (2 of 10)                        (3 of 10)                      │
│                                                                             │
│  AGH        LLM01, 04                        #1, 5, 8                       │
│             (2 of 10)                        (3 of 10)                      │
│                                                                             │
│  TM         LLM05                            #3, 6                          │
│             (1 of 10)                        (2 of 10)                      │
│                                                                             │
│  RA         -                                #9, 10                         │
│             (0 of 10)                        (2 of 10)                      │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

## 5.2 Key Insights

**Most Comprehensive Practices:**
1. **SR (Security Requirements)** - Touches all OWASP risks
2. **SA (Secure Architecture)** - Touches all OWASP risks
3. **ST (Security Testing)** - Touches all OWASP risks
4. **ML (Monitoring & Logging)** - Touches 17 of 20 OWASP risks

**HAI-Specific Practice Alignment:**
- **EA** aligns directly with LLM06 (Excessive Agency) and Agentic #2, #3, #6
- **AGH** aligns directly with Agentic #1 (Agent Goal Hijack) and LLM01, LLM04
- **TM** aligns directly with Agentic #6 (Tool Misuse) and LLM05
- **RA** aligns directly with Agentic #9, #10 (Cascading Failures, Rogue Agents)

---

# 6. Gap Analysis

## 6.1 OWASP Risks Not Fully Addressed by Single Practice

Some OWASP risks require multiple HAIAMM practices working together:

| OWASP Risk | Required Practice Combination | Notes |
|------------|------------------------------|-------|
| LLM01 (Prompt Injection) | TA + SR + SA + ST + ML + AGH | Requires defense in depth |
| LLM03 (Supply Chain) | TA + SR + EH + IR + ST + IM | Spans multiple domains |
| Agentic #4 (InterAgent) | SA + IR + ST + ML + EH | New risk, not directly covered by single HAI practice |
| Agentic #9 (Cascading) | SA + ML + IM + EH + RA | Requires system-wide view |

## 6.2 Potential HAIAMM Enhancements

Based on OWASP coverage analysis, consider these potential additions:

```
┌────────────────────────────────────────────────────────────────────────────┐
│              POTENTIAL HAIAMM ENHANCEMENTS                                  │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. INTER-AGENT COMMUNICATION (IAC)                                         │
│  ──────────────────────────────────                                         │
│  Gap: Agentic #4 lacks direct HAI practice                                 │
│  Proposal: New HAI practice for multi-agent systems                        │
│  Focus: Protocol security, agent authentication, message integrity         │
│                                                                             │
│  2. MEMORY INTEGRITY (MI)                                                   │
│  ────────────────────────                                                   │
│  Gap: Agentic #8 (Memory Poisoning) addressed indirectly                   │
│  Proposal: Explicit practice for context/memory security                   │
│  Focus: Context validation, memory isolation, poisoning detection          │
│                                                                             │
│  3. CASCADE PREVENTION (CP)                                                 │
│  ──────────────────────────                                                 │
│  Gap: Agentic #9 spread across multiple practices                          │
│  Proposal: Dedicated practice for failure isolation                        │
│  Focus: Circuit breakers, blast radius, graceful degradation               │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

---

# 7. Implementation Guidance

## 7.1 Priority Order for OWASP Coverage

Based on risk severity and HAIAMM coverage, implement practices in this order:

```
┌────────────────────────────────────────────────────────────────────────────┐
│              IMPLEMENTATION PRIORITY                                        │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  PHASE 1: CRITICAL (Weeks 1-4)                                              │
│  ─────────────────────────────                                              │
│  Addresses: LLM01, LLM06, Agentic #1, #10                                  │
│                                                                             │
│  □ SR - Define security requirements and boundaries                        │
│  □ EA - Implement least agency principle                                   │
│  □ AGH - Goal immutability controls                                        │
│  □ RA - Agent registry and kill switch                                     │
│                                                                             │
│  PHASE 2: HIGH (Weeks 5-8)                                                  │
│  ─────────────────────────                                                  │
│  Addresses: LLM02, LLM05, Agentic #2, #3, #6                               │
│                                                                             │
│  □ SA - Secure architecture patterns                                       │
│  □ IR - Code review for AI-specific vulnerabilities                       │
│  □ TM - Tool usage monitoring and control                                  │
│  □ ST - Security testing automation                                        │
│                                                                             │
│  PHASE 3: MEDIUM (Weeks 9-12)                                               │
│  ────────────────────────────                                               │
│  Addresses: LLM03, LLM04, LLM07, LLM08, Agentic #4, #7, #8                 │
│                                                                             │
│  □ TA - Comprehensive threat modeling                                      │
│  □ ML - Monitoring and anomaly detection                                   │
│  □ EH - Environment hardening                                              │
│  □ IM - Vulnerability management                                           │
│                                                                             │
│  PHASE 4: STANDARD (Weeks 13+)                                              │
│  ────────────────────────────                                               │
│  Addresses: LLM09, LLM10, Agentic #5, #9                                   │
│                                                                             │
│  □ EG - Security training program                                          │
│  □ SM - Metrics and strategy                                               │
│  □ PC - Policy and compliance                                              │
│  □ DR - Design reviews                                                     │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

## 7.2 Minimum Viable Coverage

For organizations starting their HAI security journey, achieve minimum viable OWASP coverage with these Level 1 activities:

| Practice | L1 Activity | OWASP Coverage |
|----------|-------------|----------------|
| SR | Document CAN/CANNOT/MUST | All risks |
| SA | Implement basic sandboxing | LLM01, 05, 06, Agentic #1-3, 6 |
| EA | Restrict permissions | LLM06, Agentic #2, 3, 6 |
| AGH | Goal verification | LLM01, Agentic #1, 5, 8 |
| ST | Enable SAST/secrets scanning | LLM02, 03, 07 |
| ML | Basic action logging | All risks (detection) |

---

# 8. Assessment Mapping

## 8.1 OWASP-Aligned Assessment Questions

Use these questions to assess OWASP coverage through HAIAMM:

### LLM01 (Prompt Injection) Assessment

| Practice | L1 Question | L2 Question |
|----------|-------------|-------------|
| TA | Is prompt injection in your threat model? | Do you have documented injection scenarios? |
| SR | Are input validation requirements defined? | Are pattern-based validations specified? |
| SA | Is input sanitization implemented? | Is prompt/data separation enforced? |
| ST | Do you test for prompt injection? | Is injection testing in CI/CD? |
| AGH | Are goal immutability controls present? | Is goal drift monitored? |

### LLM06 / Agentic #2 (Excessive Agency) Assessment

| Practice | L1 Question | L2 Question |
|----------|-------------|-------------|
| SR | Are minimal permissions documented? | Is least privilege formally specified? |
| SA | Are permission boundaries implemented? | Is human-in-the-loop for sensitive ops? |
| EA | Are tool permissions scoped? | Is permission enforcement automated? |
| ML | Are agent actions logged? | Is permission anomaly detection active? |

### Agentic #10 (Rogue Agents) Assessment

| Practice | L1 Question | L2 Question |
|----------|-------------|-------------|
| SA | Is agent registration required? | Are agent boundaries enforced? |
| ML | Can you detect unknown agents? | Is behavioral monitoring active? |
| IM | Do you have agent incident response? | Is automated response configured? |
| RA | Is a kill switch implemented? | Are automated triggers configured? |

## 8.2 Audit Evidence Mapping

| OWASP Risk | Evidence Required | HAIAMM Source |
|------------|-------------------|---------------|
| LLM01 | Threat model, validation rules, test results | TA, SR, ST |
| LLM02 | Data classification, filtering rules, test results | SR, SA, ST |
| LLM06 | Permission specs, enforcement logs, audit trails | SR, SA, EA, ML |
| Agentic #1 | Goal definitions, integrity checks, monitoring | SR, AGH, ML |
| Agentic #10 | Agent registry, kill switch tests, incident response | SA, RA, IM |

---

# 9. VerifHAI Integration

## 9.1 Using VerifHAI for OWASP Compliance

```
┌────────────────────────────────────────────────────────────────────────────┐
│              VERIFHAI COMMANDS FOR OWASP COMPLIANCE                         │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ASSESSMENT                                                                 │
│  ──────────                                                                 │
│                                                                             │
│  /verifhai assess                                                           │
│  └── Quick check of all practices                                          │
│  └── Shows coverage of OWASP risks                                         │
│  └── Identifies highest-priority gaps                                      │
│                                                                             │
│  /verifhai measure                                                          │
│  └── Full assessment with scoring                                          │
│  └── Generates OWASP coverage report                                       │
│  └── Creates improvement roadmap                                           │
│                                                                             │
│  PRACTICE BUILDING                                                          │
│  ─────────────────                                                          │
│                                                                             │
│  /verifhai practice sr                                                      │
│  └── Build Security Requirements                                           │
│  └── Addresses: ALL OWASP risks (foundation)                               │
│                                                                             │
│  /verifhai practice ta                                                      │
│  └── Build Threat Assessment                                               │
│  └── Addresses: LLM01, 03, 04, 08; Agentic #1, 7, 8                        │
│                                                                             │
│  /verifhai practice sa                                                      │
│  └── Build Secure Architecture                                             │
│  └── Addresses: ALL OWASP risks (design)                                   │
│                                                                             │
│  REVIEW                                                                     │
│  ──────                                                                     │
│                                                                             │
│  /verifhai review                                                           │
│  └── Review code for OWASP vulnerabilities                                 │
│  └── Checks for LLM Top 10 patterns                                        │
│  └── Checks for Agentic Top 10 patterns                                    │
│  └── HAI-specific risk detection (EA, AGH, TM, RA)                        │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

## 9.2 Example: OWASP-Focused Review Session

```
User: /verifhai review --owasp

VerifHAI: Analyzing code for OWASP AI security risks...

=== OWASP LLM Top 10 Findings ===

LLM01 (Prompt Injection):
  ⚠ HIGH: No input sanitization in src/chat/handler.ts:45
  ⚠ MEDIUM: User input directly in prompt template at src/prompts/index.ts:23

LLM02 (Sensitive Information Disclosure):
  ⚠ HIGH: API key logged at src/services/api.ts:78
  ✓ OK: Output filtering present in src/response/filter.ts

LLM06 (Excessive Agency):
  ⚠ HIGH: AI has unrestricted file system access
  ⚠ MEDIUM: No human approval for database writes

=== OWASP Agentic Top 10 Findings ===

Agentic #1 (Agent Goal Hijack):
  ⚠ MEDIUM: No goal immutability mechanism detected

Agentic #6 (Tool Misuse):
  ⚠ HIGH: Tool parameter validation missing
  ⚠ MEDIUM: No rate limiting on tool calls

Agentic #10 (Rogue Agents):
  ⚠ CRITICAL: No kill switch implemented
  ✓ OK: Agent registration present

=== Summary ===
Critical: 1
High: 4
Medium: 4
OK: 2

Highest Priority: Implement kill switch (Agentic #10 / HAIAMM RA)

Would you like help implementing fixes?
```

---

# 10. Resources

## 10.1 OWASP Resources

| Resource | URL |
|----------|-----|
| OWASP LLM Top 10 2025 | https://owasp.org/www-project-top-10-for-large-language-model-applications/ |
| OWASP LLM Top 10 PDF | https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf |
| OWASP GenAI Security Project | https://genai.owasp.org/ |
| OWASP Agentic AI Top 10 | https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ |
| Agentic AI Threats & Mitigations | https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/ |

## 10.2 HAIAMM Resources

| Resource | Location |
|----------|----------|
| HAIAMM Framework | verifhai-public/docs/haiamm.md |
| Vibe Coding Security Guide | verifhai-public/docs/security-patterns/Vibe-Coding-Security-Guide.md |
| HAI Security Architecture Patterns | verifhai-public/docs/security-patterns/HAI-Security-Architecture-Patterns.md |
| VerifHAI Claude Skill | claude-skill/SKILL.md |

## 10.3 Related Standards

| Standard | Relationship to HAIAMM |
|----------|------------------------|
| NIST AI RMF | Governance layer above HAIAMM |
| ISO/IEC 42001 | Certifiable standard, HAIAMM provides implementation |
| MITRE ATLAS | Attack knowledge base, feeds HAIAMM TA |
| MAESTRO | Agentic threat modeling, complements HAIAMM TA |
| SAFE-MCP | Protocol security, complements HAIAMM SA |

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | January 2026 | Initial release with LLM Top 10 2025 and Agentic Top 10 2026 |

---

**Use HAIAMM for maturity, OWASP for specifics.**

*This crosswalk is part of the VerifHAI project. Contributions welcome.*

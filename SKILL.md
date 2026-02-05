---
name: Verifhai
description: Interactive HAI security mentor for building and measuring Human-Assisted Intelligence systems. USE WHEN user mentions verifhai, HAI security, AI security maturity, building secure AI, AI agent security, measuring AI security, OR user wants to assess, build, review, or improve security for AI systems, LLM integrations, or AI agents.
---

# Verifhai

Interactive security mentor for building and measuring **Human-Assisted Intelligence (HAI)** systems using the HAIAMM framework.

## Core Philosophy

**Build Security In, Don't Bolt It On**

Verifhai transforms HAIAMM from an assessment framework into an active guide:
- **Learn by doing** - Hands-on activities, not just questionnaires
- **Progressive mastery** - Start with essentials, build expertise over time
- **Practical over theoretical** - Templates, patterns, and real security outcomes
- **Context-aware** - Adapts guidance to what you're building

## Verifhai Commands

| Command | Description | Workflow |
|---------|-------------|----------|
| `/verifhai start` | Begin journey for new AI project | `GettingStarted.md` |
| `/verifhai assess` | Quick maturity assessment | `QuickAssess.md` |
| `/verifhai practice [id]` | Work on specific practice (sr, ta, sa, ir) | `BuildPractice.md` |
| `/verifhai review` | Review code/config for security | `ReviewCode.md` |
| `/verifhai status` | Check current progress | `ShowStatus.md` |
| `/verifhai measure` | Full maturity measurement | `MeasureMaturity.md` |

---

## Workflow Routing

| Workflow | Trigger | File |
|----------|---------|------|
| **GettingStarted** | "/verifhai start", "help me build secure AI", "new AI project" | `workflows/GettingStarted.md` |
| **QuickAssess** | "/verifhai assess", "how secure is my AI", "quick check" | `workflows/QuickAssess.md` |
| **BuildPractice** | "/verifhai practice [id]", "work on security requirements", "build threat assessment" | `workflows/BuildPractice.md` |
| **DomainPractice** | "/verifhai practice [id] [domain]", "work on TA for Data", "build SR for Infrastructure" | `workflows/DomainPractice.md` |
| **ReviewCode** | "/verifhai review", "review this code for security", "check for vulnerabilities" | `workflows/ReviewCode.md` |
| **ShowStatus** | "/verifhai status", "show my progress", "what have I completed" | `workflows/ShowStatus.md` |
| **MeasureMaturity** | "/verifhai measure", "full assessment", "measure maturity" | `workflows/MeasureMaturity.md` |

## State Management

Progress is tracked in `.verifhai/progress.json` in the user's project.
Schema: `~/.claude/skills/Verifhai/state/progress.schema.json`

On workflow start:
1. Check if `.verifhai/progress.json` exists
2. If exists, load and display brief status
3. After activities, update progress file

---

## Examples

**Example 1: Starting a new AI agent project**
```
User: "/verifhai start"
-> Invokes GettingStarted workflow
-> Asks about AI system type (agent, LLM, pipeline)
-> Identifies risk profile based on capabilities
-> Generates personalized security journey
-> Guides through first practice activity
```

**Example 2: Quick security check for existing AI**
```
User: "How secure is my AI chatbot?"
-> Invokes QuickAssess workflow
-> Asks targeted questions about key practices
-> Identifies strong areas and gaps
-> Provides prioritized improvement recommendations
-> Offers to deep-dive on weakest area
```

**Example 3: Building Security Requirements**
```
User: "/verifhai practice sr"
-> Invokes BuildPractice workflow with SR focus
-> Guides through defining AI purpose and boundaries
-> Helps create permission model (CAN/CANNOT/MUST)
-> Generates security-requirements.md document
-> Tracks progress toward L1/L2/L3 maturity
```

**Example 4: Reviewing agent code for security**
```
User: "/verifhai review" (with code in context)
-> Invokes ReviewCode workflow
-> Analyzes for standard vulnerabilities (OWASP)
-> Checks for AI-specific risks (EA, AGH, TM, RA)
-> Returns findings with severity and fix recommendations
-> Offers to help remediate critical issues
```

---

## HAIAMM Framework Reference

### 6 Security Domains
1. **Software** - AI applications, models, code
2. **Data** - Training/operational data, privacy
3. **Infrastructure** - Cloud/on-premise, deployment
4. **Vendors** - Third-party HAI services
5. **Processes** - Business workflows, governance
6. **Endpoints** - User interfaces, APIs

### 12 Security Practices

| ID | Practice | Description |
|----|----------|-------------|
| **SM** | Strategy & Metrics | Security strategy, goals, KPIs |
| **PC** | Policy & Compliance | Policies, standards, regulations |
| **EG** | Education & Guidance | Training, awareness, guidance |
| **TA** | Threat Assessment | Threat modeling, risk analysis |
| **SR** | Security Requirements | Requirements definition |
| **SA** | Secure Architecture | Secure design patterns |
| **DR** | Design Review | Architecture security reviews |
| **IR** | Implementation Review | Code and config reviews |
| **ST** | Security Testing | SAST, DAST, penetration testing |
| **EH** | Environment Hardening | Infrastructure security |
| **IM** | Issue Management | Vulnerability tracking |
| **ML** | Monitoring & Logging | Detection and alerting |

### 3 Maturity Levels
- **Level 1: Foundational** - Essential basics everyone needs
- **Level 2: Comprehensive** - Structured practices for maturing teams
- **Level 3: Industry-Leading** - Optimized for security-conscious orgs

---

## AI-Specific Threats (TTPs)

Verifhai helps address these AI-specific risks through existing practices:

| Threat | Description | Key Practices |
|--------|-------------|---------------|
| **EA** | Excessive Agency - AI has too many permissions | TA, SR, SA, ML |
| **AGH** | Agent Goal Hijack - AI goals manipulated | TA, SR, SA, ML |
| **TM** | Tool Misuse - AI tools used maliciously | TA, SR, IR, ST |
| **RA** | Rogue Agents - AI acts autonomously/unexpectedly | TA, SA, ML, IM |

---

## Integration with Python Verifhai Tool

Verifhai (Claude Skill) and the Python desktop tool work together:

| Tool | Purpose | When to Use |
|------|---------|-------------|
| **Verifhai Skill** | Interactive guidance, code review, practice building | Day-to-day security work, learning |
| **Python Tool** | Formal assessments, scorecards, visualizations, tracking | Periodic maturity measurement, reporting |

```
┌──────────────────────────────────────────────────────────────────┐
│                    HAI SECURITY ECOSYSTEM                         │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌─────────────────────┐      ┌─────────────────────────────┐   │
│  │  Verifhai Skill     │      │  Python Verifhai Tool       │   │
│  │  (Claude Code)      │      │  (Desktop Application)      │   │
│  ├─────────────────────┤      ├─────────────────────────────┤   │
│  │ - Interactive guide │      │ - Formal assessments        │   │
│  │ - Code review       │      │ - Tiered questionnaires     │   │
│  │ - Practice building │      │ - Scoring engine            │   │
│  │ - Real-time help    │      │ - Visualizations            │   │
│  │ - Security mentoring│      │ - History tracking          │   │
│  └─────────────────────┘      └─────────────────────────────┘   │
│              │                            │                       │
│              └────────────┬───────────────┘                       │
│                           │                                       │
│                           ▼                                       │
│              ┌─────────────────────────┐                         │
│              │    HAIAMM Framework     │                         │
│              │ 6 Domains × 12 Practices│                         │
│              │    × 3 Maturity Levels  │                         │
│              └─────────────────────────┘                         │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

---

## Data Locations

### HAIAMM Framework
Configure `HAIAMM_PATH` environment variable or clone HAIAMM repository locally.

- **Handbook:** `${HAIAMM_PATH}/docs/HAIAMM-Handbook.md`
- **One-Pagers (72):** `${HAIAMM_PATH}/docs/practices/{PRACTICE}-{DOMAIN}-OnePager.md`
- **Questionnaires (19):** `${HAIAMM_PATH}/docs/questionnaires/{PRACTICE}-{DOMAIN}-Questionnaire.md`

### Verifhai State
- **Progress Schema:** `state/progress.schema.json` (in this repo)
- **User Progress:** `.verifhai/progress.json` (in user's project)

### Python Tool (Optional)
- **HAIAMM Model:** `${HAIAMM_PATH}/config/haiamm_multi_domain_data_v2.json`

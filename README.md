# Verifhai

**Build Security In, Don't Bolt It On**

Verifhai is a security framework and toolset for building secure **Human-Assisted Intelligence (HAI)** systems. It provides structured guidance, assessments, and templates using the **HAIAMM** (Human-Assisted Intelligence Application Maturity Model) framework.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         VERIFHAI ECOSYSTEM                                    │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│   ┌─────────────────────────────┐    ┌─────────────────────────────────┐    │
│   │   Claude Skill (/verifhai)  │    │   Python CLI (verifhai)         │    │
│   ├─────────────────────────────┤    ├─────────────────────────────────┤    │
│   │ Interactive AI mentor       │    │ Formal assessments              │    │
│   │ Real-time code review       │    │ Maturity scoring engine         │    │
│   │ Guided practice building    │    │ Progress tracking               │    │
│   │ Conversational security     │    │ Export & reporting              │    │
│   └─────────────────────────────┘    └─────────────────────────────────┘    │
│                    │                              │                          │
│                    └──────────────┬───────────────┘                          │
│                                   │                                          │
│                                   ▼                                          │
│                    ┌─────────────────────────────┐                           │
│                    │      HAIAMM Framework       │                           │
│                    │  6 Domains × 12 Practices   │                           │
│                    │     × 3 Maturity Levels     │                           │
│                    └─────────────────────────────┘                           │
│                                                                               │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Table of Contents

- [Why Verifhai?](#why-verifhai)
- [Two Tools, One Framework](#two-tools-one-framework)
- [Quick Start](#quick-start)
- [Claude Skill Version](#claude-skill-version)
- [Python CLI Version](#python-cli-version)
- [HAIAMM Framework](#haiamm-framework)
- [Verifhai as Your PAI for HAI Security](#verifhai-as-your-pai-for-hai-security)
- [Contributing](#contributing)
- [License](#license)

---

## Why Verifhai?

AI systems have **unique security challenges** that traditional security tools don't address:

| Threat | Description | Impact |
|--------|-------------|--------|
| **Excessive Agency (EA)** | AI has more permissions than needed | Unintended actions, data access |
| **Agent Goal Hijacking (AGH)** | AI goals manipulated by attackers | Malicious behavior via prompts |
| **Tool Misuse (TM)** | AI tools abused for unintended purposes | Privilege escalation, data exfil |
| **Rogue Agents (RA)** | AI acts unexpectedly or autonomously | Unpredictable, harmful actions |

**Verifhai helps you:**
- Identify risks before you build (Threat Assessment)
- Define clear boundaries (Security Requirements)
- Design containment from the start (Secure Architecture)
- Verify your implementation (Code Review, Testing)
- Monitor behavior in production (Logging, Alerting)

---

## Two Tools, One Framework

Verifhai offers **two complementary tools** that work with the same HAIAMM framework:

| Tool | Best For | Use When |
|------|----------|----------|
| **Claude Skill** | Interactive guidance, learning, day-to-day work | Building features, reviewing code, learning security |
| **Python CLI** | Formal assessments, reporting, tracking | Measuring maturity, generating reports, audits |

**Use both together** for comprehensive coverage:
1. Use the Claude Skill during development for real-time guidance
2. Use the Python CLI periodically to measure and track progress

---

## Quick Start

### Option 1: Claude Skill (Recommended for Learning)

```bash
# Copy the skill to your Claude Code configuration
cp -r claude-skill ~/.claude/commands/verifhai

# Start using in any Claude Code session
/verifhai start
```

### Option 2: Python CLI (For Assessments)

```bash
# Install from source
pip install -e .

# Run your first assessment
verifhai assess --quick
```

---

## Claude Skill Version

The Claude Skill turns Verifhai into an **interactive AI security mentor** that works within Claude Code sessions. Think of it as your **PAI (Personal AI Infrastructure) for building secure HAI systems**.

### Installation

#### Step 1: Locate Your Claude Code Commands Directory

```bash
# Default location on macOS/Linux
~/.claude/commands/

# Create if it doesn't exist
mkdir -p ~/.claude/commands/
```

#### Step 2: Copy the Skill

```bash
# From the verifhai-public repository
cp -r claude-skill ~/.claude/commands/verifhai
```

#### Step 3: Verify Installation

```bash
# Check the structure
ls -la ~/.claude/commands/verifhai/
```

You should see:
```
verifhai/
├── SKILL.md           # Skill definition (required)
├── workflows/         # Workflow definitions
│   ├── GettingStarted.md
│   ├── QuickAssess.md
│   ├── BuildPractice.md
│   ├── ReviewCode.md
│   ├── MeasureMaturity.md
│   └── ShowStatus.md
└── templates/         # Security document templates
    ├── SecurityRequirements.md
    ├── ThreatModel.md
    └── ReviewChecklist.md
```

### File Structure Breakdown

#### `SKILL.md` - The Skill Definition

The heart of the Claude Skill. This file:
- Defines the skill name and description
- Maps commands to workflows
- Provides the HAIAMM framework reference
- Enables Claude to understand when to invoke Verifhai

```markdown
---
name: Verifhai
description: Interactive HAI security mentor...
---
```

**Triggers:** `/verifhai`, "help me build secure AI", "AI security", etc.

#### `workflows/` - Interactive Guidance

Each workflow is a markdown file that defines a conversational interaction:

| File | Command | Purpose |
|------|---------|---------|
| `GettingStarted.md` | `/verifhai start` | Onboard new AI projects, identify risk profile, create security journey |
| `QuickAssess.md` | `/verifhai assess` | Rapid 12-question assessment across all practices |
| `BuildPractice.md` | `/verifhai practice [id]` | Deep-dive on specific practices (SR, TA, SA, IR, etc.) |
| `ReviewCode.md` | `/verifhai review` | Security code review for AI-specific and traditional vulnerabilities |
| `MeasureMaturity.md` | `/verifhai measure` | Full tiered assessment with scoring |
| `ShowStatus.md` | `/verifhai status` | View progress, completed practices, next steps |

#### `templates/` - Security Document Templates

Ready-to-use templates for security artifacts:

| File | Purpose |
|------|---------|
| `SecurityRequirements.md` | Define CAN/CANNOT/MUST permission boundaries |
| `ThreatModel.md` | Document threats, attack vectors, mitigations |
| `ReviewChecklist.md` | Security review checklist for code reviews |

### Usage Examples

**Start a new AI project securely:**
```
/verifhai start

> Welcome to Verifhai! What type of AI system are you building?
> 1. AI Agent
> 2. LLM Integration
> 3. AI Pipeline
> ...
```

**Quick security check:**
```
/verifhai assess

> Let me ask you about each security practice...
> Security Requirements: Do you have documented permission boundaries? (Y/N)
> ...
> Your maturity score: 2.1/3.0
```

**Work on specific practice:**
```
/verifhai practice sr

> Let's build Security Requirements for your AI system.
> Step 1: Define your AI's purpose...
```

**Review code for security:**
```
/verifhai review

> I'll analyze your code for:
> - OWASP Top 10 vulnerabilities
> - AI-specific threats (EA, AGH, TM, RA)
> - Permission boundary violations
```

---

## Python CLI Version

The Python CLI provides **formal assessments, scoring, and tracking** for measuring your HAI security maturity over time.

### Requirements

- Python 3.10 or higher
- pip or pipx

### Installation

#### Option 1: Install from Source (Development)

```bash
# Clone the repository
git clone https://github.com/verifhai/verifhai-public.git
cd verifhai-public

# Install in development mode
pip install -e .

# Verify installation
verifhai version
```

#### Option 2: Install with Optional Dependencies

```bash
# With TUI support (terminal user interface)
pip install -e ".[tui]"

# With development tools
pip install -e ".[dev]"

# Everything
pip install -e ".[all]"
```

### CLI Commands

```bash
# Start interactive journey
verifhai start

# Quick assessment (5 questions)
verifhai assess --quick

# Assess specific practice
verifhai assess sr

# Full maturity measurement
verifhai measure

# Measure specific domain
verifhai measure --domain software

# Work on a practice
verifhai practice sr
verifhai practice ta --level 2

# Security code review
verifhai review path/to/code
verifhai review --format json

# Check progress
verifhai status

# Show version
verifhai version
```

### Output Formats

```bash
# Export assessment results
verifhai measure --output results.json
verifhai measure --format html --output report.html
verifhai measure --format markdown --output report.md
```

### Dependencies

| Package | Purpose |
|---------|---------|
| `typer` | CLI framework |
| `rich` | Terminal formatting, tables, progress bars |
| `pydantic` | Data validation and schemas |
| `pyyaml` | Configuration parsing |
| `textual` | TUI framework (optional) |

---

## HAIAMM Framework

The **Human-Assisted Intelligence Application Maturity Model** organizes security across three dimensions:

### 12 Security Practices

Organized into 4 categories:

| Category | ID | Practice | Description |
|----------|-----|----------|-------------|
| **Governance** | SM | Strategy & Metrics | Security strategy, goals, KPIs |
| | PC | Policy & Compliance | Policies, standards, regulations |
| | EG | Education & Guidance | Training, awareness, guidance |
| **Design** | TA | Threat Assessment | Threat modeling, risk analysis |
| | SR | Security Requirements | Requirements definition |
| | SA | Secure Architecture | Secure design patterns |
| **Verification** | DR | Design Review | Architecture security reviews |
| | IR | Implementation Review | Code and config reviews |
| | ST | Security Testing | SAST, DAST, penetration testing |
| **Operations** | EH | Environment Hardening | Infrastructure security |
| | IM | Issue Management | Vulnerability tracking |
| | ML | Monitoring & Logging | Detection and alerting |

### 6 Security Domains

Each practice applies across all domains:

| Domain | Focus Areas |
|--------|-------------|
| **Software** | AI applications, models, code, dependencies |
| **Data** | Training data, operational data, privacy, PII |
| **Infrastructure** | Cloud, on-premise, containers, deployment |
| **Vendors** | Third-party AI services, APIs, supply chain |
| **Processes** | Business workflows, governance, procedures |
| **Endpoints** | User interfaces, APIs, integrations |

### 3 Maturity Levels

| Level | Name | Description |
|-------|------|-------------|
| **L1** | Foundational | Essential basics everyone needs |
| **L2** | Comprehensive | Structured practices for maturing teams |
| **L3** | Industry-Leading | Optimized for security-conscious organizations |

---

## Verifhai as Your PAI for HAI Security

### What is PAI?

**PAI (Personal AI Infrastructure)** is a philosophy of building AI systems that work *with* you, not just *for* you. Your PAI:

- **Knows your context** - Understands your projects, preferences, patterns
- **Guides proactively** - Suggests improvements before problems occur
- **Learns with you** - Builds on previous interactions and decisions
- **Stays consistent** - Maintains your security posture across projects

### Verifhai as Your Security PAI

Verifhai implements the PAI philosophy for HAI security:

```
┌────────────────────────────────────────────────────────────────────────────┐
│                    VERIFHAI AS YOUR SECURITY PAI                            │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐                                                        │
│  │   Your AI       │                                                        │
│  │   Project       │                                                        │
│  └────────┬────────┘                                                        │
│           │                                                                 │
│           ▼                                                                 │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                         VERIFHAI                                    │    │
│  ├────────────────────────────────────────────────────────────────────┤    │
│  │                                                                     │    │
│  │  1. UNDERSTAND          2. GUIDE            3. VERIFY              │    │
│  │  ┌──────────────┐      ┌──────────────┐    ┌──────────────┐        │    │
│  │  │ What are you │      │ Here's your  │    │ Let me       │        │    │
│  │  │ building?    │ ──▶  │ security     │ ──▶│ review that  │        │    │
│  │  │              │      │ journey      │    │ for you      │        │    │
│  │  └──────────────┘      └──────────────┘    └──────────────┘        │    │
│  │         │                     │                    │                │    │
│  │         ▼                     ▼                    ▼                │    │
│  │  ┌──────────────┐      ┌──────────────┐    ┌──────────────┐        │    │
│  │  │ Risk Profile │      │ Practices    │    │ Findings &   │        │    │
│  │  │ AI Type      │      │ Templates    │    │ Fixes        │        │    │
│  │  │ Capabilities │      │ Checklists   │    │ Tracking     │        │    │
│  │  └──────────────┘      └──────────────┘    └──────────────┘        │    │
│  │                                                                     │    │
│  │  4. MEASURE             5. TRACK            6. IMPROVE             │    │
│  │  ┌──────────────┐      ┌──────────────┐    ┌──────────────┐        │    │
│  │  │ Maturity     │      │ Progress     │    │ Next steps   │        │    │
│  │  │ Scoring      │ ──▶  │ Over Time    │ ──▶│ Recommended  │        │    │
│  │  │              │      │              │    │ Actions      │        │    │
│  │  └──────────────┘      └──────────────┘    └──────────────┘        │    │
│  │                                                                     │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

### The PAI Workflow for HAI Development

**Day 1: Starting a New AI Agent**
```
/verifhai start

Verifhai identifies:
- AI type: Autonomous Agent
- Risk: High (tool access, code execution)
- Priority practices: SR, TA, SA

Generates: Personalized security journey
```

**Day 5: Adding a New Tool**
```
"I'm adding a file write tool to my agent"

Verifhai responds:
- Check against permission boundaries (SR)
- Update threat model (TA)
- Review implementation (IR)

Offers: Quick code review for the new tool
```

**Day 14: Pre-Launch Check**
```
/verifhai assess

Verifhai evaluates:
- All 12 practices
- Current maturity: 1.8/3.0

Identifies gaps:
- Missing: Security testing (ST)
- Weak: Monitoring (ML)

Recommends: Address ST before launch
```

**Ongoing: Continuous Security**
```
/verifhai status

Shows:
- Completed practices
- In-progress work
- Recommended next actions
- Maturity trend over time
```

### Why PAI Matters for HAI

Traditional security is **reactive** - you build, then audit, then fix.

PAI-driven security is **proactive** - security guidance is woven into your development workflow:

| Traditional | PAI Approach |
|-------------|--------------|
| Security audit after build | Security guidance during build |
| Generic checklists | Context-aware recommendations |
| One-time assessment | Continuous improvement tracking |
| Separate security team | Security integrated in your workflow |
| Documentation burden | Automated artifact generation |

---

## Project Structure

```
verifhai-public/
├── README.md                    # This file
├── pyproject.toml               # Python package configuration
├── src/verifhai/                # Python CLI source
│   ├── __init__.py              # Package metadata
│   ├── cli.py                   # Main CLI entry point
│   ├── commands/                # CLI subcommands
│   │   ├── assess.py            # Quick assessment
│   │   ├── measure.py           # Full measurement
│   │   ├── practice.py          # Practice activities
│   │   ├── review.py            # Code review
│   │   └── status.py            # Progress tracking
│   ├── core/                    # Framework definitions
│   │   └── haiamm.py            # HAIAMM model
│   └── tui/                     # Terminal UI (future)
├── claude-skill/                # Claude Skill version
│   ├── SKILL.md                 # Skill definition
│   ├── workflows/               # Interactive workflows
│   └── templates/               # Security templates
├── docs/                        # Documentation (future)
└── tests/                       # Test suite (future)
```

---

## Current Status

**Version:** 0.1.0 (Alpha)

| Component | Status |
|-----------|--------|
| HAIAMM Framework | Complete |
| Claude Skill | Complete (6 workflows) |
| Python CLI Structure | Complete |
| Interactive Logic | In Progress |
| Code Review Engine | In Progress |
| TUI | Planned |

---

## Contributing

Contributions are welcome! Areas where help is needed:

1. **Interactive assessment logic** - Implement the questionnaire flows
2. **Code review engine** - AI-specific vulnerability detection
3. **Additional templates** - More security document templates
4. **Testing** - Unit and integration tests
5. **Documentation** - Tutorials and guides

---

## License

GNU General Public License v3.0 (GPL-3.0)

See [LICENSE](LICENSE) for details.

---

## Links

- [Repository](https://github.com/verifhai/verifhai-public)
- [Issues](https://github.com/verifhai/verifhai-public/issues)
- [HAIAMM Framework](docs/haiamm.md) (coming soon)

---

**Build secure HAI systems from day one with Verifhai.**

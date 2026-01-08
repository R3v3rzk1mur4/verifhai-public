# ShowStatus - View HAI Security Progress

Display current security maturity progress and next steps.

## Trigger

User says: "/verifhai status", "show my progress", "what have I completed", "security progress"

## Workflow

### Step 1: Gather Progress Data

Check for existing security artifacts:
- `docs/security/security-requirements.md`
- `docs/security/threat-model.md`
- `docs/security/architecture.md`
- `.verifhai/progress.json` (if exists)

### Step 2: Display Progress Dashboard

```
## HAI Security Progress Dashboard

**Project:** [Project Name]
**Last Updated:** [Date]

### Overall Maturity

┌────────────────────────────────────────────────────────────────┐
│                                                                 │
│  Overall Score: [X.X] / 3.0                                    │
│  ████████████░░░░░░░░░░░░░░░░░░░  [XX%]                       │
│                                                                 │
│  Level: [Foundational / Comprehensive / Industry-Leading]      │
│                                                                 │
└────────────────────────────────────────────────────────────────┘

### Practice Progress

**Governance Function**
| Practice | Level | Status | Last Activity |
|----------|-------|--------|---------------|
| Strategy & Metrics (SM) | L1 | In Progress | Defined objectives |
| Policy & Compliance (PC) | - | Not Started | - |
| Education & Guidance (EG) | - | Not Started | - |

**Design Function**
| Practice | Level | Status | Last Activity |
|----------|-------|--------|---------------|
| Threat Assessment (TA) | L1 | Complete | Created threat model |
| Security Requirements (SR) | L2 | Complete | Documented + enforced |
| Secure Architecture (SA) | L1 | In Progress | Defined boundaries |

**Verification Function**
| Practice | Level | Status | Last Activity |
|----------|-------|--------|---------------|
| Design Review (DR) | - | Not Started | - |
| Implementation Review (IR) | L1 | Complete | Initial code review |
| Security Testing (ST) | - | Not Started | - |

**Operations Function**
| Practice | Level | Status | Last Activity |
|----------|-------|--------|---------------|
| Environment Hardening (EH) | L1 | In Progress | Basic hardening |
| Issue Management (IM) | - | Not Started | - |
| Monitoring & Logging (ML) | L1 | Complete | Logging configured |

### Visual Summary

```
Governance  ████░░░░░░  1.0/3.0
Design      ███████░░░  2.0/3.0
Verify      ███░░░░░░░  1.0/3.0
Operations  ████░░░░░░  1.3/3.0
```

### AI Risk Coverage

| Risk | Coverage | Status |
|------|----------|--------|
| Excessive Agency (EA) | Partial | Permissions defined, need enforcement |
| Agent Goal Hijack (AGH) | Weak | Need goal integrity checks |
| Tool Misuse (TM) | Good | Input validation + logging |
| Rogue Agents (RA) | Partial | Logging in place, need alerts |

### Security Artifacts

| Artifact | Status | Location |
|----------|--------|----------|
| Security Requirements | Created | `docs/security/security-requirements.md` |
| Threat Model | Created | `docs/security/threat-model.md` |
| Architecture Diagram | Missing | - |
| Review Checklist | Created | `docs/security/review-checklist.md` |
| Security Tests | Missing | - |

### Recent Activity

1. [Date] - Completed Security Requirements (SR) Level 1
2. [Date] - Created threat model for AI agent
3. [Date] - Initial code review performed
4. [Date] - Configured action logging

### Recommended Next Steps

**High Priority:**
1. **Security Testing (ST)** - Not started
   Add security tests for AI-specific vulnerabilities
   Command: `/verifhai practice st`

2. **Design Review (DR)** - Not started
   Review architecture for security gaps
   Command: `/verifhai practice dr`

**Medium Priority:**
3. **Issue Management (IM)** - Not started
   Formalize security issue tracking
   Command: `/verifhai practice im`

4. **Policy & Compliance (PC)** - Not started
   Document security policies
   Command: `/verifhai practice pc`

### Quick Actions

| Command | Description |
|---------|-------------|
| `/verifhai practice [id]` | Work on specific practice |
| `/verifhai assess` | Run quick assessment |
| `/verifhai review` | Review code for security |
| `/verifhai measure` | Full maturity measurement |
```

---

## Progress Tracking

### Automatic Detection

Verifhai automatically detects completed activities by checking for:

**Security Requirements (SR):**
- `**/security-requirements.md` exists
- Requirements follow SR-XXX format
- CAN/CANNOT/MUST boundaries defined

**Threat Assessment (TA):**
- `**/threat-model.md` exists
- STRIDE analysis included
- AI-specific threats covered

**Secure Architecture (SA):**
- Architecture diagram exists
- Permission boundaries documented
- Security controls marked

**Implementation Review (IR):**
- Review findings documented
- Code review comments in PRs
- Security checklist used

**Security Testing (ST):**
- Security test files exist
- Tests in CI/CD pipeline
- Coverage report available

**Monitoring & Logging (ML):**
- Logging configuration exists
- Alert rules defined
- AI actions logged

### Manual Updates

If artifacts are in non-standard locations:

```
To update your progress manually:

1. Create `.verifhai/progress.json`:
{
  "practices": {
    "SR": {"level": 2, "status": "complete", "evidence": ["path/to/requirements.md"]},
    "TA": {"level": 1, "status": "complete", "evidence": ["path/to/threat-model.md"]},
    ...
  },
  "last_assessment": "2024-01-15",
  "artifacts": {
    "security_requirements": "custom/path/requirements.md",
    "threat_model": "custom/path/threats.md"
  }
}

2. Run `/verifhai status` to see updated dashboard
```

---

## Comparison with Python Tool

For detailed tracking and visualizations:

```
For comprehensive tracking with visualizations, use the Python tool:

$ cd ~/projects/verifhai
$ python main.py

The desktop tool provides:
- Historical progress tracking
- Radar charts and heatmaps
- Trend analysis over time
- Export for reporting
- Team collaboration features
```

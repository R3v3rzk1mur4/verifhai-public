# Verifhai Quick Reference

## Commands

| Command | Description |
|---------|-------------|
| `/verifhai start` | Begin security journey for new AI project |
| `/verifhai assess` | Quick maturity assessment (~10 min) |
| `/verifhai practice [id]` | Work on specific practice |
| `/verifhai review` | Security code review |
| `/verifhai status` | View progress dashboard |
| `/verifhai measure` | Full maturity assessment |

## Practice IDs

| ID | Practice | Focus |
|----|----------|-------|
| `sm` | Strategy & Metrics | Security objectives, KPIs |
| `pc` | Policy & Compliance | Policies, regulations |
| `eg` | Education & Guidance | Training, awareness |
| `ta` | Threat Assessment | Threat modeling, risks |
| `sr` | Security Requirements | Requirements, boundaries |
| `sa` | Secure Architecture | Design patterns |
| `dr` | Design Review | Architecture review |
| `ir` | Implementation Review | Code review |
| `st` | Security Testing | Security tests |
| `eh` | Environment Hardening | Infrastructure |
| `im` | Issue Management | Vulnerability tracking |
| `ml` | Monitoring & Logging | Detection, alerting |

## AI Threat Quick Reference

| TTP | Meaning | Key Practices |
|-----|---------|---------------|
| **EA** | Excessive Agency | TA, SR, SA |
| **AGH** | Agent Goal Hijack | TA, SR, ML |
| **TM** | Tool Misuse | TA, IR, ST |
| **RA** | Rogue Agents | SA, ML, IM |

## Maturity Levels

| Level | Name | Description |
|-------|------|-------------|
| L1 | Foundational | Basic practices in place |
| L2 | Comprehensive | Documented, consistent |
| L3 | Industry-Leading | Measured, optimized |

## Security Requirement Keywords

| Keyword | Meaning |
|---------|---------|
| **SHALL** | Mandatory |
| **SHOULD** | Recommended |
| **MAY** | Optional |
| **SHALL NOT** | Prohibited |

## Permission Boundaries Template

```
CAN:
- [Allowed action 1]
- [Allowed action 2]

CANNOT:
- [Prohibited action 1]
- [Prohibited action 2]

MUST:
- Log all actions
- Respect rate limits
- Validate inputs
```

## STRIDE for AI

| Letter | Threat | AI Example |
|--------|--------|------------|
| **S** | Spoofing | Fake user/AI identity |
| **T** | Tampering | Modified inputs/outputs |
| **R** | Repudiation | Actions not logged |
| **I** | Info Disclosure | AI leaks data |
| **D** | Denial of Service | Resource exhaustion |
| **E** | Elevation | Permission bypass |

## Integration

**Claude Skill (Verifhai):**
- Interactive guidance
- Code review
- Practice building
- Real-time help

**Python Tool:**
- Formal assessments
- Visualizations
- Historical tracking
- Export/reporting

```bash
# Launch Python tool
cd ~/projects/verifhai && python main.py
```

## HAIAMM Data Location

```
~/projects/verifhai/config/haiamm_multi_domain_data_v2.2.json
```

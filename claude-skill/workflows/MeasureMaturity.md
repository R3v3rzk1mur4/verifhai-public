# MeasureMaturity - Full Security Maturity Assessment

Comprehensive maturity measurement using the HAIAMM framework.

## Trigger

User says: "/verifhai measure", "full assessment", "measure maturity", "comprehensive assessment"

## Workflow

### Step 1: Assessment Introduction

```
## Full HAIAMM Maturity Assessment

This comprehensive assessment evaluates your HAI security maturity across:
- 6 Security Domains
- 12 Security Practices
- 3 Maturity Levels

**Assessment Tiers:**

| Tier | Domains | Practices | Questions | Time |
|------|---------|-----------|-----------|------|
| Tier 1 (Quick) | 2 | 6 | ~24 | 30-45 min |
| Tier 2 (Standard) | 4 | 12 | ~195 | 4-6 hours |
| Tier 3 (Comprehensive) | 6 | 16 | ~451 | 18-24 hours |

**Which tier would you like?**

1. **Tier 1: Foundation** - Quick baseline, executive briefing
2. **Tier 2: Standard** - Annual review, operational planning
3. **Tier 3: Comprehensive** - Audit/compliance, multi-year planning

For interactive CLI assessment, the Python tool is recommended:
```bash
cd ~/projects/verifhai && python main.py
```
```

### Step 2: Tier 1 Quick Assessment

If user selects Tier 1:

```
## Tier 1: Foundation Assessment

**Domains:** Software, Data
**Practices:** SM, PC, EG, TA, SR, IM
**Questions:** ~24
**Time:** 30-45 minutes

Let's begin. For each question, answer:
- **Yes** (1.0) - Fully implemented
- **Partial** (0.5) - Partially implemented
- **No** (0.0) - Not implemented
- **N/A** - Not applicable

---

### Domain: Software

**Practice: Strategy & Metrics (SM)**

SM-SW-1.1: Does your organization have documented security objectives
specifically for AI/ML software components?
[ ] Yes  [ ] Partial  [ ] No  [ ] N/A

SM-SW-1.2: Are there defined metrics to measure the security posture
of AI software development?
[ ] Yes  [ ] Partial  [ ] No  [ ] N/A

**Practice: Threat Assessment (TA)**

TA-SW-1.1: Has a threat model been created for your AI software
that includes AI-specific threats (prompt injection, model attacks)?
[ ] Yes  [ ] Partial  [ ] No  [ ] N/A

TA-SW-1.2: Are threat assessments updated when AI capabilities
or integrations change?
[ ] Yes  [ ] Partial  [ ] No  [ ] N/A

**Practice: Security Requirements (SR)**

SR-SW-1.1: Are security requirements documented for AI software
components, including input validation and output handling?
[ ] Yes  [ ] Partial  [ ] No  [ ] N/A

SR-SW-1.2: Do security requirements include AI-specific controls
such as permission boundaries and action logging?
[ ] Yes  [ ] Partial  [ ] No  [ ] N/A

[Continue for all Tier 1 questions...]
```

### Step 3: Calculate Scores

```
## Assessment Results

**Assessment Date:** [Date]
**Tier:** [1/2/3]
**Assessor:** [Name if provided]

### Overall Maturity Score

┌────────────────────────────────────────────────────────────────┐
│                                                                 │
│  OVERALL MATURITY: [X.XX] / 3.0                                │
│                                                                 │
│  ████████████████░░░░░░░░░░░░░░  [XX%]                        │
│                                                                 │
│  Level: [FOUNDATIONAL / COMPREHENSIVE / INDUSTRY-LEADING]      │
│                                                                 │
└────────────────────────────────────────────────────────────────┘

### Domain Scores

| Domain | Score | Level | Key Gaps |
|--------|-------|-------|----------|
| Software | 2.1 | L2 | Security Testing |
| Data | 1.5 | L1 | Data Classification |
| Infrastructure | 1.8 | L1 | Environment Hardening |
| Vendors | 1.2 | L1 | Vendor Assessment |
| Processes | 2.0 | L2 | Policy Documentation |
| Endpoints | 1.6 | L1 | API Security |

### Business Function Scores

| Function | Score | Level |
|----------|-------|-------|
| Governance | 1.8 | L1 |
| Building | 2.0 | L2 |
| Verification | 1.4 | L1 |
| Operations | 1.9 | L1 |

### Practice Scores (12 Core)

| Practice | Software | Data | Infra | Vendors | Process | Endpoints | Avg |
|----------|----------|------|-------|---------|---------|-----------|-----|
| SM | 2.0 | 1.5 | 1.5 | 1.0 | 2.0 | 1.5 | 1.6 |
| PC | 1.5 | 1.5 | 1.0 | 1.0 | 1.5 | 1.0 | 1.3 |
| EG | 1.5 | 1.0 | 1.0 | 0.5 | 1.5 | 1.0 | 1.1 |
| TA | 2.5 | 2.0 | 1.5 | 1.5 | 2.0 | 1.5 | 1.8 |
| SR | 2.5 | 2.0 | 1.5 | 1.0 | 2.0 | 1.5 | 1.8 |
| SA | 2.0 | 1.5 | 2.0 | 1.0 | 1.5 | 1.5 | 1.6 |
| DR | 1.5 | 1.0 | 1.0 | 0.5 | 1.0 | 1.0 | 1.0 |
| IR | 2.0 | 1.5 | 1.0 | 0.5 | 1.0 | 1.0 | 1.2 |
| ST | 1.5 | 1.0 | 0.5 | 0.5 | 0.5 | 0.5 | 0.8 |
| EH | 2.0 | 1.5 | 2.0 | 1.0 | 1.5 | 1.5 | 1.6 |
| IM | 1.5 | 1.5 | 1.5 | 1.0 | 1.5 | 1.0 | 1.3 |
| ML | 2.5 | 2.0 | 2.0 | 1.5 | 2.0 | 1.5 | 1.9 |
```

### Step 4: Generate Improvement Roadmap

```
### Improvement Roadmap

Based on your assessment, here's a prioritized improvement plan:

**Phase 1: Critical Gaps (0-3 months)**

| Priority | Practice-Domain | Current | Target | Actions |
|----------|-----------------|---------|--------|---------|
| 1 | ST-Software | 1.5 | 2.0 | Add security tests for AI code |
| 2 | IR-Vendors | 0.5 | 1.5 | Review vendor integrations |
| 3 | DR-Process | 1.0 | 2.0 | Establish design review process |

**Phase 2: Foundation Building (3-6 months)**

| Priority | Practice-Domain | Current | Target | Actions |
|----------|-----------------|---------|--------|---------|
| 4 | EG-All | 1.1 | 2.0 | Develop security training |
| 5 | PC-All | 1.3 | 2.0 | Document security policies |
| 6 | IM-All | 1.3 | 2.0 | Formalize issue tracking |

**Phase 3: Optimization (6-12 months)**

| Priority | Practice-Domain | Current | Target | Actions |
|----------|-----------------|---------|--------|---------|
| 7 | All L2 practices | 2.0 | 2.5 | Advance to L2+ |
| 8 | AI risk coverage | Partial | Full | Complete EA/AGH/TM/RA controls |

### AI-Specific Risk Assessment

| Risk | Current Coverage | Gap | Priority |
|------|-----------------|-----|----------|
| Excessive Agency (EA) | 70% | Permission enforcement | High |
| Agent Goal Hijack (AGH) | 40% | Goal integrity checks | Critical |
| Tool Misuse (TM) | 60% | Tool input validation | High |
| Rogue Agents (RA) | 50% | Behavior monitoring | Medium |
```

### Step 5: Export Options

```
### Export Assessment Results

Would you like to export these results?

1. **Markdown Report** - `assessment-report-[date].md`
2. **JSON Data** - `assessment-[date].json` (for Python tool import)
3. **CSV Matrix** - `maturity-matrix-[date].csv`
4. **Executive Summary** - `executive-summary-[date].md`

For visualizations (radar charts, heatmaps), use the Python tool:
```bash
cd ~/projects/verifhai
python main.py --import assessment-[date].json
```
```

---

## Scoring Methodology

### Question Scoring
- **Yes** = 1.0
- **Partial** = 0.5
- **No** = 0.0
- **N/A** = Excluded

### Level Achievement
- **Level 1:** ≥80% Yes on Level 1 questions
- **Level 2:** Level 1 achieved + ≥80% Yes on Level 2 questions
- **Level 3:** Levels 1-2 achieved + ≥80% Yes on Level 3 questions

### Aggregation
- **Practice Score:** Average of all levels (0-3.0)
- **Domain Score:** Average of all practices
- **Function Score:** Average of practices in function
- **Overall Score:** Average of all practices

---

## Integration with Python Tool

For the full assessment experience with visualizations:

```bash
# Launch desktop application
cd ~/projects/verifhai
python main.py

# Or use CLI for quick assessment
python -m verifhai assess --tier 2 --output report.md

# Import Claude assessment results
python -m verifhai import assessment.json
```

The Python tool provides:
- Full questionnaire UI
- Interactive visualizations
- Historical tracking
- Trend analysis
- Team collaboration
- PGP-encrypted storage

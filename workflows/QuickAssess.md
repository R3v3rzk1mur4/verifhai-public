# QuickAssess - Fast Security Maturity Check

Quick assessment to identify security strengths and gaps in your HAI system.

## Trigger

User says: "/verifhai assess", "how secure is my AI", "quick security check", "assess my AI system"

## HAIAMM Context

### Questionnaire Sources
Load questions from official questionnaires when available:
```
${HAIAMM_PATH}/docs/questionnaires/{PRACTICE}-Software-Questionnaire.md
```

> **Note:** Set `HAIAMM_PATH` to your local HAIAMM repository path.

Available questionnaires for Software domain: SM, PC, EG, TA, SR, SA, DR, IR, ST, EH, IM, ML (all 12)

### Scoring Methodology (from Handbook)
- **Level 1 achieved:** ALL L1 questions = "Yes" (+1.0)
- **Level 2 achieved:** L1 complete + ALL L2 = "Yes" (+1.0)
- **Level 3 achieved:** L2 complete + ALL L3 = "Yes" (+1.0)
- Partial implementations count as "No" per HAIAMM rules

## State Management

### Before Assessment
1. Check if `.verifhai/progress.json` exists
2. If exists, show last assessment date and score
3. Offer to compare results

### After Assessment
1. Save results to `.verifhai/progress.json`:
```json
{
  "assessments": [{
    "id": "uuid",
    "date": "ISO8601",
    "type": "quick",
    "scores": { "SM": 1.5, "PC": 1.0, ... },
    "overallScore": 1.4,
    "gaps": [...]
  }]
}
```
2. Update practice levels based on scores
3. Record session in history

## Workflow

### Step 1: Identify Assessment Scope

```
Let's do a quick security assessment of your HAI system.

**What would you like to assess?**

1. **Specific AI project** - Assess a particular AI system or component
2. **Entire codebase** - Assess all AI-related code in this project
3. **Specific practice** - Deep-dive on one practice area (e.g., just Threat Assessment)

Which would you like?
```

### Step 2: Rapid Practice Assessment

For each core practice, ask one key question:

```
I'll ask one question per practice area. Answer honestly - this helps identify where to focus.

**Governance Practices:**

1. **Strategy & Metrics (SM)**
   Do you have documented security objectives for your AI system?
   [ ] Yes, comprehensive  [ ] Partially  [ ] No

2. **Security Requirements (SR)**
   Are there written security requirements for your AI's behavior?
   [ ] Yes, enforced  [ ] Yes, documented  [ ] No

**Design Practices:**

3. **Threat Assessment (TA)**
   Have you threat modeled your AI system for AI-specific risks?
   [ ] Yes, with mitigations  [ ] Partially  [ ] No

4. **Secure Architecture (SA)**
   Are there defined permission boundaries for your AI?
   [ ] Yes, enforced  [ ] Yes, designed  [ ] No

**Verification Practices:**

5. **Implementation Review (IR)**
   Has the AI code been security reviewed?
   [ ] Yes, regularly  [ ] Once  [ ] No

6. **Security Testing (ST)**
   Is the AI tested for security vulnerabilities?
   [ ] Automated  [ ] Manual  [ ] No

**Operations Practices:**

7. **Monitoring & Logging (ML)**
   Are AI actions logged and monitored?
   [ ] Real-time alerts  [ ] Logged  [ ] No

8. **Issue Management (IM)**
   Do you track and remediate AI security issues?
   [ ] Formal process  [ ] Ad-hoc  [ ] No
```

### Step 3: Calculate and Present Results

```
**Quick Assessment Results**

Based on your answers, here's your HAI security profile:

┌────────────────────────────────────────────────────────────────┐
│                    MATURITY SUMMARY                             │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Overall: [X.X] / 3.0  [████████░░░░░░░░] [Strong/Developing/Weak]
│                                                                 │
│  Governance    [█████░░░░░] 1.5    Building foundations        │
│  Design        [███████░░░] 2.0    Well-structured             │
│  Verification  [███░░░░░░░] 1.0    Needs attention             │
│  Operations    [█████████░] 2.5    Strong practices            │
│                                                                 │
└────────────────────────────────────────────────────────────────┘

**Strengths:**
- Monitoring & Logging (ML) - L2: Good visibility into AI behavior
- Secure Architecture (SA) - L2: Permission boundaries defined

**Critical Gaps:**
- Implementation Review (IR) - Not started: Code not reviewed for security
- Security Testing (ST) - Not started: No security testing

**Top 3 Recommendations:**

1. **[CRITICAL] Start Implementation Review (IR)**
   Your AI code hasn't been security reviewed. This is essential before production.
   Time: 2-4 hours for initial review
   Command: `/verifhai practice ir`

2. **[HIGH] Establish Security Testing (ST)**
   Add security tests for AI-specific vulnerabilities.
   Time: 1-2 hours to set up basic tests
   Command: `/verifhai practice st`

3. **[MEDIUM] Formalize Security Requirements (SR)**
   Document your permission model more formally.
   Time: 1 hour to document
   Command: `/verifhai practice sr`

Would you like to work on Implementation Review now?
```

### Step 4: Detailed Practice Breakdown (Optional)

If user wants more detail:

```
**Detailed Practice Scores:**

| Practice | Score | Level | Evidence |
|----------|-------|-------|----------|
| Strategy & Metrics (SM) | 1.0 | L1 | Basic objectives |
| Policy & Compliance (PC) | 0.5 | - | Informal only |
| Education & Guidance (EG) | 0.5 | - | Ad-hoc training |
| Threat Assessment (TA) | 1.5 | L1 | Partial threat model |
| Security Requirements (SR) | 1.5 | L1 | Documented but not enforced |
| Secure Architecture (SA) | 2.0 | L2 | Boundaries defined |
| Design Review (DR) | 1.0 | L1 | Informal reviews |
| Implementation Review (IR) | 0.0 | - | Not performed |
| Security Testing (ST) | 0.0 | - | No security tests |
| Environment Hardening (EH) | 1.5 | L1 | Basic hardening |
| Issue Management (IM) | 1.0 | L1 | Ad-hoc tracking |
| Monitoring & Logging (ML) | 2.5 | L2 | Good logging |

**AI-Specific Risk Coverage:**

| Risk | Status | Notes |
|------|--------|-------|
| Excessive Agency (EA) | Partial | Permissions defined but not enforced |
| Agent Goal Hijack (AGH) | Weak | No goal integrity checks |
| Tool Misuse (TM) | Partial | Some input validation |
| Rogue Agents (RA) | Good | Logging captures agent behavior |
```

### Step 5: Action Plan

```
**Your 30-Day Security Improvement Plan:**

**Week 1: Critical Gaps**
- [ ] Complete Implementation Review (IR) - Review all AI code
- [ ] Set up basic Security Testing (ST) - Add prompt injection tests

**Week 2: Strengthen Design**
- [ ] Formalize Security Requirements (SR) - Document permission model
- [ ] Update Threat Assessment (TA) - Include AI-specific threats

**Week 3: Governance**
- [ ] Document Strategy & Metrics (SM) - Define security objectives
- [ ] Create Security Guidance (EG) - Document secure patterns

**Week 4: Operations**
- [ ] Formalize Issue Management (IM) - Track security findings
- [ ] Enhance Monitoring (ML) - Add AI-specific alerts

**Track Progress:**
- Run `/verifhai assess` weekly to track improvement
- Use `/verifhai status` to see detailed progress
- Use Python Verifhai tool for formal quarterly assessments
```

---

## Scoring Algorithm

**Scoring Criteria:**
- Yes, comprehensive/enforced/automated = 1.0
- Partial/documented/manual = 0.5
- No/not started = 0.0

**Level Calculation:**
- 0.0-0.5 = Not started
- 0.5-1.5 = Level 1 (Foundational)
- 1.5-2.5 = Level 2 (Comprehensive)
- 2.5-3.0 = Level 3 (Industry-Leading)

**Function Scores:**
- Governance = Average(SM, PC, EG)
- Design = Average(TA, SR, SA)
- Verification = Average(DR, IR, ST)
- Operations = Average(EH, IM, ML)

---

## Integration with Python Tool

For formal assessments with full questionnaires and visualizations:

```
For a comprehensive assessment with full reporting, use the Python Verifhai tool:

$ cd ~/projects/verifhai
$ python main.py

The desktop tool provides:
- Full 451-question assessment (Tier 3)
- Interactive visualizations
- Historical tracking
- Export to JSON/CSV/Markdown
- PGP-encrypted storage

Quick CLI assessment:
$ python -m verifhai assess --tier 1  # 24 questions, 30 min
$ python -m verifhai assess --tier 2  # 195 questions, 4-6 hours
$ python -m verifhai assess --tier 3  # 451 questions, 18-24 hours
```

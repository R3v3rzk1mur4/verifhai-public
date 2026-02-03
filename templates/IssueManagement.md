# Issue Management (IM) Template

## Document Control

| Field | Value |
|-------|-------|
| Project | [Project Name] |
| Version | 1.0 |
| Date | [YYYY-MM-DD] |
| Author | [Author Name] |
| Status | Draft / Active |

---

## 1. Issue Management Overview

### 1.1 Purpose

This document defines the process for managing security issues in HAI (Human-Assisted Intelligence) systems, including:

- Security vulnerability discovery and triage
- AI-specific incident handling
- Remediation tracking
- Post-incident analysis

### 1.2 Scope

| Issue Type | In Scope | Handler |
|------------|----------|---------|
| Security vulnerabilities | Yes | Security Team |
| AI behavior anomalies | Yes | AI/ML + Security |
| Prompt injection attempts | Yes | Security Team |
| Permission violations | Yes | Security Team |
| Data breaches | Yes | Security + Legal |
| Service availability | Partial | SRE + Security |

---

## 2. Issue Classification

### 2.1 Severity Levels

| Severity | Definition | SLA (Detection to Resolution) | Escalation |
|----------|------------|-------------------------------|------------|
| **Critical** | Active exploitation, data breach, agent compromise | 4 hours | Immediate executive notification |
| **High** | Exploitable vulnerability, significant risk | 24 hours | Security Lead + Engineering Lead |
| **Medium** | Moderate risk, no active exploitation | 7 days | Security Team |
| **Low** | Minor issue, limited impact | 30 days | Assigned engineer |
| **Info** | Observation, best practice | Backlog | Track for future |

### 2.2 AI-Specific Issue Categories

| Category | Code | Description | Examples |
|----------|------|-------------|----------|
| Prompt Injection | PI | Attempts to manipulate AI behavior | Instruction override, jailbreak |
| Excessive Agency | EA | AI exceeds intended permissions | Unauthorized file access |
| Goal Hijacking | AGH | AI goals manipulated | Multi-turn manipulation |
| Tool Misuse | TM | Tools used inappropriately | Path traversal via tools |
| Rogue Agent | RA | AI behaves unexpectedly | Runaway loops, resource exhaustion |
| Data Leakage | DL | Sensitive data exposed | PII in responses |
| Model Issue | MI | Underlying model problem | Harmful outputs |

### 2.3 Standard Security Categories

| Category | Code | Description |
|----------|------|-------------|
| Authentication | AUTH | Identity and access issues |
| Authorization | AUTHZ | Permission issues |
| Injection | INJ | Input injection vulnerabilities |
| Data Exposure | DEXP | Information disclosure |
| Cryptography | CRYP | Encryption/hashing issues |
| Configuration | CONF | Misconfiguration |
| Dependency | DEP | Third-party vulnerabilities |

---

## 3. Issue Lifecycle

### 3.1 Lifecycle Stages

```
┌─────────────────────────────────────────────────────────────────┐
│                      ISSUE LIFECYCLE                             │
│                                                                  │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐  │
│  │  DETECT  │───▶│  TRIAGE  │───▶│ CONTAIN  │───▶│   FIX    │  │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘  │
│       │               │               │               │         │
│       ▼               ▼               ▼               ▼         │
│  - Discovery     - Classify      - Stop harm     - Root cause  │
│  - Report        - Severity      - Isolate       - Remediate   │
│  - Log           - Assign        - Preserve      - Test        │
│                                                                  │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐                  │
│  │  VERIFY  │───▶│  CLOSE   │───▶│  LEARN   │                  │
│  └──────────┘    └──────────┘    └──────────┘                  │
│       │               │               │                         │
│       ▼               ▼               ▼                         │
│  - Test fix      - Document     - Post-mortem                  │
│  - Regression    - Update KB    - Improve process              │
│  - Deploy        - Notify       - Update training              │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Stage Details

#### Stage 1: Detection

**Sources:**
- Automated monitoring and alerts
- Security testing (SAST, DAST, pen testing)
- Bug bounty reports
- User reports
- Internal discovery
- Third-party notifications

**Actions:**
1. Log the detection source and time
2. Capture initial evidence
3. Create issue ticket
4. Notify triage team

#### Stage 2: Triage

**Actions:**
1. Validate the issue is real
2. Classify category (AI-specific or standard)
3. Assign severity level
4. Determine scope of impact
5. Assign owner
6. Set SLA based on severity

**Triage Checklist:**
```
[ ] Issue validated and reproducible
[ ] Category assigned: [PI/EA/AGH/TM/RA/DL/MI/AUTH/AUTHZ/INJ/DEXP/CRYP/CONF/DEP]
[ ] Severity assigned: [Critical/High/Medium/Low/Info]
[ ] Affected systems identified: [List]
[ ] Affected users/data assessed: [Scope]
[ ] Owner assigned: [Name]
[ ] SLA set: [Time]
```

#### Stage 3: Containment

**Actions:**
1. Stop ongoing harm
2. Isolate affected systems if needed
3. Preserve evidence for investigation
4. Implement temporary mitigations
5. Monitor for further exploitation

**AI-Specific Containment:**
```
For Prompt Injection (PI):
[ ] Block offending input patterns
[ ] Add to detection rules
[ ] Monitor for variants

For Excessive Agency (EA):
[ ] Revoke excessive permissions immediately
[ ] Review permission logs
[ ] Audit all recent agent actions

For Rogue Agent (RA):
[ ] Activate kill switch
[ ] Stop agent execution
[ ] Review all actions taken
[ ] Isolate agent environment
```

#### Stage 4: Fix

**Actions:**
1. Identify root cause
2. Develop remediation
3. Review fix with security
4. Test fix in staging
5. Deploy fix
6. Verify in production

**Fix Requirements:**
```
[ ] Root cause documented
[ ] Fix addresses root cause (not just symptom)
[ ] Fix reviewed by security
[ ] Tests added for issue
[ ] Regression tests pass
[ ] Fix deployed to affected environments
[ ] Production verification complete
```

#### Stage 5: Verify

**Actions:**
1. Confirm fix is effective
2. Run regression tests
3. Verify no new issues introduced
4. Monitor for recurrence

#### Stage 6: Close

**Actions:**
1. Document resolution
2. Update knowledge base
3. Notify stakeholders
4. Update issue tracker

#### Stage 7: Learn

**Actions:**
1. Conduct post-mortem (for High/Critical)
2. Identify process improvements
3. Update detection rules
4. Update training materials
5. Share learnings with team

---

## 4. Issue Ticket Template

### 4.1 New Issue Template

```markdown
## Issue Title
[Concise description of the issue]

## Summary
[1-2 paragraph description]

## Classification
- **Category:** [AI-Specific: PI/EA/AGH/TM/RA/DL/MI | Standard: AUTH/AUTHZ/INJ/DEXP/CRYP/CONF/DEP]
- **Severity:** [Critical/High/Medium/Low/Info]
- **Status:** [New/Triaged/Contained/Fixing/Verifying/Closed]

## Impact Assessment
- **Affected Systems:** [List]
- **Affected Users:** [Count/Description]
- **Data at Risk:** [Type, volume]
- **Business Impact:** [Description]

## Discovery
- **Detected By:** [Source]
- **Detection Date:** [YYYY-MM-DD HH:MM]
- **Reporter:** [Name/System]

## Technical Details
### Description
[Detailed technical description]

### Reproduction Steps
1. [Step 1]
2. [Step 2]
3. [Step 3]

### Evidence
[Logs, screenshots, payloads - REDACT SENSITIVE DATA]

### Root Cause (if known)
[Explanation of underlying cause]

## Remediation
### Containment Actions
- [ ] [Action 1]
- [ ] [Action 2]

### Fix
- **PR/Commit:** [Link]
- **Description:** [What was fixed]
- **Deployed:** [Date/Environment]

### Verification
- [ ] Fix tested in staging
- [ ] Fix verified in production
- [ ] Regression tests added

## Timeline
| Time | Event |
|------|-------|
| [Time] | Issue detected |
| [Time] | Triage complete |
| [Time] | Containment implemented |
| [Time] | Fix deployed |
| [Time] | Issue closed |

## Lessons Learned
[What we learned, what we'll do differently]
```

---

## 5. Incident Response Procedures

### 5.1 Critical Security Incident

**Triggers:**
- Active exploitation detected
- Data breach confirmed
- Agent compromise
- Unauthorized access to sensitive systems

**Response Procedure:**

```
HOUR 0: DETECTION & ESCALATION
[ ] Confirm incident is real
[ ] Page on-call security engineer
[ ] Page engineering lead
[ ] Notify executive sponsor
[ ] Start incident bridge/war room
[ ] Begin incident log

HOUR 0-1: CONTAINMENT
[ ] Assess scope of compromise
[ ] Isolate affected systems
[ ] Activate kill switch for compromised agents
[ ] Preserve logs and evidence
[ ] Block attacker access if identified
[ ] Implement emergency mitigations

HOUR 1-4: INVESTIGATION & REMEDIATION
[ ] Determine root cause
[ ] Identify all affected systems/data
[ ] Develop fix
[ ] Test fix
[ ] Deploy fix
[ ] Verify effectiveness

HOUR 4+: RECOVERY & LEARNING
[ ] Restore normal operations
[ ] Monitor for recurrence
[ ] Complete incident report
[ ] Notify affected parties if required
[ ] Schedule post-mortem
[ ] Update detection and response
```

### 5.2 AI Agent Incident

**Triggers:**
- Agent performing unauthorized actions
- Agent ignoring constraints
- Prompt injection successful
- Agent accessing forbidden resources

**AI-Specific Response:**

```
IMMEDIATE (Minutes 0-5):
[ ] Activate agent kill switch
[ ] Stop all agent execution
[ ] Capture agent state and logs
[ ] Alert security team

CONTAINMENT (Minutes 5-30):
[ ] Review all agent actions since anomaly
[ ] Identify scope of unauthorized actions
[ ] Revert unauthorized changes if possible
[ ] Block agent from resuming

INVESTIGATION (Hours 1-4):
[ ] Analyze attack vector (prompt injection, goal hijacking, etc.)
[ ] Determine if other agents affected
[ ] Identify improvements to containment
[ ] Document findings

REMEDIATION (Hours 4+):
[ ] Implement additional controls
[ ] Update permission boundaries
[ ] Enhance detection rules
[ ] Test and verify fixes
[ ] Carefully restart agent with monitoring
```

---

## 6. Issue Register

### 6.1 Open Issues

| ID | Title | Category | Severity | Status | Owner | SLA | Days Open |
|----|-------|----------|----------|--------|-------|-----|-----------|
| ISS-001 | [Title] | [Cat] | [Sev] | [Status] | [Name] | [Date] | [Days] |

### 6.2 Recently Closed

| ID | Title | Category | Severity | Resolution | Closed Date |
|----|-------|----------|----------|------------|-------------|
| ISS-000 | [Title] | [Cat] | [Sev] | [Fix summary] | [Date] |

---

## 7. Metrics & Reporting

### 7.1 Key Metrics

| Metric | Target | Current | Trend |
|--------|--------|---------|-------|
| MTTR (Critical) | < 4 hours | [Current] | [↑↓→] |
| MTTR (High) | < 24 hours | [Current] | [↑↓→] |
| Open Critical Issues | 0 | [Current] | [↑↓→] |
| Open High Issues | < 5 | [Current] | [↑↓→] |
| SLA Compliance | > 95% | [Current] | [↑↓→] |
| Recurrence Rate | < 5% | [Current] | [↑↓→] |

### 7.2 Monthly Report Template

```markdown
## Security Issue Management Report - [Month Year]

### Summary
- Total Issues: [Count]
- Critical: [Count] | High: [Count] | Medium: [Count] | Low: [Count]
- Opened: [Count] | Closed: [Count]
- AI-Specific: [Count] ([Percentage]%)

### SLA Performance
- Critical: [X]% within SLA
- High: [X]% within SLA
- Overall: [X]% within SLA

### Top Categories
1. [Category]: [Count]
2. [Category]: [Count]
3. [Category]: [Count]

### Notable Issues
- [ISS-XXX]: [Brief description and outcome]

### Trends
- [Observation about trends]

### Recommendations
1. [Improvement recommendation]
2. [Improvement recommendation]
```

---

## 8. Knowledge Base

### 8.1 Common Issues & Solutions

| Issue Pattern | Category | Root Cause | Standard Fix |
|---------------|----------|------------|--------------|
| "Ignore previous instructions" in input | PI | Missing input validation | Add injection detection |
| Agent accessing /etc/passwd | TM | Path traversal | Validate paths against allowlist |
| Agent in infinite loop | RA | No iteration limit | Add iteration limits |
| PII in agent response | DL | No output sanitization | Add output filtering |

### 8.2 Detection Rules

| Rule ID | Pattern | Category | Action |
|---------|---------|----------|--------|
| DET-001 | /ignore.*previous.*instructions/i | PI | Alert + block |
| DET-002 | Permission denied > 100/hour | EA | Alert |
| DET-003 | Agent iterations > 80% limit | RA | Alert |
| DET-004 | Path contains ../ | TM | Block + alert |

---

## 9. Contacts & Escalation

### 9.1 Escalation Matrix

| Severity | First Contact | Escalation (30 min) | Escalation (2 hrs) |
|----------|---------------|--------------------|--------------------|
| Critical | On-call engineer | Security Lead | CTO/CISO |
| High | On-call engineer | Security Lead | - |
| Medium | Security team | - | - |
| Low | Assigned engineer | - | - |

### 9.2 Contact List

| Role | Name | Email | Phone | On-Call |
|------|------|-------|-------|---------|
| Security Lead | [Name] | [Email] | [Phone] | [Schedule] |
| On-Call Engineer | [Name] | [Email] | [Phone] | [Schedule] |
| Legal Contact | [Name] | [Email] | [Phone] | [Schedule] |
| Executive Sponsor | [Name] | [Email] | [Phone] | Critical only |

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | [Date] | [Author] | Initial issue management process |

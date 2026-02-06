# Processes Domain: AI-Automated Security Operations - Assessments

## Assessment Overview

| Level | Questions | Passing Score | Format |
|-------|-----------|---------------|--------|
| L1 | 10 questions | 80% (8/10) | Multiple choice |
| L2 | 12 questions | 80% (10/12) | Multiple choice + scenario |
| L3 | 8 questions + practical | 80% + practical pass | Scenario + process design |

---

## Level 1 Assessment: AI-Automated Process Basics

### Questions

**Q1. What does SOAR stand for in security operations?**

- A) Security Orchestration, Automation, and Response ✓
- B) Security Operations and Response
- C) System Optimization and Recovery
- D) Secure Operations Architecture Review

**Explanation:** SOAR platforms provide Security Orchestration (connecting tools), Automation (executing workflows), and Response (taking action).

---

**Q2. What is a key limitation of AI in security process automation?**

- A) AI is too fast
- B) AI may lack business context for complex judgment calls ✓
- C) AI is always 100% accurate
- D) AI never needs human oversight

**Explanation:** AI struggles with nuanced business decisions and novel situations that require human judgment and context.

---

**Q3. In AI-assisted incident triage, what is the AI's primary role?**

- A) Pre-score, enrich, and prioritize alerts for human review ✓
- B) Replace all human analysts
- C) Make all final decisions
- D) Only generate reports

**Explanation:** AI assists by triaging, enriching, and prioritizing, but humans make final decisions on complex cases.

---

**Q4. When should AI-automated processes escalate to humans?**

- A) Never - AI handles everything
- B) When AI confidence is low, situations are novel, or decisions are high-impact ✓
- C) Only when the AI system crashes
- D) For every single alert

**Explanation:** Escalate when AI is uncertain, encounters new patterns, or when decisions could have significant impact.

---

**Q5. What is the purpose of quality sampling AI-closed incidents?**

- A) To slow down the AI
- B) To create more work for analysts
- C) To verify AI made correct decisions and identify improvement areas ✓
- D) To comply with AI regulations only

**Explanation:** Quality sampling catches AI errors, identifies patterns for improvement, and maintains accountability.

---

**Q6. Which security process is a good candidate for AI automation?**

- A) Executive communication during breaches
- B) Board reporting
- C) Policy exception approvals
- D) Routine alert triage and enrichment ✓

**Explanation:** Routine, repeatable tasks like alert triage are ideal for AI automation; judgment-heavy tasks need humans.

---

**Q7. What is a SOAR playbook?**

- A) An automated workflow that executes security response steps ✓
- B) A sports play diagram
- C) A compliance document
- D) A user manual

**Explanation:** SOAR playbooks are automated workflows that execute predefined security response steps.

---

**Q8. How does AI-automated compliance reporting help organizations?**

- A) It eliminates the need for auditors
- B) It automates evidence collection and report generation, requiring human review ✓
- C) It makes compliance optional
- D) It replaces all compliance staff

**Explanation:** AI automates gathering evidence and drafting reports, but humans must review for accuracy before submission.

---

**Q9. What is a key benefit of AI process automation in security operations?**

- A) Eliminates all security risks
- B) Makes human analysts unnecessary
- C) Provides consistent, 24/7 execution of routine tasks ✓
- D) Guarantees 100% accuracy

**Explanation:** AI provides consistent execution around the clock, saving analyst time for complex work.

---

**Q10. What should happen when an AI-automated process encounters an error?**

- A) Ignore it and continue
- B) Restart the entire system
- C) Delete the incident
- D) Log the error, notify appropriate team, and fall back to manual process ✓

**Explanation:** Errors should be logged, notifications sent, and manual fallback processes activated to maintain operations.

---

## Level 2 Assessment: AI Process Operations

### Questions

**Q1. What is the recommended quality sampling rate for AI-closed incidents?**

- A) 5-10% sample for accuracy validation ✓
- B) 100% - review every incident
- C) 0% - trust the AI completely
- D) Only review when customers complain

**Explanation:** Sampling 5-10% balances quality assurance with efficiency; reviewing everything defeats automation's purpose.

---

**Q2. When designing a SOAR playbook, what should be defined as "human review required"?**

- A) Nothing - full automation
- B) Situations with high business impact, executive involvement, or novel patterns ✓
- C) Only technical errors
- D) Random samples

**Explanation:** Human review is needed for high-impact decisions, sensitive situations, and novel patterns AI hasn't seen.

---

**Q3. How does AI process automation integrate with ITIL Incident Management?**

- A) AI replaces ITIL
- B) ITIL doesn't apply to AI
- C) AI actions are logged in incident tickets, following ITIL escalation matrix ✓
- D) AI ignores ITIL processes

**Explanation:** AI automation should integrate with ITIL, logging actions in tickets and following established escalation paths.

---

**Q4. What is the target accuracy rate for AI incident classification?**

- A) 50%
- B) 75%
- C) 100% always
- D) >95% ✓

**Explanation:** High-performing AI classification should achieve >95% accuracy; below this, too many errors reach production.

---

**Q5. What is "process conformance" in AI workflow monitoring?**

- A) How closely actual execution matches the designed process ✓
- B) How fast the process runs
- C) How much the process costs
- D) How many people like the process

**Explanation:** Conformance measures whether the process is executing as designed, identifying deviations or workarounds.

---

**Scenario A:** Your SOAR platform auto-closes 60% of phishing alerts. Quality review shows 5% of auto-closed alerts were actually malicious.

**Q6. What is the primary concern with this scenario?**

- A) 60% auto-close rate is too low
- B) 5% false negative rate means real phishing emails are being missed ✓
- C) Quality review is unnecessary
- D) SOAR is working perfectly

**Explanation:** A 5% false negative rate means actual phishing is being auto-closed, potentially leading to compromise.

---

**Q7. What action should be taken for Scenario A?**

- A) Increase auto-close rate to 80%
- B) Disable all automation
- C) Tighten auto-close criteria, retrain AI model, increase quality sampling ✓
- D) Ignore the quality review

**Explanation:** Tighten criteria to reduce false negatives, retrain the model, and increase sampling to catch issues earlier.

---

**Scenario B:** Analysts report that the AI enrichment step in your incident playbook frequently times out, causing manual fallback.

**Q8. What is the operational impact of this issue?**

- A) No impact
- B) Reduced costs
- C) Better security
- D) Increased analyst workload, slower MTTR, potential for missed context ✓

**Explanation:** Timeout-driven fallback increases manual work, slows response, and may mean analysts lack enrichment context.

---

**Q9. How should timeout issues in AI playbooks be addressed?**

- A) Increase timeout, optimize integration, add caching, consider async enrichment ✓
- B) Remove the enrichment step
- C) Accept the current state
- D) Replace all AI with manual processes

**Explanation:** Address timeouts through optimization (faster queries, caching, async processing) while maintaining the enrichment value.

---

**Q10. In ITIL terms, AI playbook changes should go through which process?**

- A) No process needed
- B) Change Management ✓
- C) Only Problem Management
- D) Service Catalog

**Explanation:** Playbook changes affect incident handling and should follow Change Management to ensure proper review and approval.

---

**Q11. What metric best measures the business impact of AI process automation?**

- A) Number of playbooks created
- B) Lines of automation code
- C) MTTR reduction and analyst time saved ✓
- D) Number of AI models deployed

**Explanation:** Business impact is measured by outcomes: faster response (MTTR) and efficiency gains (analyst time saved).

---

**Q12. What is process mining used for in AI workflow optimization?**

- A) Mining cryptocurrency
- B) Deleting old processes
- C) Creating new processes from scratch
- D) Analyzing actual process execution to identify inefficiencies and improvement opportunities ✓

**Explanation:** Process mining analyzes how processes actually execute (vs. how designed) to find bottlenecks and improvements.

---

## Level 3 Assessment: Process Excellence Leadership

### Questions

**Q1. What is the typical target for security automation ROI?**

- A) 100-400%+ ROI through analyst time savings, MTTR reduction, and avoided hires ✓
- B) 50% ROI
- C) 10% ROI
- D) ROI doesn't matter for security

**Explanation:** Well-implemented security automation typically delivers 100-400%+ ROI through efficiency gains.

---

**Q2. Which metric indicates AI process quality degradation over time?**

- A) Number of playbooks
- B) Declining accuracy scores and increasing false positive/negative rates ✓
- C) Server uptime
- D) Number of users

**Explanation:** Tracking accuracy trends reveals if AI quality is degrading, signaling need for retraining or tuning.

---

**Q3. How should process excellence teams handle AI model updates?**

- A) Deploy immediately without testing
- B) Never update models
- C) Test in staging, validate accuracy, deploy with rollback plan through change management ✓
- D) Only update annually

**Explanation:** Model updates should follow proper testing, validation, and change management to prevent production issues.

---

**Scenario C:** Your organization wants to calculate ROI for SOAR implementation. You have: 10,000 incidents/year, 0.5 hours saved per incident, $75/hour analyst cost, $200K platform cost.

**Q4. What is the annual analyst time savings value?**

- A) $75,000
- B) $200,000
- C) $750,000
- D) $375,000 (10,000 × 0.5 × $75) ✓

**Explanation:** 10,000 incidents × 0.5 hours × $75/hour = $375,000 in analyst time savings.

---

**Q5. What is the net ROI for Scenario C (assuming $50K maintenance)?**

- A) $125,000 net benefit ($375K - $250K costs) ✓
- B) $575,000
- C) -$100,000
- D) $0

**Explanation:** $375K savings - ($200K platform + $50K maintenance) = $125K net benefit (50% ROI).

---

**Q6. What industry contribution demonstrates process automation leadership?**

- A) Keeping all playbooks proprietary
- B) Publishing playbook templates, contributing to SOAR best practices, speaking at conferences ✓
- C) Using only vendor default playbooks
- D) Avoiding all industry collaboration

**Explanation:** Leadership involves sharing knowledge through templates, best practices, and industry engagement.

---

**Q7. What is the purpose of a Process Excellence community of practice?**

- A) Social networking
- B) Reducing security staff
- C) Cross-functional collaboration to continuously improve AI-automated processes ✓
- D) Replacing management

**Explanation:** Communities of practice bring together diverse expertise to improve automation quality and effectiveness.

---

**Q8. How should organizations handle AI process failures during critical incidents?**

- A) Wait for AI to recover
- B) Blame the AI vendor
- C) Ignore the incident
- D) Have documented manual fallback procedures that can be executed immediately ✓

**Explanation:** Manual fallback procedures ensure operations continue even when AI automation fails.

---

### Practical Exercise: Process Automation Design

**Exercise:** Design an AI-automated security process for the following scenario:

> **Process:** Vulnerability Management Triage
>
> **Current State:**
> - 500+ new vulnerabilities reported monthly
> - Analysts manually review each for exploitability and impact
> - Average triage time: 30 minutes per vulnerability
> - Backlog growing, critical vulnerabilities sometimes delayed
>
> **Requirements:**
> - Reduce triage time by 70%
> - Ensure critical vulnerabilities are identified within 4 hours
> - Maintain >95% accuracy in prioritization
> - Integrate with existing ITSM for remediation tracking

**Deliverables:**

1. **Process Design** - Workflow with AI and human steps
2. **Automation Scope** - What AI automates vs. human handles
3. **Quality Assurance** - How to ensure accuracy
4. **ITIL Integration** - How it fits with ITSM
5. **Metrics** - KPIs to measure success
6. **Risks & Mitigations** - Potential issues and controls

---

## Answer Key Summary

### L1 Answers
1-A, 2-B, 3-A, 4-B, 5-C, 6-D, 7-A, 8-B, 9-C, 10-D

### L2 Answers
1-A, 2-B, 3-C, 4-D, 5-A, 6-B, 7-C, 8-D, 9-A, 10-B, 11-C, 12-D

### L3 Answers
1-A, 2-B, 3-C, 4-D, 5-A, 6-B, 7-C, 8-D
Practical: Rubric-based evaluation

---

**Document Version:** 1.0
**Framework:** HAIAMM v2.0
**Practice:** Education & Guidance (EG)
**Domain:** Processes
**Author:** Verifhai

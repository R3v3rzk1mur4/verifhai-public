# DomainPractice - Domain-Specific Practice Guidance

Build a specific HAIAMM practice for a specific domain using the 72 practice-domain one-pagers.

## Trigger

User says: "/verifhai practice [id] [domain]", "work on TA for Data domain", "build SR for Infrastructure"

## HAIAMM Context Loading

This workflow dynamically loads domain-specific guidance:

### One-Pager Path
```
/Users/kuaihinojosa/projects/HAIAMM/docs/practices/{PRACTICE}-{DOMAIN}-OnePager.md
```

Where:
- `{PRACTICE}` = SM | PC | EG | TA | SR | SA | DR | IR | ST | EH | IM | ML
- `{DOMAIN}` = Software | Data | Infrastructure | Vendors | Processes | Endpoints

### Questionnaire Path (if exists)
```
/Users/kuaihinojosa/projects/HAIAMM/docs/questionnaires/{PRACTICE}-{DOMAIN}-Questionnaire.md
```

Available questionnaires:
- **Software domain:** All 12 practices
- **Data domain:** SM, PC, EG, TA, SR, SA, DR (7 practices)
- Other domains: Extract questions from one-pager maturity sections

---

## Workflow

### Step 1: Parse Arguments

Extract practice and domain from user request:
- Practice ID (uppercase): SM, PC, EG, TA, SR, SA, DR, IR, ST, EH, IM, ML
- Domain (capitalize): Software, Data, Infrastructure, Vendors, Processes, Endpoints

### Step 2: Load One-Pager Context

Read the relevant one-pager file:
```
/Users/kuaihinojosa/projects/HAIAMM/docs/practices/{PRACTICE}-{Domain}-OnePager.md
```

Extract from the one-pager:
1. **Practice Overview** - What this practice achieves in this domain
2. **Domain-Specific Challenges** - Unique concerns for this domain
3. **Level 1 Activities** - Foundational activities
4. **Level 2 Activities** - Comprehensive activities
5. **Level 3 Activities** - Industry-leading activities
6. **Key Success Indicators** - How to know you've achieved each level
7. **Common Pitfalls** - What to avoid

### Step 3: Check Current Progress

If `.verifhai/progress.json` exists:
1. Load current level for this practice
2. Show user their status
3. Recommend starting level based on progress

```
**Current Status for {PRACTICE} ({Domain} domain):**

Level: {current_level}
Last Updated: {date}
Evidence: {count} artifacts

Recommendation: {Start at Level 1 / Continue with Level 2 / Work toward Level 3}
```

### Step 4: Present Domain-Specific Guidance

Based on the one-pager content, guide the user through activities:

```
## {PRACTICE}: {Practice Name} - {Domain} Domain

### Domain-Specific Context
{Extracted from one-pager}

### Your Current Level: {level}

### Activities for Level {target}

{Activities extracted from one-pager, customized for this domain}

**Step 1:** {Activity 1}
> {Prompt for user input or action}

**Step 2:** {Activity 2}
> {Prompt for user input or action}

**Step 3:** {Activity 3}
> {Prompt for user input or action}

### Success Indicators
To complete Level {target}, you need:
- [ ] {Indicator 1}
- [ ] {Indicator 2}
- [ ] {Indicator 3}

### Common Pitfalls to Avoid
- {Pitfall 1}
- {Pitfall 2}
```

### Step 5: Questionnaire Assessment (if available)

If questionnaire exists for this practice-domain combination:
1. Load questionnaire file
2. Ask Level 1 questions with evidence requirements
3. Only proceed to Level 2 if ALL Level 1 = Yes
4. Calculate score using HAIAMM methodology

```
## {PRACTICE}-{Domain} Assessment

### Level 1 Questions

**Q1:** {Question from questionnaire}
- Evidence required: {evidence type}
- [ ] Yes  [ ] No

**Q2:** {Question from questionnaire}
- Evidence required: {evidence type}
- [ ] Yes  [ ] No

{Continue for all L1 questions}

### Level 1 Score: {count_yes}/{total} = {percentage}%

{If all Yes, proceed to Level 2 questions}
```

### Step 6: Generate Domain-Specific Artifacts

Based on the practice and domain, help create appropriate artifacts:

| Practice | Domain | Typical Artifacts |
|----------|--------|-------------------|
| SR | Software | `docs/security/software-security-requirements.md` |
| SR | Data | `docs/security/data-security-requirements.md` |
| TA | Software | `docs/security/software-threat-model.md` |
| TA | Infrastructure | `docs/security/infrastructure-threat-model.md` |
| SA | Software | Architecture diagram with software security controls |
| SA | Infrastructure | Infrastructure security architecture |
| EH | Infrastructure | Infrastructure hardening runbook |
| EH | Endpoints | Endpoint security baseline |
| ML | Software | Application logging configuration |
| ML | Infrastructure | Infrastructure monitoring setup |

### Step 7: Update Progress

After completing activities:

1. Update `.verifhai/progress.json`:
   - Set practice level
   - Add domain context
   - Record evidence artifacts
   - Add session history

2. Display progress update:
```
**Progress Updated**

{PRACTICE} ({Domain}): Level {old} → Level {new}

**Evidence Recorded:**
- {artifact 1}
- {artifact 2}

**Next Steps:**
- {Recommendation for continuing}

Type `/verifhai status` to see full progress.
```

---

## Domain Reference

### Software Domain
Focus: AI applications, models, code, APIs
Key Concerns: Code vulnerabilities, model security, API security, prompt injection
Technologies: SAST, DAST, code review, secure coding

### Data Domain
Focus: Training data, operational data, privacy
Key Concerns: Data classification, privacy, compliance, data poisoning
Technologies: DLP, data classification, encryption, anonymization

### Infrastructure Domain
Focus: Cloud/on-prem hosting, networking
Key Concerns: Configuration security, network segmentation, access control
Technologies: CSPM, IaC security, container security

### Vendors Domain
Focus: Third-party AI services, supply chain
Key Concerns: Vendor risk, SBOM, supply chain security
Technologies: Vendor assessment, contract review, SLA monitoring

### Processes Domain
Focus: Business workflows, governance, operations
Key Concerns: Human oversight, approval workflows, incident response
Technologies: SOAR, workflow automation, GRC

### Endpoints Domain
Focus: User interfaces, client applications
Key Concerns: Input validation, output sanitization, client security
Technologies: EDR, browser security, mobile security

---

## Example Interaction

```
User: /verifhai practice ta infrastructure

Verifhai: Loading TA-Infrastructure-OnePager.md...

## Threat Assessment: Infrastructure Domain

### Domain-Specific Context
Infrastructure threat assessment focuses on cloud and network security
risks for your AI deployment environment.

**Key Threats for Infrastructure:**
- Cloud misconfiguration exposing AI endpoints
- Network-level attacks on model inference
- Container escape from AI workloads
- Supply chain compromise of AI dependencies

### Your Current Level: Not Started

### Activities for Level 1

**Step 1: Inventory AI Infrastructure**
> List all infrastructure components hosting your AI:
> - Cloud provider(s) and regions
> - Compute resources (VMs, containers, serverless)
> - Network topology
> - Storage locations

[User provides inventory]

**Step 2: Identify Infrastructure-Specific Threats**
Using STRIDE for infrastructure:
- **Spoofing:** Can attackers impersonate AI services?
- **Tampering:** Can infrastructure configs be modified?
- **Repudiation:** Are infrastructure changes logged?
- **Information Disclosure:** Can network traffic expose AI data?
- **Denial of Service:** Can AI infrastructure be overwhelmed?
- **Elevation:** Can container escape occur?

[Interactive threat identification]

**Step 3: Document Infrastructure Threat Model**
I'll help you create: docs/security/infrastructure-threat-model.md

### Success Indicators for Level 1
- [ ] AI infrastructure inventory documented
- [ ] STRIDE analysis for infrastructure complete
- [ ] Infrastructure threat model documented
- [ ] Key risks prioritized

Ready to begin? Let's start with Step 1.
```

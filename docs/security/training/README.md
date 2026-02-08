# HAI Security Education & Guidance Curriculum

A comprehensive training curriculum for building and maintaining secure Human-Assisted Intelligence (HAI) systems, based on the **HAIAMM Framework**.

## Curriculum Overview

| Module | Primary Audience | L1 Duration | Total Questions |
|--------|------------------|-------------|-----------------|
| [Core: HAI Fundamentals](./00-core-module-hai-fundamentals.md) | All | 30 min | 35 |
| [Software Domain](./01-software-domain.md) | Developers, AppSec | 1 hour | 37 |
| [Data Domain](./02-data-domain.md) | Privacy, Compliance | 1.5 hours | 37 |
| [Infrastructure Domain](./03-infrastructure-domain.md) | Cloud Security, SRE | 1 hour | 35 |
| [Vendors Domain](./04-vendors-domain.md) | Procurement, Legal | 1 hour | 35 |
| [Processes Domain](./05-processes-domain.md) | SOC, Security Ops | 1 hour | 30 |
| [Endpoints Domain](./06-endpoints-domain.md) | All Employees | 45 min | 28 |

**Total: 237 assessment questions across 7 modules + hands-on labs**

### Labs

| Lab | Primary Audience | Duration | Questions |
|-----|------------------|----------|-----------|
| [JWT Security for Python Developers](./lab-jwt-security.md) | Python Developers, AppSec | L1: 1h, L2: 2h, L3: 3h | 28 |
| [SSO & SAML Security for Python Developers](./lab-sso-saml-security.md) | Python Developers, AppSec, Identity Engineers | L1: 1h, L2: 2h, L3: 3h | 28 |

### Video Scripts

| Series | Episodes | Total Runtime | Lab Module |
|--------|----------|---------------|------------|
| [JWT Security Video Scripts](./lab-jwt-security-video-scripts.md) | 8 episodes | ~80 min | EG-LAB-JWT-001 |
| [SSO & SAML Security Video Scripts](./lab-sso-saml-security-video-scripts.md) | 10 episodes | ~95 min | EG-LAB-SAML-001 |

---

## Maturity Progression

Each module follows a **Crawl → Walk → Run** progression:

| Level | Focus | Learning Style | Assessment |
|-------|-------|----------------|------------|
| **L1: Crawl** | Foundational awareness | Concepts, definitions | Multiple choice |
| **L2: Walk** | Role-based competency | Hands-on scenarios | Scenario-based |
| **L3: Run** | Leadership & innovation | Advanced concepts | Practical exercises |

---

## Learning Paths

### Path 1: All Employees
**Duration:** ~2 hours
```
Core Module (L1) → Endpoints Domain (L1)
```

### Path 2: Developers
**Duration:** ~6 hours
```
Core Module (L1-L2) → Software Domain (L1-L2) → Vendors Domain (L1)
```

### Path 3: Security Team
**Duration:** ~12 hours
```
Core Module (L1-L3) → Software Domain (L1-L2) → Infrastructure Domain (L1-L2)
→ Processes Domain (L1-L2) → Vendors Domain (L1)
```

### Path 4: Privacy/Compliance
**Duration:** ~8 hours
```
Core Module (L1-L2) → Data Domain (L1-L3) → Vendors Domain (L1-L2)
```

### Path 5: Security Champions
**Duration:** ~10 hours
```
Core Module (L1-L2) → [Relevant Domain L1-L2] → Endpoints Domain (L1-L3)
```

---

## Module Contents

### Core Module: HAI Security Fundamentals
The foundation everyone needs - understand AI-specific threats and human-AI collaboration.

**Key Topics:**
- What is HAI and why it needs different security
- The 4 AI-specific threats (EA, AGH, TM, RA)
- Human-AI collaboration patterns
- Defense in depth for AI systems

**Files:**
- [Content](./00-core-module-hai-fundamentals.md)
- [Assessments](./00-core-module-assessments.md)

---

### Software Domain
Secure coding practices when building with AI assistance.

**Key Topics:**
- Secure coding fundamentals with AI
- Prompt injection defenses
- Secure tool implementation
- AI security tools (SAST/DAST/SCA)
- Security Champions program

**Files:**
- [Content](./01-software-domain.md)
- [Assessments](./01-software-domain-assessments.md)

---

### Data Domain
Privacy and data protection for AI systems.

**Key Topics:**
- GDPR/CCPA/HIPAA for AI
- Data classification
- AI-specific data risks
- DPIAs for AI systems
- Privacy-Enhancing Technologies (PETs)

**Files:**
- [Content](./02-data-domain.md)
- [Assessments](./02-data-domain-assessments.md)

---

### Infrastructure Domain
AI-driven cloud and infrastructure security.

**Key Topics:**
- CSPM/CNAPP tools
- Human-AI collaboration for infra security
- IaC security scanning
- Secure AI hosting architecture
- Zero Trust for AI workloads

**Files:**
- [Content](./03-infrastructure-domain.md)
- [Assessments](./03-infrastructure-domain-assessments.md)

---

### Vendors Domain
Third-party and supply chain security.

**Key Topics:**
- Vendor risk categories
- AI-assisted vendor assessment
- SBOM analysis
- Contract security requirements
- SLSA and software supply chain

**Files:**
- [Content](./04-vendors-domain.md)
- [Assessments](./04-vendors-domain-assessments.md)

---

### Processes Domain
AI-automated security operations.

**Key Topics:**
- SOAR and security automation
- Human-AI process collaboration
- Quality assurance for AI processes
- ITIL integration
- Process optimization and ROI

**Files:**
- [Content](./05-processes-domain.md)
- [Assessments](./05-processes-domain-assessments.md)

---

### Endpoints Domain
User security awareness with AI protection.

**Key Topics:**
- AI endpoint protection awareness
- Threat recognition (phishing, social engineering)
- Responding to AI security actions
- Privacy transparency
- Security culture and champions

**Files:**
- [Content](./06-endpoints-domain.md)
- [Assessments](./06-endpoints-domain-assessments.md)

---

## Assessment Summary

### Question Counts by Module and Level

| Module | L1 | L2 | L3 | Total |
|--------|----|----|----|----|
| Core | 10 | 15 | 10 | 35 |
| Software | 12 | 15 | 10 | 37 |
| Data | 12 | 15 | 10 | 37 |
| Infrastructure | 10 | 15 | 10 | 35 |
| Vendors | 10 | 15 | 10 | 35 |
| Processes | 10 | 12 | 8 | 30 |
| Endpoints | 10 | 10 | 8 | 28 |
| **Total** | **74** | **97** | **66** | **237** |

### Passing Requirements

- **L1**: 80% on multiple choice questions
- **L2**: 80% on scenario-based questions
- **L3**: 80% on advanced questions + passing practical exercise

---

## Implementation Guide

### Rolling Out Training

**Phase 1: Awareness (Month 1)**
- Deploy Core Module L1 to all employees
- Deploy Endpoints Domain L1 to all employees

**Phase 2: Role-Based (Months 2-3)**
- Deploy relevant domain L1-L2 to specific roles
- Developers → Software Domain
- Security → Infrastructure, Processes Domains
- Privacy → Data Domain
- Procurement → Vendors Domain

**Phase 3: Advanced (Months 4+)**
- L3 content for Security Champions
- L3 for security team members
- Continuous learning and updates

### Tracking Progress

Use your LMS or create tracking in `.verifhai/progress.json`:

```json
{
  "user_id": "example",
  "modules_completed": {
    "core": {"l1": true, "l2": true, "l3": false},
    "software": {"l1": true, "l2": false, "l3": false}
  },
  "assessment_scores": {
    "core_l1": 90,
    "core_l2": 85
  },
  "last_updated": "2025-02-05"
}
```

---

## Related Resources

### HAIAMM Framework
- [HAIAMM Handbook](/Users/kuaihinojosa/projects/HAIAMM/docs/HAIAMM-Handbook.md)
- [Practice One-Pagers](/Users/kuaihinojosa/projects/HAIAMM/docs/practices/)

### Verifhai Tools
- `/verifhai assess` - Quick maturity assessment
- `/verifhai practice [id]` - Work on specific practices
- `/verifhai review` - Security code review
- `/verifhai status` - Check progress

---

## Contributing

To improve this curriculum:
1. Submit issues for errors or gaps
2. Propose new scenarios or questions
3. Share implementation experiences
4. Contribute translations

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-02 | Initial release - 7 modules, 237 questions |

---

**Framework:** HAIAMM v2.0
**Practice:** Education & Guidance (EG)
**Author:** Verifhai

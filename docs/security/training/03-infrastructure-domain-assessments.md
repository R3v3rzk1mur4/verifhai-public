# Infrastructure Domain: AI-Driven Infrastructure Security - Assessments

## Assessment Overview

| Level | Questions | Passing Score | Format |
|-------|-----------|---------------|--------|
| L1 | 10 questions | 80% (8/10) | Multiple choice |
| L2 | 15 questions | 80% (12/15) | Multiple choice + scenario |
| L3 | 10 questions + practical | 80% + practical pass | Scenario + architecture design |

---

## Level 1 Assessment: AI Infrastructure Security Basics

### Instructions
- 10 multiple choice questions
- 80% passing score required (8/10 correct)
- Time limit: 15 minutes

---

### Questions

**Q1. What does CSPM stand for in cloud security?**

- A) Cloud Security Policy Management
- B) Cloud Security Posture Management ✓
- C) Cloud System Performance Monitoring
- D) Centralized Security Platform Management

**Explanation:** CSPM (Cloud Security Posture Management) tools continuously monitor cloud configurations to detect security misconfigurations.

---

**Q2. In the human-AI collaboration model, what is "Level 2" collaboration?**

- A) AI detects and humans investigate
- B) AI recommends actions and humans approve before execution ✓
- C) AI automates everything without human involvement
- D) Humans do everything without AI

**Explanation:** Level 2 is AI-recommends-human-approves: AI proposes remediation actions, but humans review and approve before execution.

---

**Q3. What is the primary limitation of AI infrastructure security tools that requires human oversight?**

- A) AI tools are too slow
- B) AI tools are too expensive
- C) AI tools may lack business context and produce false positives ✓
- D) AI tools don't work in the cloud

**Explanation:** AI tools may not understand business context, leading to false positives or missing nuanced risks that humans can evaluate.

---

**Q4. When securing infrastructure that hosts AI systems, what is the first network security control to implement?**

- A) Faster internet connections
- B) Private endpoints with no public IP addresses ✓
- C) Larger security groups
- D) More logging

**Explanation:** AI systems should not be directly exposed to the internet; use private endpoints and access through API gateways.

---

**Q5. What should you do when you receive a CSPM alert about a publicly accessible S3 bucket?**

- A) Ignore it - S3 buckets are meant to be public
- B) Delete the entire bucket immediately
- C) Validate the finding, assess risk, and restrict access if it shouldn't be public ✓
- D) Wait for someone else to fix it

**Explanation:** Triage alerts by validating the finding, assessing actual risk, and taking appropriate remediation action.

---

**Q6. What is IaC security scanning?**

- A) Scanning physical infrastructure
- B) Analyzing Infrastructure-as-Code files for security issues before deployment ✓
- C) Scanning the internet for infrastructure
- D) Backing up infrastructure configurations

**Explanation:** IaC security scanning (using tools like tfsec, Checkov) finds security issues in Terraform, CloudFormation, etc. before they're deployed.

---

**Q7. Which human-AI collaboration level is appropriate for auto-remediating a non-encrypted S3 bucket in a non-production environment?**

- A) Level 1 - AI assists only
- B) Level 3 - AI automates low-risk scenarios ✓
- C) Level 4 - Never automate
- D) No AI involvement needed

**Explanation:** Enabling encryption on a non-production S3 bucket is low-risk and easily reversible, making it suitable for automation.

---

**Q8. What is the purpose of egress filtering for AI infrastructure?**

- A) To make AI faster
- B) To ensure AI can only communicate with approved destinations ✓
- C) To increase AI accuracy
- D) To reduce AI costs

**Explanation:** Egress filtering restricts what the AI can connect to, preventing data exfiltration or malicious communication.

---

**Q9. When should you escalate an AI infrastructure security alert to incident response?**

- A) For every alert
- B) Only for alerts about cost
- C) When there is evidence of active exploitation or critical production impact ✓
- D) Never - AI handles everything

**Explanation:** Escalate when there's active exploitation, critical production impact, or situations beyond normal remediation.

---

**Q10. What is a key security requirement for AI model files in cloud infrastructure?**

- A) They should be publicly accessible for sharing
- B) They should be encrypted at rest with access controls ✓
- C) They should be stored in temporary storage
- D) They don't need any special protection

**Explanation:** AI models are valuable assets requiring encryption at rest and strict access controls to prevent theft or tampering.

---

## Level 2 Assessment: AI Infrastructure Security Operations

### Instructions
- 15 questions (10 multiple choice + 5 scenario-based)
- 80% passing score required (12/15 correct)
- Time limit: 30 minutes

---

### Multiple Choice Questions (1-10)

**Q1. What is the purpose of "false positive suppression" in CSPM configuration?**

- A) To hide all security findings
- B) To document and exclude known non-issues with proper justification ✓
- C) To make dashboards look better
- D) To disable the CSPM tool

**Explanation:** False positive suppression allows documenting legitimate exceptions while maintaining visibility of real issues.

---

**Q2. In an IaC security pipeline, when should security scans run?**

- A) Only in production
- B) Pre-commit and in CI/CD pipeline before deployment ✓
- C) Only once a year
- D) After deployment to production

**Explanation:** Shift-left security: scan at pre-commit for immediate feedback and in CI/CD before deployment to production.

---

**Q3. What is a "Tier 2" automation in the automation governance framework?**

- A) No automation allowed
- B) Auto-remediate with notification to team ✓
- C) Human approval required
- D) Emergency response only

**Explanation:** Tier 2 allows auto-remediation of medium-risk issues with notification so teams are aware of automated changes.

---

**Q4. What should an infrastructure security runbook include?**

- A) Only the problem description
- B) Trigger, investigation steps, remediation options, verification, and escalation paths ✓
- C) Only contact information
- D) Marketing materials

**Explanation:** Runbooks should be comprehensive: triggering conditions, how to investigate, remediation options, verification steps, and when to escalate.

---

**Q5. What is "configuration drift" in cloud infrastructure?**

- A) Clouds moving to different data centers
- B) Actual infrastructure state diverging from defined/expected configuration ✓
- C) Performance degradation over time
- D) Cost increases

**Explanation:** Drift occurs when actual configurations differ from IaC definitions, potentially introducing security issues.

---

**Q6. Which IaC security finding should block deployment?**

- A) Missing optional tags
- B) IAM policy with "Action": "*" allowing all actions ✓
- C) Using a slightly outdated AMI
- D) Resource naming convention issues

**Explanation:** Overly permissive IAM policies are high-severity security issues that should block deployment.

---

**Q7. What is the purpose of "policy-as-code" (e.g., OPA/Rego)?**

- A) To write better documentation
- B) To define and enforce security policies programmatically in CI/CD ✓
- C) To generate code automatically
- D) To create backups

**Explanation:** Policy-as-code enables automated enforcement of security policies during the deployment pipeline.

---

**Q8. When tuning CSPM to reduce alert fatigue, what is the WRONG approach?**

- A) Suppress known false positives with documentation
- B) Prioritize by exploitability
- C) Disable all alerts to reduce noise ✓
- D) Establish baselines and alert on deviations

**Explanation:** Disabling all alerts eliminates visibility into real issues. Proper tuning maintains security while reducing noise.

---

**Q9. What is the benefit of integrating CSPM with a SIEM?**

- A) Reduces CSPM costs
- B) Enables correlation of infrastructure findings with other security events ✓
- C) Makes CSPM faster
- D) Eliminates need for human review

**Explanation:** SIEM integration allows correlation of CSPM findings with other events for better threat detection and investigation.

---

**Q10. In the cloud security reference architecture, what is the purpose of the API Gateway layer?**

- A) To make the AI faster
- B) To provide authentication, rate limiting, and request validation before traffic reaches AI services ✓
- C) To store AI models
- D) To replace the AI system

**Explanation:** API Gateway provides security controls (auth, rate limiting, validation) as a security perimeter for AI services.

---

### Scenario-Based Questions (11-15)

**Scenario A:** Your CSPM tool reports: "Critical: EC2 instance i-abc123 has security group allowing SSH (port 22) from 0.0.0.0/0." The instance is in your production VPC and hosts an AI inference service.

**Q11. What is the first step in responding to this alert?**

- A) Immediately delete the instance
- B) Validate the finding and assess if SSH access from anywhere is actually needed ✓
- C) Ignore it because production is important
- D) Add more open ports

**Explanation:** First validate the finding is accurate and assess if this exposure is intentional or a misconfiguration.

---

**Q12. If the open SSH is confirmed as a misconfiguration, what is the appropriate remediation?**

- A) Leave it open for convenience
- B) Restrict the security group to allow SSH only from known management IPs or bastion hosts ✓
- C) Delete the entire security group
- D) Open more ports to balance the risk

**Explanation:** Restrict SSH to specific trusted IPs (management network, bastion) rather than the entire internet.

---

**Scenario B:** Your team is configuring automation for CSPM findings. A new engineer proposes auto-remediating all IAM policy findings by removing the flagged permissions.

**Q13. What is the problem with auto-remediating all IAM policy findings?**

- A) It's too slow
- B) Removing permissions without context could break production applications and services ✓
- C) IAM doesn't support automation
- D) It's too expensive

**Explanation:** IAM changes are high-risk; auto-removing permissions could disrupt services that legitimately need them.

---

**Q14. What automation tier should IAM policy modifications be assigned to?**

- A) Tier 1 - Auto-remediate
- B) Tier 2 - Auto-remediate with notification
- C) Tier 3 - Recommend only, human approval required ✓
- D) Fully automated with no oversight

**Explanation:** IAM changes are high-risk and require human review to understand business context before modification.

---

**Scenario C:** Your IaC security scanner flags this Terraform code:

```hcl
resource "aws_s3_bucket" "data" {
  bucket = "my-ai-training-data"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
```

**Q15. Why is this configuration a security concern?**

- A) The bucket name is too long
- B) All public access block settings are disabled, allowing the bucket to be made public ✓
- C) The bucket should use a different region
- D) Terraform is not secure

**Explanation:** All public access block settings are `false`, meaning the bucket can be configured for public access - a common data exposure risk.

---

## Level 3 Assessment: Infrastructure Security Leadership

### Instructions
- 10 scenario-based questions + 1 practical exercise
- 80% on written questions (8/10) + practical pass required
- Time limit: 45 minutes for written, 45 minutes for practical

---

### Scenario-Based Questions (1-10)

**Q1. What is the core principle of Zero Trust architecture for AI infrastructure?**

- A) Trust everything inside the network
- B) Never trust, always verify - authenticate and authorize every access ✓
- C) Trust all AI systems automatically
- D) Disable all security to simplify operations

**Explanation:** Zero Trust assumes no implicit trust; every access must be authenticated and authorized regardless of location.

---

**Q2. What is "micro-segmentation" in Zero Trust AI infrastructure?**

- A) Making AI systems smaller
- B) Isolating workloads with explicit allow rules, inspecting east-west traffic ✓
- C) Segmenting the marketing team
- D) Dividing data into small pieces

**Explanation:** Micro-segmentation isolates workloads from each other with explicit rules, limiting blast radius if one is compromised.

---

**Q3. What is "confidential computing" for AI workloads?**

- A) Keeping AI work secret from management
- B) Using hardware-based security (TEEs) to protect data even while being processed ✓
- C) Encrypting AI marketing materials
- D) Making AI work confidentially with customers

**Explanation:** Confidential computing uses Trusted Execution Environments (TEEs) to protect data during processing, not just at rest.

---

**Q4. What metric measures the percentage of security findings remediated automatically?**

- A) MTTR
- B) Automation Rate ✓
- C) False Positive Rate
- D) Coverage

**Explanation:** Automation Rate measures what percentage of eligible findings are auto-remediated vs. requiring manual action.

---

**Q5. What is the target for "Critical Findings MTTR" in a mature infrastructure security program?**

- A) Less than 24 hours ✓
- B) Within 30 days
- C) Within 90 days
- D) No target needed

**Explanation:** Critical findings should be remediated within 24 hours due to high risk of exploitation.

---

**Scenario D:** Your organization is designing infrastructure for a new AI system that will process sensitive customer financial data. You need to recommend the security architecture.

**Q6. Which architecture pattern is MOST appropriate for this scenario?**

- A) Public cloud with default settings
- B) Zero Trust architecture with confidential computing for sensitive processing ✓
- C) On-premises only with no cloud
- D) Public endpoints for easy access

**Explanation:** Sensitive financial data requires Zero Trust (verify every access) and potentially confidential computing for data-in-use protection.

---

**Q7. What network control is essential for this sensitive AI system?**

- A) Public IP for easy access
- B) Private endpoints with API gateway, egress filtering, and east-west traffic inspection ✓
- C) Open security groups for flexibility
- D) No network controls needed with encryption

**Explanation:** Sensitive systems need private endpoints, controlled ingress (API gateway), filtered egress, and internal traffic inspection.

---

**Scenario E:** Your infrastructure security metrics show: Critical Findings: 3, Auto-Remediation Rate: 68%, False Positive Rate: 12%, IaC Coverage: 92%.

**Q8. Which metric indicates the highest priority issue?**

- A) Auto-Remediation Rate at 68%
- B) Critical Findings at 3 - these need immediate attention ✓
- C) False Positive Rate at 12%
- D) IaC Coverage at 92%

**Explanation:** Any critical findings represent immediate risk and should be prioritized over process improvements.

---

**Q9. What industry contribution demonstrates infrastructure security thought leadership?**

- A) Keeping all security practices secret
- B) Contributing to CIS Benchmarks, publishing secure architectures, speaking at conferences ✓
- C) Using only proprietary tools
- D) Avoiding all industry collaboration

**Explanation:** Thought leadership involves contributing to standards (CIS), sharing knowledge, and participating in industry forums.

---

**Q10. What is the purpose of participating in cloud vendor security programs?**

- A) To get free cloud credits
- B) To provide feedback that improves native security features and learn best practices ✓
- C) To complain about pricing
- D) To avoid security responsibility

**Explanation:** Engaging with cloud vendor security programs helps improve cloud security features and provides learning opportunities.

---

### Practical Exercise: AI Infrastructure Security Architecture

**Exercise:** Design a secure infrastructure architecture for the following AI system:

> **System:** AI-Powered Document Processing Platform
>
> **Requirements:**
> - Process customer documents (contracts, invoices, legal documents)
> - Extract and summarize key information using LLM
> - Store processed results for customer access
> - Handle PII (names, addresses, account numbers)
> - Serve 1000+ enterprise customers
> - Compliance: SOC 2, GDPR
>
> **Current State:**
> - AWS cloud environment
> - Existing VPC with public and private subnets
> - No current AI workloads

**Deliverables (45 minutes):**

1. **Architecture Diagram** (15 points)
   - Network layout (VPCs, subnets, security groups)
   - Compute (where AI workloads run)
   - Data storage (documents, models, results)
   - Access paths (customer access, admin access)
   - Security controls placement

2. **Security Controls Specification** (15 points)
   - Network security (segmentation, firewalls, WAF)
   - Identity and access (authentication, authorization)
   - Data protection (encryption, key management)
   - AI-specific controls (rate limiting, input/output validation)

3. **Monitoring and Detection** (10 points)
   - CSPM/CNAPP integration
   - Logging requirements
   - Alerting strategy
   - Incident response triggers

4. **Automation Strategy** (10 points)
   - What should be automated (tier classification)
   - Approval workflows for high-risk changes
   - IaC security pipeline

5. **Compliance Mapping** (10 points)
   - SOC 2 control coverage
   - GDPR data protection measures
   - Audit logging requirements

6. **Risk Assessment** (10 points)
   - Top 5 infrastructure security risks
   - Mitigations for each risk
   - Residual risk acceptance

7. **Implementation Roadmap** (5 points)
   - Phased approach
   - Quick wins
   - Dependencies

**Passing Criteria:**
- Architecture demonstrates defense-in-depth
- Network segmentation isolates AI workloads appropriately
- Data protection addresses PII requirements
- AI-specific controls are included
- Monitoring provides visibility into security posture
- Automation is risk-appropriate
- Compliance requirements are addressed
- Risks are identified with practical mitigations

---

## Answer Key Summary

### L1 Answers
1-B, 2-B, 3-C, 4-B, 5-C, 6-B, 7-B, 8-B, 9-C, 10-B

### L2 Answers
1-B, 2-B, 3-B, 4-B, 5-B, 6-B, 7-B, 8-C, 9-B, 10-B, 11-B, 12-B, 13-B, 14-C, 15-B

### L3 Answers
1-B, 2-B, 3-B, 4-B, 5-A, 6-B, 7-B, 8-B, 9-B, 10-B
Practical: Rubric-based evaluation

---

**Document Version:** 1.0
**Framework:** HAIAMM v2.0
**Practice:** Education & Guidance (EG)
**Domain:** Infrastructure
**Author:** Verifhai

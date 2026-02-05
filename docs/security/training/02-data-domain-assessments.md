# Data Domain: Privacy & Data Security with AI - Assessments

## Assessment Overview

| Level | Questions | Passing Score | Format |
|-------|-----------|---------------|--------|
| L1 | 12 questions | 80% (10/12) | Multiple choice |
| L2 | 15 questions | 80% (12/15) | Multiple choice + scenario |
| L3 | 10 questions + practical | 80% + practical pass | Scenario + DPIA exercise |

---

## Level 1 Assessment: Privacy & Data Security Fundamentals

### Instructions
- 12 multiple choice questions
- 80% passing score required (10/12 correct)
- Time limit: 20 minutes

---

### Questions

**Q1. Under GDPR, what is the maximum time allowed to respond to a Data Subject Access Request (DSAR)?**

- A) 72 hours
- B) 7 days
- C) 30 days (extendable to 90 in complex cases) ✓
- D) 90 days

**Explanation:** GDPR Article 12 requires response within one month (30 days), extendable by two additional months for complex requests.

---

**Q2. Which GDPR principle requires organizations to only collect personal data that is necessary for the specified purpose?**

- A) Accuracy
- B) Data Minimization ✓
- C) Storage Limitation
- D) Accountability

**Explanation:** Data Minimization (Article 5(1)(c)) requires that personal data shall be adequate, relevant, and limited to what is necessary.

---

**Q3. What type of data is "Protected Health Information (PHI)"?**

- A) Any information about health
- B) Health information that can identify an individual, protected under HIPAA ✓
- C) Public health statistics
- D) Information about healthy foods

**Explanation:** PHI under HIPAA includes individually identifiable health information held by covered entities.

---

**Q4. Which AI-specific data risk involves the AI revealing personal data it learned during training?**

- A) Over-collection
- B) Training data extraction ✓
- C) Unauthorized profiling
- D) Cross-context use

**Explanation:** Training data extraction occurs when AI can be prompted to reveal memorized personal data from its training set.

---

**Q5. Under GDPR Article 22, what right do data subjects have regarding automated decision-making?**

- A) The right to free AI services
- B) The right not to be subject to solely automated decisions that significantly affect them, and to request human review ✓
- C) The right to have AI make all decisions
- D) No specific rights

**Explanation:** Article 22 gives data subjects the right to not be subject to solely automated decisions with significant effects, plus rights to human intervention, explanation, and contest.

---

**Q6. What classification level would typically apply to Social Security Numbers?**

- A) Public
- B) Internal
- C) Confidential
- D) Restricted ✓

**Explanation:** SSNs are sensitive PII requiring the highest protection level (Restricted) due to identity theft risk.

---

**Q7. Which lawful basis under GDPR Article 6 would typically apply to an AI fraud detection system?**

- A) Consent
- B) Contract
- C) Legitimate Interests ✓
- D) Vital Interests

**Explanation:** Fraud detection typically relies on legitimate interests, with a balancing test against data subject rights.

---

**Q8. What is the GDPR breach notification deadline to supervisory authorities?**

- A) 24 hours
- B) 72 hours ✓
- C) 7 days
- D) 30 days

**Explanation:** GDPR Article 33 requires notification to the supervisory authority within 72 hours of becoming aware of a breach.

---

**Q9. When an AI chatbot asks a customer for their full medical history to answer a simple product question, this violates which privacy principle?**

- A) Accuracy
- B) Data Minimization ✓
- C) Storage Limitation
- D) Integrity

**Explanation:** Collecting medical history for a product question violates data minimization - collecting more than necessary for the purpose.

---

**Q10. What is "PII" in data privacy context?**

- A) Privacy Information Index
- B) Personally Identifiable Information ✓
- C) Private Internet Interface
- D) Protected Information Infrastructure

**Explanation:** PII (Personally Identifiable Information) is any information that can identify an individual.

---

**Q11. Under the CCPA, what right allows California residents to tell businesses not to sell their personal information?**

- A) Right to Delete
- B) Right to Know
- C) Right to Opt-Out of Sale ✓
- D) Right to Portability

**Explanation:** CCPA gives California residents the right to opt out of the sale of their personal information.

---

**Q12. Which of the following is a GDPR "special category" of data requiring additional protection?**

- A) Email address
- B) Phone number
- C) Health data ✓
- D) Job title

**Explanation:** GDPR Article 9 identifies special categories including health data, biometrics, race, religion, and sexual orientation.

---

## Level 2 Assessment: Privacy Compliance Operations

### Instructions
- 15 questions (10 multiple choice + 5 scenario-based)
- 80% passing score required (12/15 correct)
- Time limit: 35 minutes

---

### Multiple Choice Questions (1-10)

**Q1. When is a Data Protection Impact Assessment (DPIA) required under GDPR?**

- A) For all data processing
- B) When processing is likely to result in high risk to individuals, including systematic profiling and new technologies like AI ✓
- C) Only for marketing activities
- D) Only when requested by regulators

**Explanation:** GDPR Article 35 requires DPIAs for processing likely to result in high risk, including profiling, large-scale sensitive data, and new technologies.

---

**Q2. What are "Complementary User Entity Controls" (CUECs) in the context of AI vendor privacy compliance?**

- A) Controls the vendor implements
- B) Controls the customer must implement for the vendor's privacy controls to be effective ✓
- C) Optional privacy enhancements
- D) Regulatory requirements

**Explanation:** CUECs are controls the customer organization must implement on their side for the overall privacy control environment to be effective.

---

**Q3. When handling a DSAR for data processed by an AI system, what MUST be included in the response?**

- A) Only database records
- B) Database records, AI conversation logs, AI-generated profiles/inferences, and meaningful information about AI logic ✓
- C) Only the user's name
- D) A link to the privacy policy

**Explanation:** DSAR responses must include all personal data, including AI-processed data, inferences, and explanation of automated decision-making logic.

---

**Q4. What is the primary purpose of data classification in AI systems?**

- A) To make data easier to search
- B) To identify data sensitivity and apply appropriate protection controls ✓
- C) To reduce storage costs
- D) To improve AI accuracy

**Explanation:** Data classification identifies sensitivity levels to ensure appropriate security and privacy controls are applied.

---

**Q5. In privacy incident response, what is the first step after detecting a potential breach?**

- A) Notify all customers
- B) Contain the incident to prevent further exposure ✓
- C) Delete all evidence
- D) Issue a press release

**Explanation:** Containment comes first to stop ongoing data exposure before assessment and notification.

---

**Q6. What does "Privacy by Design" mean for AI systems?**

- A) Design a privacy-focused user interface
- B) Build privacy protections into AI systems from the design phase, not as an afterthought ✓
- C) Only process public data
- D) Get privacy certification

**Explanation:** Privacy by Design means integrating privacy considerations into system architecture from the beginning.

---

**Q7. When configuring AI-powered DLP, what should you do if the system has a high false positive rate?**

- A) Disable DLP entirely
- B) Ignore all findings
- C) Tune detection rules, start in monitoring mode, and gradually refine based on review ✓
- D) Accept all data may be blocked

**Explanation:** DLP should be tuned incrementally, starting in monitoring mode to understand false positive patterns before blocking.

---

**Q8. What is the purpose of pseudonymization in AI data processing?**

- A) Delete personal data
- B) Replace identifying information with pseudonyms while retaining data utility, reducing risk ✓
- C) Encrypt data completely
- D) Make data public

**Explanation:** Pseudonymization reduces re-identification risk while keeping data useful for processing, analysis, or AI training.

---

**Q9. Under GDPR, when must data subjects be notified of a breach?**

- A) Always, for every breach
- B) When the breach is likely to result in high risk to their rights and freedoms ✓
- C) Only if regulators request it
- D) Never - only regulators are notified

**Explanation:** GDPR Article 34 requires data subject notification when a breach is likely to result in high risk to their rights and freedoms.

---

**Q10. What is "data minimization" in the context of AI prompts?**

- A) Using shorter prompts
- B) Only including personal data in prompts that is necessary for the AI task ✓
- C) Minimizing AI response length
- D) Using less training data

**Explanation:** Data minimization for AI prompts means not including unnecessary PII - only what the AI needs to perform the specific task.

---

### Scenario-Based Questions (11-15)

**Scenario A:** Your company's AI customer service chatbot logs all conversations including full customer details. A customer submits a DSAR requesting all their personal data. The logs contain:
- Full conversation history with the customer
- AI-generated sentiment analysis scores
- AI-generated "likely to churn" predictions
- Customer's credit card number (captured incorrectly during support)

**Q11. What MUST be included in the DSAR response for Scenario A?**

- A) Only the conversation history
- B) Conversation history, AI sentiment scores, churn predictions, and credit card number (with explanation of why CC was stored) ✓
- C) Only the credit card number
- D) Nothing - chatbot data is exempt

**Explanation:** All personal data must be provided, including AI-generated inferences about the individual. The unexpected CC storage should be addressed.

---

**Q12. What immediate action should be taken regarding the credit card storage in Scenario A?**

- A) Delete it without telling anyone
- B) Investigate how it was captured, assess if it's a breach, implement controls to prevent future capture ✓
- C) Continue storing it
- D) Add it to the customer profile

**Explanation:** Storing full CC numbers likely violates PCI-DSS and purpose limitation. Investigate, remediate, and prevent recurrence.

---

**Scenario B:** Your AI vendor announces they will begin using customer prompts and responses to improve their models. Your organization processes sensitive customer data through this AI.

**Q13. What is your first action regarding Scenario B?**

- A) Accept it as part of using AI services
- B) Review your contract and DPA to determine if this is permitted, and assess GDPR implications ✓
- C) Immediately stop all AI usage
- D) Ask customers to consent

**Explanation:** First, determine your contractual and legal position before taking action.

---

**Q14. If the vendor's use of data for training is NOT permitted under your agreement, what should you do?**

- A) Ignore it
- B) Formally object and require opt-out, or consider terminating the relationship if not addressed ✓
- C) Just accept it
- D) Report to police

**Explanation:** Exercise your contractual rights to object and require data not be used for training, or evaluate alternative vendors.

---

**Scenario C:** Your organization is implementing an AI system that will analyze employee communications to detect insider threats. You are conducting a DPIA.

**Q15. What is the PRIMARY privacy concern for the system in Scenario C?**

- A) The AI might not be accurate
- B) Systematic monitoring of employees creates significant privacy risks requiring strong justification and safeguards ✓
- C) The AI might be expensive
- D) Employees might not like it

**Explanation:** Employee monitoring AI involves systematic surveillance with significant privacy implications, requiring careful balancing of legitimate interests against employee rights.

---

## Level 3 Assessment: Privacy Leadership & Innovation

### Instructions
- 10 scenario-based questions + 1 practical exercise
- 80% on written questions (8/10) + practical pass required
- Time limit: 45 minutes for written, 45 minutes for practical

---

### Scenario-Based Questions (1-10)

**Q1. What is "differential privacy" in the context of AI?**

- A) Different privacy policies for different users
- B) A mathematical technique that adds calibrated noise to data/outputs to protect individual privacy while maintaining aggregate utility ✓
- C) Privacy that varies over time
- D) Privacy only for differential equations

**Explanation:** Differential privacy provides mathematical guarantees that individual records cannot be identified in AI outputs.

---

**Q2. How does federated learning enhance privacy for AI systems?**

- A) By encrypting all data
- B) By training AI on distributed data at edge devices without centralizing personal data ✓
- C) By deleting data after training
- D) By using only public data

**Explanation:** Federated learning keeps personal data on devices, only sharing model updates (not raw data) for aggregation.

---

**Q3. What is the "epsilon" parameter in differential privacy?**

- A) The encryption key
- B) The privacy budget - lower values mean more privacy but more noise ✓
- C) The data size
- D) The model accuracy

**Explanation:** Epsilon (ε) is the privacy budget; smaller epsilon = stronger privacy guarantees but more noise added to outputs.

---

**Q4. In a privacy community of practice, what is the role of "Privacy Champions"?**

- A) Full-time privacy lawyers
- B) Advocates who promote privacy awareness in their teams and escalate privacy concerns ✓
- C) External privacy consultants
- D) Regulatory inspectors

**Explanation:** Privacy Champions are embedded in teams to advocate for privacy, advise on implementations, and escalate concerns.

---

**Q5. What metric measures how quickly your organization responds to Data Subject Access Requests?**

- A) Privacy Incident Rate
- B) DSAR Response Time ✓
- C) Consent Rate
- D) DPIA Completion Rate

**Explanation:** DSAR Response Time tracks average time to fulfill data subject requests (target: faster than regulatory deadlines).

---

**Scenario D:** Your organization wants to use customer data to train an AI model that will personalize product recommendations. The data includes purchase history, browsing behavior, and demographic information.

**Q6. What privacy-enhancing technology would allow training while minimizing individual privacy risk?**

- A) Stronger passwords
- B) Differential privacy or federated learning to train without exposing individual records ✓
- C) Better firewalls
- D) Longer retention periods

**Explanation:** Differential privacy adds noise during training to prevent memorization of individual records; federated learning keeps data distributed.

---

**Q7. What must the DPIA for Scenario D's AI system specifically address?**

- A) Only technical security
- B) Necessity and proportionality, lawful basis, profiling implications, data subject rights, and safeguards ✓
- C) Only cost estimates
- D) Only accuracy metrics

**Explanation:** DPIAs for AI must address why the processing is necessary, legal basis, profiling impacts, data subject rights (including opt-out), and protective measures.

---

**Scenario E:** Your privacy program metrics show: DSAR Response Time: 18 days, DPIA Coverage: 100%, Privacy Incidents: 3 per quarter, PET Adoption: 45%.

**Q8. Which metric indicates the biggest opportunity for improvement in Scenario E?**

- A) DSAR Response Time (18 days is good)
- B) DPIA Coverage (100% is excellent)
- C) PET Adoption at 45% - privacy-enhancing technologies should be more widely used ✓
- D) Privacy Incidents (3 is acceptable)

**Explanation:** PET adoption at 45% suggests many AI systems aren't using privacy-enhancing technologies that could further reduce risk.

---

**Q9. What industry contribution demonstrates privacy thought leadership?**

- A) Keeping all privacy practices secret
- B) Publishing privacy implementation case studies, contributing to standards, speaking at privacy conferences ✓
- C) Having the largest privacy budget
- D) Processing the most personal data

**Explanation:** Thought leadership involves sharing knowledge through publications, standards development, and industry events.

---

**Q10. What is the purpose of "synthetic data" in privacy-preserving AI?**

- A) Data that is fake and useless
- B) AI-generated data with same statistical properties as real data, allowing AI development without real personal data ✓
- C) Data stored in synthetic materials
- D) Compressed data

**Explanation:** Synthetic data maintains statistical utility for AI training/testing while not containing actual personal information.

---

### Practical Exercise: DPIA for AI System

**Exercise:** Complete a Data Protection Impact Assessment for the following AI system:

> **System:** AI-Powered HR Analytics Platform
>
> **Capabilities:**
> - Analyze employee performance data
> - Predict employee attrition risk
> - Recommend compensation adjustments
> - Identify candidates for promotion
> - Detect potential policy violations
>
> **Data Processed:**
> - Employee performance reviews
> - Compensation history
> - Attendance records
> - Communication metadata (not content)
> - Demographic information
>
> **Users:** HR team, department managers
> **Jurisdiction:** EU (GDPR applies)

**Deliverables (45 minutes):**

1. **Processing Description** (10 points)
   - Nature, scope, context, and purposes
   - Data flows and retention

2. **Necessity and Proportionality** (10 points)
   - Lawful basis analysis
   - Purpose limitation assessment
   - Data minimization evaluation

3. **AI-Specific Considerations** (15 points)
   - Automated decision-making analysis (Article 22)
   - Profiling implications
   - Transparency and explainability
   - Human oversight mechanisms

4. **Risk Assessment** (15 points)
   - Identify at least 5 privacy risks
   - Assess likelihood and severity
   - Consider employee rights impact

5. **Mitigation Measures** (10 points)
   - Propose controls for each identified risk
   - Include technical and organizational measures
   - Address AI-specific risks

6. **Data Subject Rights** (10 points)
   - How will employees exercise their rights?
   - Right to object to profiling
   - Right to human review of AI decisions

7. **Recommendation** (5 points)
   - Approve/Approve with conditions/Not approve
   - Key conditions if applicable
   - Review schedule

**Passing Criteria:**
- Processing description is complete and accurate
- Lawful basis analysis is correct (legitimate interests with balancing test, or other appropriate basis)
- AI-specific considerations address Article 22 implications
- At least 5 material privacy risks identified
- Mitigation measures directly address risks
- Data subject rights mechanism is practical
- Recommendation is justified by analysis

---

## Answer Key Summary

### L1 Answers
1-C, 2-B, 3-B, 4-B, 5-B, 6-D, 7-C, 8-B, 9-B, 10-B, 11-C, 12-C

### L2 Answers
1-B, 2-B, 3-B, 4-B, 5-B, 6-B, 7-C, 8-B, 9-B, 10-B, 11-B, 12-B, 13-B, 14-B, 15-B

### L3 Answers
1-B, 2-B, 3-B, 4-B, 5-B, 6-B, 7-B, 8-C, 9-B, 10-B
Practical: Rubric-based evaluation

---

**Document Version:** 1.0
**Framework:** HAIAMM v2.0
**Practice:** Education & Guidance (EG)
**Domain:** Data
**Author:** Verifhai

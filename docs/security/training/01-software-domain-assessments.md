# Software Domain: Secure Development with AI - Assessments

## Assessment Overview

| Level | Questions | Passing Score | Format |
|-------|-----------|---------------|--------|
| L1 | 12 questions | 80% (10/12) | Multiple choice + code review |
| L2 | 15 questions | 80% (12/15) | Scenario + code analysis |
| L3 | 10 questions + practical | 80% + practical pass | Advanced scenarios + threat model |

---

## Level 1 Assessment: Secure Coding Basics with AI

### Instructions
- 12 questions (8 multiple choice + 4 code review)
- 80% passing score required (10/12 correct)
- Time limit: 20 minutes

---

### Multiple Choice Questions (1-8)

**Q1. When using AI coding assistants, who is ultimately responsible for the security of the code?**

- A) The AI vendor
- B) The security team
- C) The developer using the AI assistant ✓
- D) No one - AI code is always secure

**Explanation:** Developers remain responsible for validating all AI-generated code and ensuring it follows security best practices.

---

**Q2. Which is the correct approach to prevent SQL injection when AI suggests a database query?**

- A) Use string concatenation with user input
- B) Use parameterized queries with placeholders ✓
- C) Escape special characters manually
- D) Trust the AI to generate secure queries

**Explanation:** Parameterized queries separate code from data, preventing SQL injection regardless of input content.

---

**Q3. What is "prompt injection" in the context of AI security?**

- A) Injecting SQL into a database
- B) User input that manipulates AI behavior by including malicious instructions ✓
- C) Injecting JavaScript into web pages
- D) A type of buffer overflow attack

**Explanation:** Prompt injection occurs when user-controlled input contains instructions that override or modify the AI's intended operation.

---

**Q4. Which defense strategy is MOST effective against prompt injection?**

- A) Trust all user input
- B) Only use AI for internal systems
- C) Separate instructions from user content with clear delimiters and validate both input and output ✓
- D) Disable the AI when suspicious input is detected

**Explanation:** Defense in depth - separating instructions from data, plus validating both inputs and outputs - provides the strongest protection.

---

**Q5. When implementing an AI tool that reads files, what is the correct security approach?**

- A) Allow the AI to read any file it requests
- B) Validate paths against an allowlist and prevent path traversal ✓
- C) Only allow reading files smaller than 1MB
- D) Require a password for each file read

**Explanation:** Path validation (allowlist + path traversal prevention) ensures AI can only access intended files.

---

**Q6. Which of these is a "red flag" in AI-generated code that should NEVER be committed?**

- A) Using async/await patterns
- B) eval() with user input ✓
- C) Using environment variables for configuration
- D) Importing third-party libraries

**Explanation:** eval() with user input allows arbitrary code execution and is a critical security vulnerability.

---

**Q7. What is the purpose of SAST tools in secure development?**

- A) Test the running application for vulnerabilities
- B) Find vulnerabilities in source code before deployment ✓
- C) Manage API keys and secrets
- D) Monitor production for attacks

**Explanation:** SAST (Static Application Security Testing) analyzes source code to find vulnerabilities during development.

---

**Q8. How should developers respond to AI security tool findings?**

- A) Automatically fix everything the tool suggests
- B) Ignore all findings as false positives
- C) Review findings, understand the issue, and fix genuine vulnerabilities ✓
- D) Disable the tool if there are too many findings

**Explanation:** Developers should review findings critically, understand the security issue, and fix real vulnerabilities while documenting genuine false positives.

---

### Code Review Questions (9-12)

**Review the following code snippets and identify the security issue.**

---

**Q9. Python Code:**
```python
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
```

**What is the security vulnerability?**

- A) Missing error handling
- B) SQL Injection via string formatting ✓
- C) Missing authentication
- D) No vulnerability present

**Explanation:** String formatting with user input creates SQL injection. Fix: `db.execute("SELECT * FROM users WHERE id = ?", (user_id,))`

---

**Q10. JavaScript Code:**
```javascript
app.get('/file', (req, res) => {
    const filename = req.query.name;
    const content = fs.readFileSync(`/data/${filename}`);
    res.send(content);
});
```

**What is the security vulnerability?**

- A) Missing HTTPS
- B) Path traversal - user can read arbitrary files ✓
- C) XSS vulnerability
- D) No vulnerability present

**Explanation:** An attacker could request `?name=../../../etc/passwd` to read sensitive system files. Fix: Validate filename against allowlist and use path.resolve() with path.startsWith() check.

---

**Q11. AI Prompt Code:**
```python
def summarize_document(user_document):
    prompt = f"Summarize this document: {user_document}"
    return ai_model.generate(prompt)
```

**What is the security vulnerability?**

- A) The prompt is too short
- B) Prompt injection - user content mixed with instructions ✓
- C) Missing rate limiting
- D) No vulnerability present

**Explanation:** User document content is mixed directly with instructions, allowing prompt injection. Fix: Use delimiters (`<document>` tags) and instruct AI to only process content within tags.

---

**Q12. Go Code:**
```go
func handleRequest(w http.ResponseWriter, r *http.Request) {
    userInput := r.URL.Query().Get("cmd")
    out, _ := exec.Command("sh", "-c", userInput).Output()
    w.Write(out)
}
```

**What is the security vulnerability?**

- A) Missing error handling
- B) Command injection - user can execute arbitrary commands ✓
- C) Missing authentication
- D) XSS in output

**Explanation:** User input is passed directly to a shell command, allowing arbitrary command execution. This endpoint should be removed or heavily restricted with input validation.

---

## Level 2 Assessment: Role-Based Secure Development

### Instructions
- 15 questions (10 multiple choice + 5 scenario-based)
- 80% passing score required (12/15 correct)
- Time limit: 35 minutes

---

### Multiple Choice Questions (1-10)

**Q1. In Python, which is the secure way to generate random tokens?**

- A) `random.randint(0, 999999)`
- B) `secrets.token_urlsafe(32)` ✓
- C) `hash(str(time.time()))`
- D) `uuid.uuid4()`

**Explanation:** The `secrets` module provides cryptographically secure random generation. `random` is predictable, and time-based approaches are guessable.

---

**Q2. Which Express.js middleware provides comprehensive security headers?**

- A) body-parser
- B) cors
- C) helmet ✓
- D) morgan

**Explanation:** Helmet sets various HTTP security headers (CSP, X-Frame-Options, etc.) to protect against common web vulnerabilities.

---

**Q3. In a security code review, what should be checked for AI integration code?**

- A) Only traditional vulnerabilities like SQL injection
- B) Only AI-specific issues like prompt injection
- C) Both traditional vulnerabilities AND AI-specific security (prompt injection, tool permissions, output sanitization) ✓
- D) AI code doesn't need security review

**Explanation:** AI integration code needs review for both traditional vulnerabilities AND AI-specific risks like injection, excessive permissions, and output handling.

---

**Q4. When configuring SAST in CI/CD, what is the best practice for handling findings?**

- A) Fail the build on any finding
- B) Never fail the build - just report
- C) Fail on critical/high, warn on medium, track low ✓
- D) Only run SAST on release branches

**Explanation:** A balanced approach: block deployments for serious issues, warn on moderate issues, and track everything for remediation.

---

**Q5. What is the purpose of input validation with Zod (or similar schema validators)?**

- A) Make code run faster
- B) Ensure input matches expected types and constraints before processing ✓
- C) Format output for display
- D) Compress data for storage

**Explanation:** Schema validation ensures inputs match expected types, ranges, and formats, preventing unexpected data from reaching application logic.

---

**Q6. When creating team security guidance, what should be included for AI integration?**

- A) Only links to vendor documentation
- B) Requirements for input validation, output sanitization, permission constraints, logging, and rate limiting ✓
- C) A statement that AI code is automatically secure
- D) Instructions to disable security tools for AI code

**Explanation:** Team guidance should specify concrete security requirements for AI: validate inputs, sanitize outputs, constrain permissions, log actions, and implement rate limiting.

---

**Q7. In Go, what is the secure way to prevent command injection when running external commands?**

- A) Use `exec.Command("sh", "-c", userInput)`
- B) Escape special characters in user input
- C) Avoid shell, pass arguments directly: `exec.Command("tool", userInput)` ✓
- D) Run commands as root for full access

**Explanation:** Avoiding the shell and passing arguments directly prevents shell metacharacter interpretation.

---

**Q8. What is the correct approach for AI tool permission boundaries?**

- A) Give AI all permissions for flexibility
- B) Define explicit permissions per tool with allowlists and limits ✓
- C) Rely on the AI to self-limit
- D) Only restrict file system access

**Explanation:** Each tool should have explicit permission definitions (allowed paths, operations, limits) enforced before execution.

---

**Q9. When tuning AI security tools to reduce false positives, what should you do?**

- A) Disable the tool entirely
- B) Suppress patterns with documented rationale and security team review ✓
- C) Mark all findings as false positives
- D) Stop running the tool on AI-related code

**Explanation:** False positives should be suppressed with clear documentation of why they're false positives, reviewed by security to ensure real issues aren't missed.

---

**Q10. What is the main benefit of integrating security tools into IDE vs. only CI/CD?**

- A) It's cheaper
- B) Developers get early feedback and can fix issues before commit ✓
- C) IDE tools are more accurate
- D) CI/CD tools don't work properly

**Explanation:** IDE integration provides immediate feedback, allowing developers to fix issues as they code rather than after commit.

---

### Scenario-Based Questions (11-15)

**Scenario A:** Your team is building an AI-powered customer support chatbot that can access customer order information. The AI can look up orders by customer email.

**Q11. What is the primary security concern with this chatbot?**

- A) The AI is too slow
- B) The AI could be tricked into revealing other customers' order information ✓
- C) The chatbot might use too many API tokens
- D) Customers might not like AI support

**Explanation:** Prompt injection could manipulate the AI to query/reveal information for other customers, or an unauthenticated user could request anyone's orders.

---

**Q12. What security controls should be implemented for Scenario A?**

- A) Only rate limiting
- B) Authentication, authorization (verify requester owns the email), input validation, and output filtering ✓
- C) Only logging
- D) Disable the order lookup feature

**Explanation:** Multiple controls needed: verify user identity, ensure they can only access their own data, validate inputs for injection, and filter outputs for sensitive data.

---

**Scenario B:** An AI code review tool is being integrated into your CI/CD pipeline. It will analyze all pull requests and post comments about potential issues.

**Q13. What is the Information Disclosure risk in Scenario B?**

- A) The tool is too slow
- B) The AI could leak code snippets, secrets, or sensitive logic in its comments ✓
- C) Developers might ignore AI comments
- D) The tool costs too much

**Explanation:** An AI with access to all code could potentially include sensitive code snippets, secrets, or proprietary logic in public PR comments.

---

**Q14. How should the AI code review tool's outputs be secured?**

- A) Trust the AI to not leak sensitive information
- B) Implement output filtering to scan for secrets/sensitive patterns before posting comments ✓
- C) Only run the tool on public repositories
- D) Disable PR comments entirely

**Explanation:** Output filtering should scan AI responses for secrets, PII, and sensitive patterns before posting publicly visible comments.

---

**Scenario C:** Your team receives this AI security tool finding:

```
CRITICAL: Potential command injection in ai_tools.py:47
Code: subprocess.run(f"process {user_input}", shell=True)
```

**Q15. What is the correct response to this finding?**

- A) Suppress it as a false positive - AI tools make mistakes
- B) Investigate, confirm it's a real vulnerability, fix by removing shell=True and using argument list, verify the fix ✓
- C) Ignore it because it's in AI-related code
- D) Add a comment explaining why it's needed

**Explanation:** This is a genuine command injection vulnerability. Fix by using `subprocess.run(["process", user_input], shell=False)` to prevent shell interpretation.

---

## Level 3 Assessment: Security Champions & Industry Leadership

### Instructions
- 10 scenario-based questions + 1 practical threat model exercise
- 80% on written questions (8/10) + practical pass required
- Time limit: 45 minutes for written, 45 minutes for practical

---

### Scenario-Based Questions (1-10)

**Q1. As a Security Champion, what percentage of your time should typically be allocated to security activities?**

- A) 100% - full-time security role
- B) 20-30% - balance security with development ✓
- C) 5% - occasional security tasks
- D) 0% - Security Champions just have the title

**Explanation:** Security Champions typically allocate 20-30% of time to security activities while remaining active developers.

---

**Q2. When measuring secure development effectiveness, which metric indicates issues escaping to production?**

- A) Training completion rate
- B) Vulnerability density (vulns per KLOC)
- C) Escaped vulnerabilities ✓
- D) SAST tool adoption rate

**Explanation:** Escaped vulnerabilities measures security issues found in production that should have been caught earlier.

---

**Q3. In AI application threat modeling, which AI-specific threat relates to the AI having more access than needed?**

- A) Agent Goal Hijacking (AGH)
- B) Excessive Agency (EA) ✓
- C) Tool Misuse (TM)
- D) Rogue Agents (RA)

**Explanation:** Excessive Agency (EA) specifically addresses AI having more permissions, tools, or capabilities than necessary.

---

**Q4. When contributing to industry secure coding standards, which organization focuses on web and AI application security?**

- A) IEEE
- B) ISO
- C) OWASP ✓
- D) IETF

**Explanation:** OWASP (Open Web Application Security Project) maintains the LLM Top 10, ASVS, and other application security standards.

---

**Q5. What is the target MTTR (Mean Time to Remediate) for HIGH severity vulnerabilities in a mature security program?**

- A) 24 hours
- B) Less than 7 days ✓
- C) 30 days
- D) 90 days

**Explanation:** High severity vulnerabilities typically have a 7-day remediation SLA in mature programs. Critical is faster (24-48h), medium is 30 days.

---

**Scenario D:** You're threat modeling an AI agent that can read documents, query databases, and send emails on behalf of users.

**Q6. What is the most critical attack scenario for this agent?**

- A) The AI sends too many emails
- B) An attacker uses prompt injection to have the AI exfiltrate sensitive database data via email ✓
- C) The AI reads documents slowly
- D) Users don't like the AI's responses

**Explanation:** Combining database access (read sensitive data) with email (exfiltrate to attacker) via prompt injection is the highest-impact attack chain.

---

**Q7. What architectural control best addresses the risk in Q6?**

- A) Remove the email capability
- B) Implement separation of duties - database and email tools should require separate approval flows ✓
- C) Add more logging
- D) Rate limit the AI

**Explanation:** Separation of duties prevents the attack chain. If sensitive database queries require human approval, the exfiltration via email is blocked.

---

**Scenario E:** Your organization's security scorecard shows: Training: 85%, Vuln Density: 0.5/KLOC, Critical Escaped: 0, MTTR High: 5 days, Security Testing: 65%.

**Q8. Which area needs the most improvement based on this scorecard?**

- A) Training (85%)
- B) Vulnerability Density (0.5/KLOC)
- C) Security Testing (65%) ✓
- D) MTTR High (5 days)

**Explanation:** Security Testing at 65% is below the typical 80% target and is the lowest performing metric, indicating a gap in test coverage.

---

**Q9. How can a Security Champion improve the Security Testing metric?**

- A) Write more unit tests
- B) Conduct training on security testing, create security test templates, integrate security tests into CI/CD ✓
- C) Remove complex code
- D) Reduce the target percentage

**Explanation:** Champions can improve security testing through training, templates, and pipeline integration to make security testing easier for all developers.

---

**Q10. What is the key difference between leading and lagging security indicators?**

- A) Leading indicators are faster to measure
- B) Leading indicators predict future security (training, code review), lagging indicators measure past results (incidents, escaped vulns) ✓
- C) Lagging indicators are more important
- D) There is no meaningful difference

**Explanation:** Leading indicators (training, proactive measures) predict future security posture, while lagging indicators (incidents) measure what already happened.

---

### Practical Exercise: AI Application Threat Model

**Exercise:** Create a complete threat model for the following system:

> **System:** An AI-powered code assistant integrated into your company's IDE
>
> **Capabilities:**
> - Read all source code in open projects
> - Suggest code completions and fixes
> - Search internal documentation wiki
> - Access company GitHub (read-only)
> - No ability to modify files directly (suggestions only)
>
> **Users:** All software developers (500+)

**Deliverables (45 minutes):**

1. **Architecture Diagram** (10 points)
   - Show all components and data flows
   - Mark trust boundaries
   - Identify where user input enters the system

2. **Asset Inventory** (5 points)
   - List all assets with sensitivity levels
   - Identify which assets the AI can access

3. **STRIDE + AI Threat Analysis** (15 points)
   - Complete STRIDE analysis for the AI component
   - Add EA, AGH, TM, RA analysis
   - Rate each threat (Low/Medium/High/Critical)

4. **Top 3 Attack Scenarios** (10 points)
   - Describe realistic attack scenarios
   - Include attack chain (how attacker achieves goal)
   - Identify impact if successful

5. **Recommended Controls** (10 points)
   - Propose controls for each top attack scenario
   - Map controls to defense-in-depth layers
   - Prioritize implementation order

**Passing Criteria:**
- Architecture accurately represents system with clear trust boundaries
- All major assets identified with appropriate sensitivity levels
- At least 8/10 threats identified with AI context
- Attack scenarios are realistic and complete
- Controls directly address identified threats

---

## Answer Key Summary

### L1 Answers
1-C, 2-B, 3-B, 4-C, 5-B, 6-B, 7-B, 8-C, 9-B, 10-B, 11-B, 12-B

### L2 Answers
1-B, 2-C, 3-C, 4-C, 5-B, 6-B, 7-C, 8-B, 9-B, 10-B, 11-B, 12-B, 13-B, 14-B, 15-B

### L3 Answers
1-B, 2-C, 3-B, 4-C, 5-B, 6-B, 7-B, 8-C, 9-B, 10-B
Practical: Rubric-based evaluation

---

**Document Version:** 1.0
**Framework:** HAIAMM v2.0
**Practice:** Education & Guidance (EG)
**Domain:** Software
**Author:** Verifhai

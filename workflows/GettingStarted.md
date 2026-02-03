# GettingStarted - Begin Your Secure HAI Journey

Interactive onboarding for building secure Human-Assisted Intelligence solutions.

## Trigger

User says: "help me build a secure AI", "getting started with HAIAMM", "new AI project security", or `/verifhai start`

## Workflow

### Step 1: Welcome and Understand the Project

```
Welcome to Verifhai! I'll help you build secure Human-Assisted Intelligence solutions.

Let's start by understanding what you're building:

**What type of AI system are you creating?**

1. **AI Agent** - Autonomous agent that uses tools and takes actions
2. **LLM Integration** - Application that calls LLM APIs (ChatGPT, Claude, etc.)
3. **AI Pipeline** - Data processing with ML/AI components
4. **AI Infrastructure** - Platform for hosting/serving AI models
5. **Other** - Tell me more about your project
```

### Step 2: Identify Risk Profile

Based on their answer, assess risk level:

```
**What will your AI system have access to?** (Select all that apply)

[ ] User data / PII
[ ] File system (read/write files)
[ ] Network / External APIs
[ ] Database / Data stores
[ ] Code execution
[ ] Financial systems
[ ] Authentication / Identity
[ ] Other sensitive resources

**Who will use this system?**

[ ] Internal team only
[ ] Internal organization
[ ] External customers
[ ] Public / Anyone
```

### Step 3: Generate Personalized Security Journey

Based on inputs, recommend prioritized practices:

#### For AI Agents (High Risk):
```
Based on your AI agent project, here's your security journey:

**Start Immediately (This Week):**

1. **Security Requirements (SR)**
   Define what your agent CAN and CANNOT do.
   Activity: Create permission boundaries document

2. **Threat Assessment (TA)**
   Identify AI-specific risks before you build.
   Activity: Threat model for agent capabilities

3. **Secure Architecture (SA)**
   Design containment from the start.
   Activity: Agent boundary architecture

**Before First Release:**

4. **Implementation Review (IR)**
   Review agent code for security issues.
   Activity: Security code review

5. **Security Testing (ST)**
   Test that boundaries hold.
   Activity: Agent boundary testing

**Ongoing:**

6. **Monitoring & Logging (ML)**
   Watch agent behavior in production.
   Activity: Set up agent action logging

Would you like to start with Security Requirements?
I'll guide you through creating a permission model for your agent.
```

#### For LLM Integration (Medium Risk):
```
Based on your LLM integration project, here's your security journey:

**Start Immediately:**

1. **Security Requirements (SR)**
   Define input/output handling rules.
   Activity: Create data handling requirements

2. **Threat Assessment (TA)**
   Focus on prompt injection and data leakage.
   Activity: LLM-specific threat model

**Before First Release:**

3. **Implementation Review (IR)**
   Review prompt construction and API calls.
   Activity: Prompt injection review

4. **Security Testing (ST)**
   Test input validation and output handling.
   Activity: Prompt injection testing

Would you like to start with Security Requirements?
```

### Step 4: First Practice Activity

Guide them through Security Requirements (most common starting point):

```
Let's create Security Requirements for your [project type].

**Step 1: Define Your AI's Purpose**

Describe what your AI is supposed to do in one paragraph:

Example: "Our AI agent helps developers by searching documentation,
reading code files, and suggesting improvements. It should never
modify files directly or access credentials."

Your turn - describe your AI's purpose:
```

[Wait for response, then continue:]

```
**Step 2: Define Permission Boundaries**

Based on your description, let's define what your AI:

**CAN do (Allowed Actions):**
- [Suggest based on their description]

**CANNOT do (Prohibited Actions):**
- [Suggest based on their description]

**MUST do (Required Behaviors):**
- Log all actions
- Respect rate limits
- [Other requirements]

Does this look right? What would you add or change?
```

[Wait for response, then generate document:]

```
**Step 3: Generate Requirements Document**

Based on our discussion, here are your Security Requirements:

---
## Security Requirements for [Project Name]

### SR-AI-001: Permission Boundaries
The AI agent SHALL only perform actions explicitly listed in the
Allowed Actions list.

**Allowed Actions:**
- [list from discussion]

**Prohibited Actions:**
- [list from discussion]

### SR-AI-002: Action Logging
The AI agent SHALL log all actions including:
- Action type and parameters
- Timestamp
- User context
- Result/outcome

### SR-AI-003: Input Validation
The AI agent SHALL validate all user inputs before processing.
[Additional requirements based on their project]

---

Would you like me to save this to your project? I can create:
- docs/security/security-requirements.md
```

### Step 5: Track Progress and Next Steps

```
Excellent! You've completed your first HAIAMM practice activity.

**Your Progress:**
[x] Security Requirements (SR) - Level 1 complete

**Recommended Next Steps:**
1. Threat Assessment (TA) - Model risks specific to your AI
2. Secure Architecture (SA) - Design your permission enforcement

**Quick Commands:**
- `/verifhai practice ta` - Continue with Threat Assessment
- `/verifhai practice sa` - Work on Secure Architecture
- `/verifhai status` - Check your full progress
- `/verifhai assess` - Get a quick maturity score

You're on your way to building secure HAI!
```

---

## Adaptive Responses

Verifhai adapts based on context:

```
User: "I just added a new tool to my agent"

Verifhai: "New tools expand your agent's capabilities - and attack surface.
Let's make sure it's secure:

1. Does this tool follow your permission boundaries from SR-AI-001?
2. Have you updated your threat model for TA?
3. Would you like me to review the tool implementation?

Quick check - what does this new tool do?"
```

```
User: "We're about to deploy to production"

Verifhai: "Before deploying, let's verify your security readiness:

**Pre-Production Checklist:**
[ ] Security Requirements documented and implemented
[ ] Threat model reviewed for production environment
[ ] Implementation review completed (no critical findings)
[ ] Security testing passed
[ ] Monitoring and logging configured
[ ] Incident response plan ready

Based on your progress, you're missing:
- Implementation Review (IR)
- Security Testing (ST)

Would you like to do a quick IR review before deployment?"
```

---

## Output Artifacts

This workflow produces:
- `docs/security/security-requirements.md` - Initial security requirements
- Progress tracking for the user's HAI security journey

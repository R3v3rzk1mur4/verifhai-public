# Monitoring & Logging (ML) Template

## Document Control

| Field | Value |
|-------|-------|
| Project | [Project Name] |
| Version | 1.0 |
| Date | [YYYY-MM-DD] |
| Author | [Author Name] |
| Status | Draft / Active |

---

## 1. Monitoring & Logging Overview

### 1.1 Purpose

This document defines the monitoring and logging requirements for HAI (Human-Assisted Intelligence) systems, including:

- Security event logging standards
- AI-specific event capture
- Alert configuration and thresholds
- Log integrity and retention
- Dashboard and metric definitions

### 1.2 Scope

| System Component | Logging Level | Alerting |
|------------------|---------------|----------|
| AI Agent Core | Full audit | Yes |
| Tool Invocations | Full audit | Yes |
| Permission Checks | Full audit | Yes |
| User Inputs | Sanitized | Anomaly-based |
| AI Outputs | Sampled/Full | Anomaly-based |
| Infrastructure | Standard | Yes |

---

## 2. Event Types

### 2.1 AI-Specific Events

| Event Type | Code | Description | Severity | Required Fields |
|------------|------|-------------|----------|-----------------|
| Tool Invocation | TOOL | AI agent calls a tool | INFO | tool_name, parameters, result |
| Permission Check | PERM | Access decision made | INFO/WARN | action, resource, decision, reason |
| Permission Denied | PERM_DENY | Access blocked | WARN | action, resource, reason, user_context |
| Prompt Injection Detected | INJ | Injection pattern found | CRITICAL | pattern_id, risk_score, input_snippet |
| Rate Limit Triggered | RATE | Usage limit hit | WARN | limit_type, current_value, threshold |
| Iteration Limit | ITER | Loop limit reached | WARN | iteration_count, max_iterations |
| Agent Timeout | TIMEOUT | Execution exceeded time | WARN | duration_ms, timeout_ms |
| Kill Switch Activated | KILL | Agent forcefully stopped | CRITICAL | reason, agent_state |
| Goal Deviation | GOAL | Agent behavior anomaly | WARN | expected_goal, observed_behavior |
| Excessive Agency | EA | Agent exceeded permissions | CRITICAL | action_attempted, permission_boundary |

### 2.2 Standard Security Events

| Event Type | Code | Description | Severity |
|------------|------|-------------|----------|
| Authentication | AUTH | Login/logout events | INFO |
| Authentication Failure | AUTH_FAIL | Failed login attempt | WARN |
| Authorization | AUTHZ | Access control decisions | INFO |
| Configuration Change | CONFIG | System config modified | WARN |
| Data Access | DATA | Sensitive data accessed | INFO |
| Error | ERROR | Application error | ERROR |
| System Start/Stop | SYS | Service lifecycle | INFO |

### 2.3 Event Severity Levels

| Level | Code | Description | Alerting |
|-------|------|-------------|----------|
| DEBUG | 10 | Verbose debugging info | Never |
| INFO | 20 | Normal operations | Never |
| WARN | 30 | Potential issues | Optional |
| ERROR | 40 | Errors requiring attention | Yes |
| CRITICAL | 50 | Security incidents, system failures | Immediate |

---

## 3. Structured Log Format

### 3.1 Standard Log Entry Schema

```json
{
  "id": "uuid-v4",
  "timestamp": "ISO-8601 with timezone",
  "level": "INFO|WARN|ERROR|CRITICAL",
  "event_type": "EVENT_CODE",
  "service": "service-name",
  "version": "1.0.0",

  "context": {
    "agent_id": "agent-identifier",
    "session_id": "session-identifier",
    "user_id": "user-identifier (hashed if PII)",
    "correlation_id": "request-trace-id"
  },

  "event": {
    "action": "what happened",
    "resource": "what was affected",
    "result": "success|failure|blocked",
    "details": {}
  },

  "metrics": {
    "duration_ms": 150,
    "tokens_used": 1500,
    "iteration_count": 3
  },

  "security": {
    "risk_score": 0.0,
    "patterns_matched": [],
    "sanitized": true
  },

  "integrity": {
    "hash": "sha256-of-entry",
    "prev_hash": "sha256-of-previous-entry",
    "sequence": 12345
  }
}
```

### 3.2 Example Log Entries

**Tool Invocation (Success):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "level": "INFO",
  "event_type": "TOOL",
  "service": "ai-agent",
  "context": {
    "agent_id": "agent-abc123",
    "session_id": "sess-xyz789",
    "user_id": "usr_hash_456",
    "correlation_id": "req-111222333"
  },
  "event": {
    "action": "file_read",
    "resource": "/data/reports/summary.txt",
    "result": "success",
    "details": {
      "bytes_read": 2048,
      "file_type": "text/plain"
    }
  },
  "metrics": {
    "duration_ms": 45
  },
  "security": {
    "risk_score": 0.0,
    "sanitized": true
  }
}
```

**Permission Denied:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440001",
  "timestamp": "2024-01-15T10:30:05.000Z",
  "level": "WARN",
  "event_type": "PERM_DENY",
  "service": "ai-agent",
  "context": {
    "agent_id": "agent-abc123",
    "session_id": "sess-xyz789",
    "user_id": "usr_hash_456",
    "correlation_id": "req-111222334"
  },
  "event": {
    "action": "file_write",
    "resource": "/etc/passwd",
    "result": "blocked",
    "details": {
      "reason": "path_not_in_allowlist",
      "rule": "DENY-FS-001"
    }
  },
  "security": {
    "risk_score": 0.8,
    "patterns_matched": ["path_traversal_attempt"]
  }
}
```

**Prompt Injection Detected:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440002",
  "timestamp": "2024-01-15T10:30:10.000Z",
  "level": "CRITICAL",
  "event_type": "INJ",
  "service": "ai-agent",
  "context": {
    "agent_id": "agent-abc123",
    "session_id": "sess-xyz789",
    "user_id": "usr_hash_456",
    "correlation_id": "req-111222335"
  },
  "event": {
    "action": "input_validation",
    "resource": "user_prompt",
    "result": "blocked",
    "details": {
      "input_length": 256,
      "input_snippet": "[REDACTED - injection attempt]"
    }
  },
  "security": {
    "risk_score": 0.95,
    "patterns_matched": ["DIO-001", "RM-001"],
    "action_taken": "block"
  }
}
```

---

## 4. PII Sanitization

### 4.1 Sanitization Requirements

| Data Type | Pattern | Action | Replacement |
|-----------|---------|--------|-------------|
| Email | `[\w.-]+@[\w.-]+\.\w+` | Redact | `[EMAIL]` |
| Phone | `\+?[\d\s-()]{10,}` | Redact | `[PHONE]` |
| SSN | `\d{3}-\d{2}-\d{4}` | Redact | `[SSN]` |
| Credit Card | `\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}` | Redact | `[CC]` |
| API Key | `(api[_-]?key|token|secret)[\s:=]+\S+` | Redact | `[API_KEY]` |
| Password | `(password|passwd|pwd)[\s:=]+\S+` | Redact | `[PASSWORD]` |
| IP Address | `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` | Hash | SHA256 prefix |
| User ID | Application-specific | Hash | SHA256 prefix |

### 4.2 Sanitization Rules

```
NEVER log:
- Raw passwords or secrets
- Full credit card numbers
- Social Security Numbers
- API keys or tokens
- Private keys or certificates
- Session tokens (full)

ALWAYS sanitize:
- User inputs before logging
- AI outputs if they may contain user data
- Error messages that might expose internals
- Stack traces in production

MAY log (with care):
- Hashed user identifiers
- Partial tokens (first 4 chars)
- Anonymized IP addresses
- Redacted prompts (for security analysis)
```

### 4.3 Sanitization Verification Checklist

```
[ ] PII patterns configured for all known types
[ ] Sanitization runs BEFORE log write
[ ] Sanitization tested with sample data
[ ] Regular expressions reviewed for bypass
[ ] Custom application PII patterns added
[ ] Sanitization failures default to full redaction
```

---

## 5. Alert Configuration

### 5.1 Alert Rules

| Rule ID | Condition | Severity | Action | Escalation |
|---------|-----------|----------|--------|------------|
| ALT-001 | Permission denied > 10/min | HIGH | Alert + block session | Security team |
| ALT-002 | Injection detected (any) | CRITICAL | Alert + block + log full context | Immediate |
| ALT-003 | Kill switch activated | CRITICAL | Alert all channels | Immediate |
| ALT-004 | Error rate > 5%/5min | MEDIUM | Alert | Engineering |
| ALT-005 | Iteration limit hit > 3/hour | MEDIUM | Alert | Engineering |
| ALT-006 | Unusual tool pattern | MEDIUM | Alert for review | Security team |
| ALT-007 | Rate limit exceeded | HIGH | Alert + temporary block | Security team |
| ALT-008 | Agent timeout | LOW | Log only | None |
| ALT-009 | Authentication failure > 5/min | HIGH | Alert + block IP | Security team |
| ALT-010 | Data access anomaly | MEDIUM | Alert for review | Security team |

### 5.2 Alert Thresholds

| Metric | Warning | Critical | Window |
|--------|---------|----------|--------|
| Permission denials | 5/min | 20/min | 1 minute |
| Error rate | 2% | 5% | 5 minutes |
| Latency (p99) | 5s | 30s | 5 minutes |
| Token usage | 80% quota | 95% quota | 1 hour |
| Failed auth | 3/min | 10/min | 1 minute |

### 5.3 Alert Channels

| Channel | Use For | Response Time |
|---------|---------|---------------|
| PagerDuty/Opsgenie | Critical alerts | < 5 min |
| Slack #security | High/Medium alerts | < 30 min |
| Email | Low priority, summaries | < 4 hours |
| Dashboard | All (visual) | On-demand |
| SIEM | All (correlation) | Automated |

### 5.4 Alert Template

```markdown
## Security Alert: [RULE_ID] - [SEVERITY]

**Time:** [TIMESTAMP]
**Service:** [SERVICE_NAME]
**Agent:** [AGENT_ID]

### Summary
[BRIEF DESCRIPTION]

### Details
- Event Type: [EVENT_TYPE]
- Trigger: [WHAT_TRIGGERED_ALERT]
- Count: [OCCURRENCE_COUNT] in [TIME_WINDOW]

### Context
- Session: [SESSION_ID]
- User: [USER_ID_HASHED]
- Correlation ID: [CORRELATION_ID]

### Recommended Actions
1. [ACTION_1]
2. [ACTION_2]

### Links
- [Dashboard](link)
- [Runbook](link)
- [Related Logs](link)
```

---

## 6. Dashboard & Metrics

### 6.1 Key Metrics

| Metric | Description | Target | Alert Threshold |
|--------|-------------|--------|-----------------|
| Tool Invocation Rate | Tools called per minute | Baseline ±20% | > 50% deviation |
| Permission Denial Rate | Denials / Total checks | < 1% | > 5% |
| Injection Detection Rate | Injections detected/hour | 0 | Any |
| Agent Error Rate | Errors / Total requests | < 0.1% | > 1% |
| Mean Response Time | Average request duration | < 2s | > 10s |
| Token Consumption | Tokens used per hour | Budget | > 80% budget |
| Active Agents | Concurrent agent count | Capacity | > 80% capacity |
| Kill Switch Activations | Count per day | 0 | Any |

### 6.2 Dashboard Panels

**Overview Dashboard:**
```
┌─────────────────────────────────────────────────────────────────────┐
│                     HAI SECURITY DASHBOARD                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────┐│
│  │ Active Agents│  │ Requests/min │  │ Error Rate   │  │ Alerts   ││
│  │     12       │  │    1,234     │  │    0.05%     │  │    2     ││
│  │   ▲ +2       │  │   ▲ +15%     │  │   ✓ Normal   │  │  ⚠ High  ││
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────┘│
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │ Tool Invocations (Last Hour)                                   │ │
│  │ ████████████████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ │ │
│  │ file_read: 45%  |  web_search: 30%  |  code_exec: 15%  |  10% │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │ Security Events Timeline                                       │ │
│  │                                                                 │ │
│  │ 10:00 ─────●────────●───────────●●●─────────────●──────── 11:00│ │
│  │           PERM     INJ          RATE            ERROR          │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  ┌─────────────────────────────┐  ┌─────────────────────────────┐  │
│  │ Permission Checks           │  │ Recent Alerts               │  │
│  │ ✓ Allowed: 12,456 (99.2%)  │  │ • INJ-001 10:15 CRITICAL    │  │
│  │ ✗ Denied: 98 (0.8%)        │  │ • RATE-001 10:12 HIGH       │  │
│  │                             │  │ • PERM-005 10:05 MEDIUM     │  │
│  └─────────────────────────────┘  └─────────────────────────────┘  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 6.3 Required Dashboard Views

| Dashboard | Purpose | Refresh Rate | Audience |
|-----------|---------|--------------|----------|
| Security Overview | Real-time security status | 30s | Security team |
| Agent Performance | Agent health and metrics | 1min | Engineering |
| Incident Timeline | Security event correlation | 10s | Security/SRE |
| Compliance | Audit and compliance metrics | 1hr | Leadership |
| Cost/Usage | Token and resource usage | 5min | Engineering |

---

## 7. Log Retention & Storage

### 7.1 Retention Policy

| Log Type | Hot Storage | Warm Storage | Cold/Archive | Total Retention |
|----------|-------------|--------------|--------------|-----------------|
| Security Events | 30 days | 90 days | 2 years | 2+ years |
| Audit Logs | 30 days | 1 year | 7 years | 7+ years |
| Application Logs | 7 days | 30 days | 90 days | 90 days |
| Debug Logs | 24 hours | 7 days | - | 7 days |
| Performance Metrics | 7 days | 30 days | 1 year | 1 year |

### 7.2 Storage Requirements

| Tier | Storage Type | Access Speed | Cost | Use Case |
|------|--------------|--------------|------|----------|
| Hot | SSD/Fast | < 100ms | $$$ | Active investigation |
| Warm | Standard | < 1s | $$ | Recent history |
| Cold | Archive | < 1hr | $ | Compliance/legal |

### 7.3 Log Rotation

```
Rotation Policy:
- Rotate when file size > 100MB
- Rotate daily regardless of size
- Compress rotated logs (gzip)
- Delete beyond retention period
- Verify integrity before deletion
```

---

## 8. Log Integrity & Tamper-Evidence

### 8.1 Hash Chain Implementation

```
Each log entry includes:
- hash: SHA-256 of current entry content
- prev_hash: SHA-256 of previous entry
- sequence: Monotonically increasing sequence number

Verification:
1. Compute hash of entry content
2. Compare with stored hash
3. Verify prev_hash matches previous entry
4. Verify sequence is consecutive
5. Any break indicates tampering
```

### 8.2 Integrity Verification

| Check | Frequency | Action on Failure |
|-------|-----------|-------------------|
| Hash chain validation | Every 5 minutes | Alert + investigate |
| Sequence gap check | Real-time | Alert + investigate |
| Log file checksum | Daily | Alert + restore from backup |
| Cross-system correlation | Daily | Alert + investigate |

### 8.3 Tamper-Evidence Checklist

```
[ ] Hash chain implemented for security logs
[ ] Sequence numbers verified
[ ] Log shipping to immutable storage
[ ] Write-once storage for critical logs
[ ] Regular integrity verification scheduled
[ ] Alerting on integrity failures
[ ] Backup verification procedures
```

---

## 9. Anomaly Detection

### 9.1 Baseline Behaviors

| Behavior | Normal Range | Anomaly Threshold |
|----------|--------------|-------------------|
| Tool calls per session | 5-50 | > 100 or < 2 |
| Session duration | 1-30 min | > 2 hours |
| Unique tools per session | 2-8 | > 15 |
| Permission check ratio | 95%+ allowed | < 80% allowed |
| Error frequency | < 1% | > 5% |

### 9.2 Anomaly Detection Rules

| Rule | Detection Method | Response |
|------|------------------|----------|
| Unusual tool sequence | Pattern matching | Alert + review |
| High permission denials | Statistical | Alert + rate limit |
| Off-hours activity | Time-based | Alert + verify |
| New tool combinations | ML clustering | Log + review |
| Resource exhaustion | Threshold | Alert + limit |

### 9.3 Machine Learning Detection (Level 3)

```
For Level 3 maturity:
- Train models on normal agent behavior
- Detect deviation from learned patterns
- Reduce false positives over time
- Automated incident creation
- Feedback loop for model improvement
```

---

## 10. Implementation Checklist

### 10.1 Level 1: Foundational

```
[ ] Define event types to log (Section 2)
[ ] Implement structured log format (Section 3)
[ ] Configure PII sanitization (Section 4)
[ ] Set up basic alerts for critical events (Section 5)
[ ] Establish log retention policy (Section 7)
```

### 10.2 Level 2: Comprehensive

```
[ ] Centralize logs in aggregation platform
[ ] Implement full alert rule set (Section 5.1)
[ ] Create security dashboard (Section 6)
[ ] Enable hash chain for tamper-evidence (Section 8)
[ ] Configure log rotation and archival
[ ] Document and train team on procedures
```

### 10.3 Level 3: Industry-Leading

```
[ ] Implement anomaly detection (Section 9)
[ ] Enable ML-based pattern detection
[ ] Automate incident creation from alerts
[ ] Predictive alerting (trending toward threshold)
[ ] Real-time correlation across systems
[ ] Regular red team testing of detection
[ ] Continuous improvement from incident learnings
```

---

## 11. HAIAMM Practice Mapping

| Practice | ML Contribution |
|----------|-----------------|
| TA (Threat Assessment) | Logs provide evidence for threat analysis |
| SR (Security Requirements) | Logging requirements documented |
| SA (Secure Architecture) | Logging integrated into architecture |
| IR (Implementation Review) | Log implementation reviewed |
| ST (Security Testing) | Logging tested for completeness |
| IM (Issue Management) | Logs enable incident investigation |

### Related Security Patterns

| Pattern | Reference |
|---------|-----------|
| Pattern 1: Secure Logging & Monitoring | HAI-Security-Architecture-Patterns.md |
| Pattern 5: Error Handling & Fail Secure | HAI-Security-Architecture-Patterns.md |

---

## 12. Operational Procedures

### 12.1 Log Investigation Procedure

```
1. Identify incident timeframe
2. Gather correlation ID(s)
3. Query logs across services using correlation ID
4. Build event timeline
5. Identify root cause
6. Document findings
7. Update detection rules if gap found
```

### 12.2 Alert Response Procedure

| Severity | Initial Response | Escalation | Resolution SLA |
|----------|------------------|------------|----------------|
| CRITICAL | Immediate investigation | Security Lead + Engineering | 1 hour |
| HIGH | Investigate within 15 min | Security team | 4 hours |
| MEDIUM | Investigate within 1 hour | Assigned engineer | 24 hours |
| LOW | Review in daily triage | None | 1 week |

### 12.3 Regular Review Cadence

| Activity | Frequency | Owner |
|----------|-----------|-------|
| Alert rule tuning | Weekly | Security team |
| Dashboard review | Daily | On-call engineer |
| Log retention verification | Monthly | SRE |
| Integrity check review | Weekly | Security team |
| Anomaly threshold tuning | Monthly | Security + ML team |

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | [Date] | [Author] | Initial monitoring and logging template |

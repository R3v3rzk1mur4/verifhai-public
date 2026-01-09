# Environment Hardening (EH) Template

## Document Control

| Field | Value |
|-------|-------|
| Project | [Project Name] |
| Environment | Development / Staging / Production |
| Version | 1.0 |
| Date | [YYYY-MM-DD] |
| Author | [Author Name] |
| Status | Draft / Implemented / Verified |

---

## 1. Environment Overview

### 1.1 Environment Description

```
[Describe the environment being hardened]

Environment Type: [ ] Development [ ] Staging [ ] Production
Hosting: [ ] Cloud (specify) [ ] On-premise [ ] Hybrid
Container Runtime: [ ] Docker [ ] Kubernetes [ ] Other
AI Components: [ ] Agent [ ] LLM API [ ] Pipeline [ ] Infrastructure
```

### 1.2 Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    PRODUCTION ENVIRONMENT                        │
│                                                                  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │   Load      │    │   App       │    │   AI        │         │
│  │  Balancer   │───▶│  Servers    │───▶│  Services   │         │
│  └─────────────┘    └─────────────┘    └─────────────┘         │
│                            │                  │                  │
│                            ▼                  ▼                  │
│                     ┌─────────────┐    ┌─────────────┐         │
│                     │  Database   │    │   LLM API   │         │
│                     │  (Internal) │    │  (External) │         │
│                     └─────────────┘    └─────────────┘         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 1.3 Component Inventory

| Component | Version | Purpose | Risk Level | Owner |
|-----------|---------|---------|------------|-------|
| [OS] | [Version] | [Purpose] | [Risk] | [Who] |
| [Runtime] | [Version] | [Purpose] | [Risk] | [Who] |
| [AI Framework] | [Version] | [Purpose] | [Risk] | [Who] |
| [Database] | [Version] | [Purpose] | [Risk] | [Who] |

---

## 2. OS & Platform Hardening

### 2.1 Operating System

| ID | Control | Status | Implementation |
|----|---------|--------|----------------|
| EH-OS-001 | Minimal OS installation | [ ] Done | Remove unnecessary packages |
| EH-OS-002 | Security updates applied | [ ] Done | Patch management in place |
| EH-OS-003 | Unnecessary services disabled | [ ] Done | List: [services removed] |
| EH-OS-004 | Host firewall configured | [ ] Done | iptables/nftables rules |
| EH-OS-005 | SELinux/AppArmor enabled | [ ] Done | Mode: [enforcing/permissive] |
| EH-OS-006 | Audit logging enabled | [ ] Done | auditd configured |
| EH-OS-007 | SSH hardened | [ ] Done | Key-only, no root login |
| EH-OS-008 | Time synchronization | [ ] Done | NTP/chronyd configured |

**OS Hardening Script Reference:**
```bash
# Example hardening commands (adapt to your OS)
# Disable unnecessary services
systemctl disable bluetooth cups avahi-daemon

# Configure SSH hardening
echo "PermitRootLogin no" >> /etc/ssh/sshd_config
echo "PasswordAuthentication no" >> /etc/ssh/sshd_config

# Enable audit logging
systemctl enable auditd
```

### 2.2 Container Runtime (Docker/Podman)

| ID | Control | Status | Implementation |
|----|---------|--------|----------------|
| EH-CT-001 | Use minimal base images | [ ] Done | distroless/alpine |
| EH-CT-002 | Run as non-root user | [ ] Done | USER directive in Dockerfile |
| EH-CT-003 | Read-only filesystem | [ ] Done | --read-only flag |
| EH-CT-004 | No privileged containers | [ ] Done | --privileged never used |
| EH-CT-005 | Drop all capabilities | [ ] Done | --cap-drop ALL |
| EH-CT-006 | Limit resources | [ ] Done | --memory, --cpus limits |
| EH-CT-007 | No host network mode | [ ] Done | Use bridge/overlay |
| EH-CT-008 | Scan images for vulnerabilities | [ ] Done | Trivy/Snyk in CI |

**Secure Dockerfile Template:**
```dockerfile
# Use minimal base
FROM python:3.11-slim AS base

# Create non-root user
RUN useradd --create-home --shell /bin/bash appuser

# Copy application
WORKDIR /app
COPY --chown=appuser:appuser . .

# Install dependencies (no cache to reduce image size)
RUN pip install --no-cache-dir -r requirements.txt

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://localhost:8000/health || exit 1

# Run application
CMD ["python", "main.py"]
```

**Docker Run Security:**
```bash
docker run \
  --read-only \
  --user 1000:1000 \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --memory 512m \
  --cpus 1.0 \
  --network app-network \
  my-ai-app:latest
```

### 2.3 Kubernetes Hardening

| ID | Control | Status | Implementation |
|----|---------|--------|----------------|
| EH-K8-001 | Pod Security Standards | [ ] Done | restricted/baseline |
| EH-K8-002 | Network Policies | [ ] Done | Default deny, explicit allow |
| EH-K8-003 | RBAC properly configured | [ ] Done | Least privilege roles |
| EH-K8-004 | Service accounts restricted | [ ] Done | automountServiceAccountToken: false |
| EH-K8-005 | Secrets encrypted at rest | [ ] Done | EncryptionConfiguration |
| EH-K8-006 | Resource limits enforced | [ ] Done | LimitRange/ResourceQuota |
| EH-K8-007 | Container registry restricted | [ ] Done | ImagePolicyWebhook |
| EH-K8-008 | Admission controllers enabled | [ ] Done | PodSecurity, OPA/Gatekeeper |

**Secure Pod Template:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: ai-agent-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: ai-agent
    image: my-ai-agent:latest
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
    resources:
      limits:
        memory: "512Mi"
        cpu: "1000m"
      requests:
        memory: "256Mi"
        cpu: "500m"
    volumeMounts:
    - name: tmp
      mountPath: /tmp
  volumes:
  - name: tmp
    emptyDir: {}
  automountServiceAccountToken: false
```

**Network Policy Example:**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ai-agent-network-policy
spec:
  podSelector:
    matchLabels:
      app: ai-agent
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: api-gateway
    ports:
    - protocol: TCP
      port: 8000
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 5432
  - to:
    # Allow external LLM API
    - ipBlock:
        cidr: 0.0.0.0/0
    ports:
    - protocol: TCP
      port: 443
```

---

## 3. Application Runtime Hardening

### 3.1 Runtime Configuration

| ID | Control | Status | Implementation |
|----|---------|--------|----------------|
| EH-RT-001 | Debug mode disabled | [ ] Done | DEBUG=false in production |
| EH-RT-002 | Verbose errors disabled | [ ] Done | Generic error messages |
| EH-RT-003 | Stack traces hidden | [ ] Done | Not exposed to users |
| EH-RT-004 | Development endpoints disabled | [ ] Done | /debug removed |
| EH-RT-005 | Hot reload disabled | [ ] Done | Production mode only |
| EH-RT-006 | Appropriate log level | [ ] Done | INFO in production |

### 3.2 AI Agent Runtime Containment

| ID | Control | Status | Implementation |
|----|---------|--------|----------------|
| EH-AI-001 | Iteration limits enforced | [ ] Done | Max: [number] |
| EH-AI-002 | Token budget limits | [ ] Done | Max: [number] tokens |
| EH-AI-003 | Timeout protection | [ ] Done | Max: [duration] |
| EH-AI-004 | Memory limits | [ ] Done | Max: [amount] |
| EH-AI-005 | Kill switch accessible | [ ] Done | [Mechanism] |
| EH-AI-006 | Subprocess restrictions | [ ] Done | No shell access |
| EH-AI-007 | File system restrictions | [ ] Done | Allowed paths only |
| EH-AI-008 | Network egress restrictions | [ ] Done | Allowlisted endpoints |

**Agent Containment Configuration:**
```typescript
// HAI Agent containment configuration
const agentConfig: AgentContainment = {
  limits: {
    maxIterations: 50,
    maxTokens: 100000,
    timeoutMs: 300000,  // 5 minutes
    memoryMb: 512,
  },
  restrictions: {
    allowedPaths: ['/app/workspace', '/tmp'],
    allowedHosts: ['api.anthropic.com', 'api.openai.com'],
    allowShell: false,
    allowSubprocess: false,
  },
  killSwitch: {
    enabled: true,
    checkInterval: 1000,  // Check every second
    gracefulShutdownMs: 5000,
  }
};
```

### 3.3 Dependency Management

| ID | Control | Status | Implementation |
|----|---------|--------|----------------|
| EH-DP-001 | Dependencies pinned | [ ] Done | Lockfile committed |
| EH-DP-002 | Vulnerability scanning | [ ] Done | Snyk/Dependabot |
| EH-DP-003 | No unnecessary deps | [ ] Done | Minimal dependencies |
| EH-DP-004 | Regular updates | [ ] Done | Monthly review |
| EH-DP-005 | License compliance | [ ] Done | [License scanner] |
| EH-DP-006 | Integrity verification | [ ] Done | Package signatures |

---

## 4. Network Hardening

### 4.1 Network Segmentation

| Zone | Purpose | Access From | Access To |
|------|---------|-------------|-----------|
| DMZ | Public-facing | Internet | App tier |
| App | Application servers | DMZ, Admin | DB, AI Services |
| DB | Database | App tier only | None |
| AI | AI services | App tier | LLM API (external) |
| Admin | Management | VPN only | All (restricted) |

**Network Diagram:**
```
┌─────────────────────────────────────────────────────────────────┐
│                        INTERNET                                  │
└──────────────────────────┬──────────────────────────────────────┘
                           │
              ┌────────────▼────────────┐
              │         DMZ             │
              │   (Load Balancer, WAF)  │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │       APP TIER          │
              │   (Application Servers) │
              └─────┬──────────┬────────┘
                    │          │
         ┌──────────▼───┐  ┌───▼──────────┐
         │   DB TIER    │  │   AI TIER    │
         │  (Database)  │  │ (AI Services)│
         └──────────────┘  └──────────────┘
```

### 4.2 Network Controls

| ID | Control | Status | Implementation |
|----|---------|--------|----------------|
| EH-NW-001 | TLS 1.3 enforced | [ ] Done | min_version = TLS1.3 |
| EH-NW-002 | Certificate validation | [ ] Done | No self-signed in prod |
| EH-NW-003 | WAF configured | [ ] Done | [WAF provider] |
| EH-NW-004 | DDoS protection | [ ] Done | [Provider] |
| EH-NW-005 | Rate limiting at edge | [ ] Done | [Limits] |
| EH-NW-006 | Egress filtering | [ ] Done | Allowlist only |
| EH-NW-007 | Internal traffic encrypted | [ ] Done | mTLS |
| EH-NW-008 | DNS security | [ ] Done | DNSSEC, DoH |

### 4.3 API Security

| ID | Control | Status | Implementation |
|----|---------|--------|----------------|
| EH-AP-001 | Authentication required | [ ] Done | [Mechanism] |
| EH-AP-002 | Authorization enforced | [ ] Done | [Model] |
| EH-AP-003 | Rate limiting per user | [ ] Done | [Limits] |
| EH-AP-004 | Input validation | [ ] Done | Schema validation |
| EH-AP-005 | CORS properly configured | [ ] Done | Allowlist only |
| EH-AP-006 | Security headers set | [ ] Done | CSP, HSTS, etc. |
| EH-AP-007 | Request size limits | [ ] Done | [Max size] |
| EH-AP-008 | API versioning | [ ] Done | [Strategy] |

---

## 5. Secrets Management

### 5.1 Secrets Inventory

| Secret Type | Storage | Rotation | Access Control |
|-------------|---------|----------|----------------|
| API Keys (LLM) | [Vault/AWS SM/etc.] | [Frequency] | [Who] |
| Database credentials | [Vault/AWS SM/etc.] | [Frequency] | [Who] |
| TLS certificates | [ACM/Vault/etc.] | Auto-renew | [Who] |
| Signing keys | [HSM/Vault/etc.] | [Frequency] | [Who] |

### 5.2 Secrets Controls

| ID | Control | Status | Implementation |
|----|---------|--------|----------------|
| EH-SC-001 | No secrets in code | [ ] Done | Pre-commit hooks |
| EH-SC-002 | Secrets manager used | [ ] Done | [Provider] |
| EH-SC-003 | Secrets encrypted at rest | [ ] Done | AES-256 |
| EH-SC-004 | Secrets encrypted in transit | [ ] Done | TLS |
| EH-SC-005 | Rotation automated | [ ] Done | [Schedule] |
| EH-SC-006 | Access audited | [ ] Done | Audit logs |
| EH-SC-007 | Least privilege access | [ ] Done | RBAC |
| EH-SC-008 | Emergency rotation procedure | [ ] Done | Documented |

---

## 6. Monitoring & Detection Hardening

### 6.1 Security Monitoring

| ID | Control | Status | Implementation |
|----|---------|--------|----------------|
| EH-MN-001 | Security event logging | [ ] Done | [SIEM] |
| EH-MN-002 | Log integrity protection | [ ] Done | Hash chain/WORM |
| EH-MN-003 | Log retention | [ ] Done | [Duration] |
| EH-MN-004 | Alerting configured | [ ] Done | [Thresholds] |
| EH-MN-005 | Anomaly detection | [ ] Done | [Mechanism] |
| EH-MN-006 | Dashboard available | [ ] Done | [Tool] |
| EH-MN-007 | On-call rotation | [ ] Done | [Schedule] |
| EH-MN-008 | Runbooks documented | [ ] Done | [Location] |

### 6.2 AI-Specific Monitoring

| Metric | Threshold | Alert | Action |
|--------|-----------|-------|--------|
| Permission denials/hour | > 100 | High | Investigate attack |
| Injection attempts | > 10 | Critical | Block + investigate |
| Agent iterations | > 80% limit | Medium | Review behavior |
| Token usage spike | > 3x baseline | Medium | Check for abuse |
| Error rate | > 5% | High | Investigate |
| Response latency | > 10s p99 | Medium | Scale/optimize |

---

## 7. Backup & Recovery

### 7.1 Backup Configuration

| Data Type | Frequency | Retention | Storage | Encryption |
|-----------|-----------|-----------|---------|------------|
| Database | [Hourly/Daily] | [X days] | [Location] | [ ] Yes |
| Logs | [Real-time] | [X days] | [Location] | [ ] Yes |
| Config | [On change] | [X versions] | [Location] | [ ] Yes |
| Secrets | [On rotation] | [X versions] | [Location] | [ ] Yes |

### 7.2 Recovery Procedures

| Scenario | RTO | RPO | Procedure |
|----------|-----|-----|-----------|
| Database failure | [Time] | [Data loss] | [Link] |
| AI service failure | [Time] | N/A | [Link] |
| Region failure | [Time] | [Data loss] | [Link] |
| Security incident | [Time] | Preserve all | [Link] |

---

## 8. Verification Checklist

### 8.1 Pre-Deployment Verification

| Check | Method | Result | Date |
|-------|--------|--------|------|
| Vulnerability scan | [Scanner] | [ ] Pass / [ ] Fail | |
| Compliance check | [Tool] | [ ] Pass / [ ] Fail | |
| Secrets scan | [Tool] | [ ] Pass / [ ] Fail | |
| Configuration audit | Manual | [ ] Pass / [ ] Fail | |
| Network scan | [Tool] | [ ] Pass / [ ] Fail | |
| Penetration test | [Method] | [ ] Pass / [ ] Fail | |

### 8.2 Ongoing Verification

| Check | Frequency | Owner | Last Run |
|-------|-----------|-------|----------|
| Vulnerability scan | Weekly | [Who] | [Date] |
| Configuration drift | Daily | [Who] | [Date] |
| Access review | Quarterly | [Who] | [Date] |
| Penetration test | Annual | [Who] | [Date] |

---

## 9. Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| DevOps Engineer | | | |
| Security Engineer | | | |
| Operations Lead | | | |

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | [Date] | [Author] | Initial hardening baseline |

# SENTINEL SOC - System Architecture & Technical Specifications

## 1. Executive Summary & Objective

**SENTINEL SOC** is a Security Operations Center (SOC) platform engineered to address the critical gap between traditional secure file transfer (SFTP/HTTPS) and automated security telemetry. While traditional transfer solutions solely focus on point-to-point delivery, SENTINEL SOC continuously inspects, validates, scores, logs, and alerts on file-transfer behaviors in real time.

---

## 2. High-Level Architecture

```
                                 [ Client / Operator Browser ]
                                              │
                      ┌───────────────────────┴───────────────────────┐
                      ▼ (HTTPS)                                       ▼ (WSS)
           ┌──────────────────────┐                      ┌────────────────────────┐
           │   FastAPI Gateway    │                      │  WebSocket Telemetry   │
           │ (REST APIs & Auth)   │                      │  (Live Event Streaming)│
           └──────────┬───────────┘                      └──────────▲─────────────┘
                      │                                             │
      ┌───────────────┴───────────────┐                             │
      ▼                               ▼                             │
┌──────────────┐             ┌─────────────────────┐                │
│  JWT & RBAC  │             │ Secure File Ingest  │                │
│  Dependency  │             │ - Path Sanitization │                │
│  Guards      │             │ - SHA-256 Digest    │                │
└──────────────┘             │ - Storage Isolation │                │
                             └──────────┬──────────┘                │
                                        │                           │
                                        ▼                           │
                             ┌─────────────────────┐                │
                             │  Detection Engine   ├────────────────┤
                             │  (7 Heuristic Rules)│                │
                             └──────────┬──────────┘                │
                                        │                           │
                                        ▼                           │
                             ┌─────────────────────┐                │
                             │ Dynamic Risk Scorer ├────────────────┤
                             │ (0 - 100 Algorithm) │                │
                             └──────────┬──────────┘                │
                                        │                           │
                                        ▼                           │
                             ┌─────────────────────┐                │
                             │  Incident & Alerts  ├────────────────┘
                             │  (Triage Lifecycle) │
                             └──────────┬──────────┘
                                        │
                      ┌─────────────────┴─────────────────┐
                      ▼                                   ▼
           ┌─────────────────────┐             ┌─────────────────────┐
           │ Relational Storage  │             │ Tamper-Evident      │
           │ (SQLite / Postgres) │             │ Audit Trail Log     │
           └─────────────────────┘             └─────────────────────┘
```

---

## 3. Defense-in-Depth Security Pipeline

### 3.1 Anti-Path Traversal & Filename Sanitization
- Rejects null-byte injection (`\x00`).
- Rejects relative directory traversal patterns (`../`, `..\\`).
- Enforces basename extraction via regex: `re.sub(r'[^a-zA-Z0-9._-]', '_', basename)`.
- Validates canonical path boundaries with `Path.is_relative_to(target_dir)`.

### 3.2 Streaming Chunked Cryptographic Verification
- Computes SHA-256 digests in streaming 64 KB memory chunks (`hashlib.sha256()`).
- Never buffers arbitrary files completely into system RAM.
- Verifies client-supplied `expected_hash`:
  - **Match:** `integrity_status = VERIFIED`, saved to `backend/storage/uploads`.
  - **Mismatch:** `integrity_status = MISMATCH`, immediate quarantine isolation in `backend/storage/quarantine`, and status marked `QUARANTINED`.

---

## 4. Security Rule Detection Engine

The detection pipeline inspects every transfer against 7 active heuristic rules:

| Rule Code | Rule Name | Condition Trigger | Risk Weight | Default Severity |
| :--- | :--- | :--- | :--- | :--- |
| `RULE_LARGE_FILE` | Oversized File Transfer | File size > 50 MB threshold | 20 | HIGH |
| `RULE_OFF_HOURS` | Off-Hours Activity | Weekends or outside 09:00–18:00 UTC | 20 | MEDIUM |
| `RULE_UNKNOWN_DEST`| Untrusted Destination IP | IP outside approved RFC 1918 subnets | 30 | HIGH |
| `RULE_EXCESSIVE_TX`| Excessive Transfer Burst| > 10 transfers within 10-minute window | 20 | MEDIUM |
| `RULE_INSECURE_PROTO`| Insecure Protocol | Plaintext protocol (FTP, HTTP, TELNET) | 20 | HIGH |
| `RULE_INTEGRITY_FAIL`| SHA-256 Mismatch | Checksum differs from expected digest | 30 | CRITICAL |
| `RULE_FAILED_PATTERN`| Repeated Failures | >= 3 consecutive failed transfers | 15 | MEDIUM |

---

## 5. Dynamic Risk Scoring Model

The risk score $R \in [0, 100]$ is computed as the bounded sum of rule weights plus external threat intelligence:

$$R = \min\left(100, \sum_{i=1}^{n} w_i + \text{ThreatReputationBonus}\right)$$

### Classification Bands:
- **0 – 29: LOW** (Normal benign enterprise activity)
- **30 – 59: MEDIUM** (Heuristic anomaly, automated audit logging)
- **60 – 79: HIGH** (Suspicious activity, security alert triggered)
- **80 – 100: CRITICAL** (Critical incident, automatic quarantine, analyst notification)

---

## 6. Incident Triage Lifecycle

```
[ Automated Trigger ] ──> [ OPEN ]
                             │
                             ▼ (Analyst Takes Ownership)
                      [ INVESTIGATING ]
                             │
            ┌────────────────┴────────────────┐
            ▼                                 ▼
      [ RESOLVED ]                   [ FALSE_POSITIVE ]
   (Threat Mitigated)             (Rule Tuning Applied)
```

---

## 7. Tamper-Evident Audit Logging & Compliance

Every state-modifying request is captured in the immutable `audit_logs` table:
- Timestamp (UTC ISO 8601)
- Authenticated user ID and username
- Action type (`FILE_UPLOAD`, `ALERT_GENERATED`, `ALERT_UPDATED`, `RULE_UPDATED`, `AUTH_LOGIN`)
- Resource type and Resource UUID
- Client IP address and HTTP status
- Full JSON snapshot of changes and context

### Report Generation
- **PDF Reports:** Formatted using `reportlab` with executive summary statistics, security violation highlights, and tabular audit logs.
- **CSV Exports:** RFC 4180 compliant exports for external SIEM integration (Splunk, Elastic, Sentinel).

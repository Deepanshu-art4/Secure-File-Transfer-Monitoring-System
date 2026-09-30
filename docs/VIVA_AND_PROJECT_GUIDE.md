# SENTINEL SOC - Viva Defense & Project Presentation Guide

This guide prepares you to present, explain, and defend the **Secure File Transfer Monitoring System (SENTINEL SOC)** during viva examinations, technical audits, and capstone demonstrations.

---

## 1. Quick Project Pitch (30-Second Elevator Pitch)

> *"SENTINEL SOC is a Security Operations Center platform designed to secure and monitor enterprise file transfers. While standard tools like SFTP or cloud buckets simply move files blindly, SENTINEL continuously validates cryptographic integrity with SHA-256 digests, applies a 7-rule behavioral heuristic detection engine, dynamically scores risk from 0 to 100, pushes real-time telemetry over WebSockets to a live analyst dashboard, and automates incident triage with full tamper-evident audit logging and PDF compliance exports."*

---

## 2. Step-by-Step Live Demo Script

When demonstrating the system to evaluators:

### Step 1: Start the Platform
```bash
python scripts/init_db.py
uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```
Open **`http://127.0.0.1:8000`** in the browser.

### Step 2: Show the Real-Time SOC Dashboard
- Point out the **Live Telemetry (WebSocket)** green pulse indicator in the header.
- Explain the 4 KPI counters: **Total Transfers**, **Quarantined Payloads**, **Active Open Incidents**, and **Average Platform Risk**.
- Show the **Incident Severity Distribution** and **Protocol Breakdown** live charts.

### Step 3: Demonstrate Legitimate Transfer
1. Navigate to **Secure Transfers**.
2. Select any benign file (`.pdf`, `.csv`, `.docx`).
3. Note how the browser **automatically computes the SHA-256 hash** client-side before sending.
4. Click **Auto-Match** for Expected SHA-256.
5. Click **Transmit & Inspect File**.
6. Show that integrity is **`VERIFIED`**, status is **`SUCCESS`**, and risk is **`LOW`**.

### Step 4: Demonstrate Automated Attack Detection & Quarantine
1. Select another file.
2. Click **Simulate Tampering** (replaces expected hash with fake digest).
3. Set Destination IP to `185.220.101.5` (an external Tor exit node).
4. Select protocol `FTP` (plain text protocol).
5. Click **Transmit & Inspect File**.
6. **Result:**
   - Transfer is immediately flagged and **`QUARANTINED`**.
   - Risk score jumps to **`CRITICAL` (90+)**.
   - Physical payload is segregated into `backend/storage/quarantine`.
   - A live toast notification appears in real-time without page refresh!

### Step 5: Incident Triage Workflow
1. Switch to **Incident Triage**.
2. Click the newly generated Critical Incident.
3. Review the triggered violation breakdown (Checksum Mismatch + Untrusted Destination + Insecure Protocol).
4. Click **Investigate** (transitions status from `OPEN` to `INVESTIGATING`).
5. Type analyst findings in the notes editor and click **Save Investigation Findings**.
6. Click **Resolve** once mitigated.

### Step 6: Threat Intelligence & Compliance Export
1. Switch to **Threat Intelligence** and query `185.220.101.5` to show live threat classification and reputation score.
2. Switch to **Audit Trail & Reports**.
3. Click **Download Transfers PDF** and **Download Incidents PDF** to showcase the executive compliance reporting capability.

---

## 3. High-Frequency Viva Questions & Model Answers

### Q1: How does your system defend against directory traversal attacks?
**Answer:**
We implement defense-in-depth:
1. First, we reject filenames containing null-byte injections (`\x00`) and traversal patterns (`..`, `/`, `\`).
2. Second, we extract the strict basename using regex sanitization (`re.sub(r'[^a-zA-Z0-9._-]', '_', basename)`).
3. Third, before writing to disk, we compute the target path and assert `target_path.is_relative_to(target_directory)`. Any path escape attempt raises an immediate HTTP 400 security exception.

### Q2: Why stream SHA-256 calculation instead of reading `file.read()` directly?
**Answer:**
Reading large files entirely into RAM causes high memory spikes and exposes the server to Denial of Service (DoS) attacks via memory exhaustion. SENTINEL streams files in **64 KB chunks** directly through Python's `hashlib.sha256()`, maintaining $O(1)$ constant memory consumption regardless of file size (up to the 100 MB configured maximum).

### Q3: What is the risk scoring formula and how are weights determined?
**Answer:**
The dynamic risk score is a bounded cumulative index $R = \min(100, \sum w_i + T)$. Critical events like cryptographic hash mismatch carry 30 points, while high-severity violations (untrusted IP, large payloads) carry 20-30 points. If the cumulative score exceeds the organizational threshold (default: 30), an incident alert is automatically generated in the triage queue.

### Q4: How does real-time communication work without page refresh?
**Answer:**
We implement an asynchronous WebSocket hub using FastAPI and Starlette. When transfers or alerts are committed to the database, the backend broadcasts JSON events (`TRANSFER_CREATED`, `ALERT_TRIGGERED`, `ALERT_UPDATED`) to all connected SOC clients via `ws_manager.broadcast()`. The client React application listens and updates KPI metrics, toast notifications, and event streams instantaneously.

### Q5: How is role-based access control (RBAC) enforced?
**Answer:**
We use JWT bearer tokens with FastAPI dependency injection (`Depends(get_current_user)`). Routes use permission wrappers like `require_analyst_or_admin` or `require_admin`. Standard users can only view their own transfers and alerts; analysts can triage incidents and view global logs; administrators can toggle security rules and manage user accounts.

### Q6: What happens if an external threat intelligence API (like AbuseIPDB) is down or slow?
**Answer:**
We implement a local 24-hour cache in the `threat_intel_records` database table, built-in threat signatures for known malicious IPs, and asynchronous non-blocking HTTP requests with a strict 5.0-second timeout. If the external provider times out, the system falls back safely without disrupting file transfers.

# Sentinel SOC: Secure File Transfer Monitoring System

[![CI Security Test Suite](https://github.com/Deepanshu-art4/Secure-File-Transfer-Monitoring-System/actions/workflows/ci.yml/badge.svg)](https://github.com/Deepanshu-art4/Secure-File-Transfer-Monitoring-System/actions/workflows/ci.yml)
[![Deploy Console to GitHub Pages](https://github.com/Deepanshu-art4/Secure-File-Transfer-Monitoring-System/actions/workflows/deploy-pages.yml/badge.svg)](https://github.com/Deepanshu-art4/Secure-File-Transfer-Monitoring-System/actions/workflows/deploy-pages.yml)
[![Live Demo](https://img.shields.io/badge/Live_Console-GitHub_Pages-06b6d4?style=flat&logo=github)](https://deepanshu-art4.github.io/Secure-File-Transfer-Monitoring-System/)
![Python Version](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.13-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-18+-61DAFB?logo=react&logoColor=black)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue.svg)

An enterprise-grade Cybersecurity & Security Operations Center (SOC) platform designed to handle secure file transfers while continuously monitoring, logging, analyzing, and detecting suspicious file-transfer activities in real time.

> 🌐 **Live Interactive SOC Console:** [https://deepanshu-art4.github.io/Secure-File-Transfer-Monitoring-System/](https://deepanshu-art4.github.io/Secure-File-Transfer-Monitoring-System/)  
> *(Runs zero-install in the browser with real in-browser SHA-256 calculation, detection heuristic simulations, alert triage lifecycles, and direct API switcher.)*

---

## 🌟 Key Highlights

- **Secure Ingestion & Validation:** Path-traversal proof upload pipeline, strict MIME verification, and SHA-256 cryptographic integrity verification.
- **Configurable Security Rule Engine:** Detection of off-hours transfers, oversized payloads (>50MB), unknown/untrusted destination IPs, rapid transfer bursts, and insecure legacy protocols (FTP, Telnet).
- **Dynamic Risk Scoring:** Weighted 0–100 scoring model classifying events into **LOW**, **MEDIUM**, **HIGH**, and **CRITICAL** risk levels.
- **Real-Time SOC Telemetry:** WebSocket-powered event stream and live KPI dashboard updating without page refreshes.
- **Incident Triage & Alert Lifecycle:** Role-based incident state transitions (`OPEN` ➔ `INVESTIGATING` ➔ `RESOLVED` / `FALSE_POSITIVE`) with analyst forensic audit notes.
- **Threat Intelligence Lookup:** IP reputation scoring and external indicator-of-compromise (IOC) caching.
- **Tamper-Evident Audit Trail:** Immutable logging of all sensitive administrative, authentication, and file operations with client IP attribution.
- **Compliance Reporting:** Instant export of comprehensive transfer audits and security incident summaries in formal PDF and RFC 4180 CSV formats.

---

## 🏗️ High-Level Architecture

```
User / Analyst Browser
       │
       ▼  (HTTPS / WSS)
FastAPI Backend Gateway (:8000)
  ├── JWT Auth & Role-Based Access Control (Admin / Analyst / User)
  ├── File Transfer Engine (SHA-256 Verification & Storage Isolation)
  ├── Security Detection Pipeline
  │     ├── Rule Engine (Off-Hours, Size, Frequency, Protocol, Destination)
  │     ├── Statistical Anomaly Baseline
  │     └── Modular Threat Intelligence Lookups
  ├── Weighted Risk Scorer (0 - 100 Scale)
  ├── Incident & Alert Manager
  ├── Real-time WebSocket Hub
  └── Audit Logger
       │
       ▼
Relational Storage (PostgreSQL / SQLite zero-config development)
```

---

## 💻 Tech Stack

- **Backend:** Python 3.11+, FastAPI, Uvicorn, WebSockets, Pydantic v2, SQLAlchemy 2.0
- **Frontend:** React 18+, Tailwind CSS, JetBrains Mono font, HTML5 Web Cryptography API
- **Database:** PostgreSQL (with SQLite zero-config development fallback)
- **Security:** SHA-256 Digest Verification, Salted Bcrypt Password Hashing, PyJWT Token Authentication
- **DevOps & CI/CD:** Docker, Docker Compose, GitHub Actions, GitHub Pages

---

## 📂 Directory Structure

```text
Secure File Transfer Monitoring System/
│
├── .github/
│   └── workflows/
│       ├── ci.yml                     # Automated Pytest suite across Python 3.11, 3.12, 3.13
│       └── deploy-pages.yml           # Automated deployment of console to GitHub Pages
│
├── backend/
│   ├── api/
│   │   └── routes/                    # REST handlers (auth, transfers, alerts, rules, etc.)
│   ├── core/                          # App config, database session, security utilities
│   ├── models/                        # SQLAlchemy database models & enums
│   ├── schemas/                       # Pydantic schemas & validators
│   ├── services/                      # Transfer management, file storage, report generation
│   ├── detection/                     # Rule engine & anomaly detection heuristics
│   ├── risk/                          # Weighted risk scoring engine
│   ├── alerts/                        # Incident management & alert lifecycle
│   ├── threat_intel/                  # IP reputation & threat intelligence lookups
│   ├── audit/                         # Tamper-evident audit logging
│   ├── monitoring/                    # WebSocket connection manager & telemetry metrics
│   ├── storage/                       # Isolated storage (uploads, quarantine, reports)
│   ├── requirements.txt               # Backend Python dependencies
│   └── main.py                        # FastAPI entrypoint & router aggregation
│
├── frontend/                          # React SOC Console
│   ├── index.html                     # Standalone single-page SOC app with live/demo switcher
│   └── src/                           # Component sources
│
├── database/                          # Database migrations
├── tests/                             # Automated test suite (37 passing security tests)
├── docs/                              # Architecture specs & viva examination guides
├── diagrams/                          # Architecture & ER diagrams
├── scripts/                           # Database initialization & testing utilities
├── docker/                            # Dockerfile.backend, Dockerfile.frontend, nginx.conf
├── docker-compose.yml                 # Multi-container production deployment
├── .env.example                       # Environment configuration template
├── .gitignore                         # Git exclusion rules
├── LICENSE                            # MIT License
└── README.md
```

---

## 🚀 Quickstart Guide

### 1. Clone & Set Up Environment

```bash
git clone https://github.com/Deepanshu-art4/Secure-File-Transfer-Monitoring-System.git
cd Secure-File-Transfer-Monitoring-System
```

Create `.env` from template:

```bash
cp .env.example .env
```

### 2. Run Backend with Python

```bash
# Create and activate virtual environment
python -m venv venv

# On Windows PowerShell:
.\venv\Scripts\Activate.ps1
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r backend/requirements.txt pytest

# Initialize database schema and default seed data
python scripts/init_db.py

# Launch FastAPI development server
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

The server will be available at:
- **Interactive SOC Console:** `http://127.0.0.1:8000`
- **Interactive Swagger API Docs:** `http://127.0.0.1:8000/api/v1/docs`
- **ReDoc Documentation:** `http://127.0.0.1:8000/api/v1/redoc`

---

## 🔑 Default Credentials

The initialization script (`scripts/init_db.py`) pre-seeds three default roles:

| Username | Password | Role | Permissions |
|---|---|---|---|
| `admin` | `AdminPassword@2026` | `ADMIN` | Full administrative control, rule toggles, audit logs |
| `analyst` | `AnalystPassword@2026` | `ANALYST` | Incident triage, alert status updates, investigation notes |
| `user1` | `UserPassword@2026` | `USER` | Standard operator, file upload and transfer inspections |

---

## 🧪 Running Automated Tests

Run the complete 37-test security and detection verification suite:

```bash
pytest tests/ -v
```

Tests cover:
- Cryptographic hash verification and tamper rejection
- Rule engine threshold evaluations (size, off-hours, protocols, bursts)
- Risk scoring weight computation
- Incident alert state machine transitions
- JWT authentication and role-based route protection

---

## 🐳 Docker & Container Deployment

To launch the entire platform (FastAPI backend + Nginx frontend + persistent volumes) using Docker Compose:

```bash
docker compose up --build -d
```

- **Frontend Console:** `http://localhost`
- **Backend API:** `http://localhost:8000/api/v1/docs`

---

## 🌐 Cloud Deployment Options

### Deploying Frontend to GitHub Pages
The project includes a GitHub Actions workflow (`.github/workflows/deploy-pages.yml`). Any push to `main` deploys the interactive console automatically to:
`https://<username>.github.io/<repository-name>/`

### Deploying Backend to Render / Railway / Fly.io
1. Create a Web Service pointing to this repository.
2. Build Command: `pip install -r backend/requirements.txt`
3. Start Command: `python scripts/init_db.py && uvicorn backend.main:app --host 0.0.0.0 --port $PORT`
4. Set environment variables from `.env.example`.
5. Open the GitHub Pages frontend and click **⚙️ API Settings** to point to your live cloud backend URL!

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

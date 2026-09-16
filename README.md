# Secure File Transfer Monitoring System

An enterprise-grade Cybersecurity & Security Operations Center (SOC) platform designed to handle secure file transfers while continuously monitoring, logging, analyzing, and detecting suspicious file-transfer activities.

---

## Key Highlights

- **Secure Ingestion & Validation:** Path-traversal proof upload pipeline, MIME verification, and SHA-256 integrity verification.
- **Configurable Security Rule Engine:** Detection of off-hours transfers, oversized payloads, unknown/untrusted destination IPs, rapid transfer bursts, and insecure protocols.
- **Dynamic Risk Scoring:** Weighted 0–100 scoring model classifying events into **LOW**, **MEDIUM**, **HIGH**, and **CRITICAL**.
- **Real-Time SOC Telemetry:** WebSocket-powered event stream and live KPI dashboard updating without page refreshes.
- **Incident Triage & Alert Lifecycle:** Role-based incident state transitions (`OPEN` -> `INVESTIGATING` -> `RESOLVED` / `FALSE_POSITIVE`) with analyst audit notes.
- **Tamper-Evident Audit Trail:** Immutable logging of all sensitive administrative, authentication, and file operations.
- **Compliance Reporting:** Instant export of comprehensive transfer audits and security incident summaries in PDF and CSV formats.

---

## High-Level Architecture

```
User / Client Browser
       │
       ▼  (HTTPS / WSS)
FastAPI Backend Gateway
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
Relational Storage (PostgreSQL / SQLite)
```

---

## Tech Stack

- **Backend:** Python 3.13, FastAPI, Uvicorn, WebSockets, Pydantic v2, SQLAlchemy 2.0
- **Frontend:** React 18+ (Vite), Tailwind CSS, Lucide React, Recharts
- **Database:** PostgreSQL (with SQLite zero-config development fallback)
- **Security:** SHA-256 Digest Verification, Salted Bcrypt Hashing, PyJWT Token Authentication
- **DevOps:** Docker, Docker Compose

---

## Directory Structure

```text
Secure File Transfer Monitoring System/
│
├── backend/
│   ├── api/
│   │   └── routes/          # REST route handlers (auth, transfers, alerts, rules, etc.)
│   ├── core/                # App config, database session, security utilities
│   ├── models/              # SQLAlchemy database models
│   ├── schemas/             # Pydantic schemas
│   ├── services/            # Transfer management, file storage, report generation
│   ├── detection/           # Rule engine & anomaly detection
│   ├── risk/                # Weighted risk scoring engine
│   ├── alerts/              # Incident management & alert lifecycle
│   ├── threat_intel/        # IP reputation & threat intelligence
│   ├── audit/               # Tamper-evident audit logging
│   ├── monitoring/          # WebSocket connection manager
│   ├── storage/             # Isolated file storage (uploads, quarantine, reports)
│   └── requirements.txt     # Backend Python dependencies
│
├── frontend/                # React Vite frontend
├── database/                # Alembic database migrations
├── tests/                   # Automated functional, security & detection tests
├── docs/                    # Academic documentation & viva defense guides
├── diagrams/                # Architecture & ER diagrams
├── docker/                  # Docker container configs
├── .env.example             # Environment configuration template
├── .gitignore               # Version control rules
└── README.md
```

---

## Quickstart Guide

### Prerequisites
- Python 3.10+
- Node.js 18+
- Git

### Initializing Environment
1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```
2. Set up Python virtual environment:
   ```bash
   cd backend
   python -m venv venv
   # On Windows PowerShell:
   .\venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

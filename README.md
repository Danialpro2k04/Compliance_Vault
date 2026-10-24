# ComplianceVault — Week 6: Governance & Audit Dashboard

> The governance layer for TradeGuard — tamper-evident audit trails, RBAC, compliance officer overrides, and regulatory report export.

## What This Is

ComplianceVault is the **governance and audit layer** that sits on top of the TradeGuard compliance pipeline (Weeks 1-5). In trade compliance, the AI's answer isn't enough — you need to prove **HOW** it arrived at that answer, **WHO** reviewed it, and that **NOBODY** tampered with the record after the fact.

## Features

### 1. Tamper-Evident Hash-Chained Audit Logs
Every AI decision and human action is recorded in an append-only log where each entry contains a SHA-256 hash of the previous entry. If anyone modifies a past entry, every subsequent hash breaks — providing tamper-evidence for regulatory auditors.

### 2. Web Dashboard
- Overview of all processed documents with status indicators (GREEN/YELLOW/RED)
- Click into any document to see the full agent decision chain
- Filter by date range, risk level, pipeline status
- Risk distribution visualization

### 3. RBAC (Role-Based Access Control)
Three roles with progressively more access:
- **Operator**: Submit documents, view own processing status
- **Compliance Officer**: Review flagged shipments, export reports
- **Administrator**: Override any AI decision, manage users, verify audit integrity

### 4. Compliance Officer Override
Per EU AI Act Article 14, authorized persons can override AI decisions with:
- Mandatory written justification (min 20 characters)
- Immutable logging in both document and governance audit trails
- Full traceability of who overrode what, when, and why

### 5. PDF Export
Generate professional compliance reports suitable for regulatory submission, including:
- Document summary, sanctions results, HS classification
- Decision chain and human review details
- Full hash-chained audit trail
- Export metadata with timestamp and generator info

### 6. Audit Chain Verification
Independent verification of audit chain integrity — any document's chain can be verified to confirm no entries have been modified.

## Quick Start

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the dashboard
uvicorn app.main:app --host 0.0.0.0 --port 8006 --reload
```

Open http://localhost:8006 and login with:
| Role | Username | Password |
|------|----------|----------|
| Admin | danyal | admin123 |
| Compliance Officer | sarah | officer123 |
| Operator | ali | operator123 |

## Running Tests

```bash
pytest tests/ -v
```

## API Endpoints

| Method | Path | Description | Role Required |
|--------|------|-------------|--------------|
| GET | `/` | Dashboard (HTML) | Any |
| GET | `/login` | Login page | None |
| POST | `/api/login` | Authenticate | None |
| POST | `/api/logout` | Logout | Any |
| GET | `/api/documents` | List documents | Any |
| GET | `/api/documents/{id}` | Document detail | Any |
| POST | `/api/override/{id}` | Override decision | Admin |
| GET | `/api/verify/{id}` | Verify audit chain | Any |
| GET | `/api/verify/governance` | Verify governance chain | Admin |
| GET | `/api/export/{id}` | Export PDF report | Officer+ |
| GET | `/api/stats` | Dashboard stats | Any |
| GET | `/api/governance-log` | Governance events | Admin |
| GET | `/api/users` | List users | Admin |
| GET | `/health` | Health check | None |

## Architecture

```
ComplianceVault (port 8006)
├── Web Dashboard (Jinja2 templates + vanilla JS)
├── RBAC Layer (session-based auth)
├── Document Store (in-memory, syncs with tradeguard_core)
├── Audit Store (JSONL append-only, hash-chained)
├── PDF Exporter (fpdf2)
└── Connects to: TradeGuard Core Pipeline (port 8005)
```

## Regulatory Alignment

- **EU AI Act Article 14**: Human oversight — authorized override with mandatory justification
- **EU AI Act Article 50**: Transparency — full decision chain visible per document
- **ISO/IEC 42001**: AI Management System — structured audit trails with chain integrity verification

## Project Structure

```
compliance_vault/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI app + all endpoints
│   ├── config.py             # Configuration & RBAC roles
│   ├── schemas.py            # Pydantic data models
│   ├── rbac.py               # Authentication & authorization
│   ├── audit_store.py        # Hash-chained governance audit log
│   ├── document_store.py     # Document state management + overrides
│   ├── pdf_exporter.py       # PDF compliance report generation
│   ├── templates/
│   │   ├── login.html
│   │   ├── dashboard.html
│   │   └── document_detail.html
│   └── static/
│       ├── css/style.css
│       └── js/dashboard.js
├── tests/
│   └── test_compliance_vault.py
├── data/                     # Created at runtime (gitignored)
│   ├── governance_audit.jsonl
│   └── reports/              # Generated PDF reports
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

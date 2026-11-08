# MiniSOC — Cybersecurity Monitoring and Threat Detection Platform

A simulated Security Operations Center (SOC) platform for monitoring, detecting, and analyzing cybersecurity threats.

## Tech Stack

| Layer | Technologies |
|-------|-------------|
| **Frontend** | React 19, TypeScript, Vite, Tailwind CSS v4, Recharts, Lucide React |
| **Backend** | Python 3.11+, FastAPI, SQLAlchemy 2.x, Pydantic v2, Pydantic Settings |
| **Database** | SQLite (with foreign key enforcement via `PRAGMA foreign_keys=ON`) |
| **Detection**| Modular Rule-Based Engine (Open/Closed Principle) mapped to MITRE ATT&CK |
| **Testing** | Pytest (Backend), Vitest (Frontend) |

---

## Domain Enums & Severity Design

All status and severity values are governed by a single source of truth in [`app/core/enums.py`](backend/app/core/enums.py):

- **`LogSeverity`**: `info`, `low`, `medium`, `high`, `critical`
- **`AlertSeverity`**: `low`, `medium`, `high`, `critical`
- **`AlertStatus`**: `open`, `investigating`, `resolved`, `false_positive`

### Why Log Severity Includes "info" while Alert Severity Does Not
- **Security Logs** capture raw system and network telemetry. Routine, benign events (e.g., successful user logins, scheduled cron tasks, service health checks, DNS queries) are recorded with `info` severity to maintain full auditability and baseline context for incident forensics.
- **Security Alerts** represent confirmed anomalies, policy violations, or threat detection engine rule triggers. By definition, an alert requires SOC analyst triage and remediation. Generating alerts for routine benign informational telemetry would flood the queue and induce **alert fatigue**. Therefore, alert severity starts strictly at `low`.

---

## Database Architecture

MiniSOC uses SQLAlchemy 2.x declarative models with typed mappings (`Mapped[...]`, `mapped_column[...]`), SQLite foreign key pragma enforcement, and string-backed Python enums (`SQLEnum(..., native_enum=False, validate_strings=True)`).

### Models

1. **`SecurityLog` (`security_logs`)**
   - Ingests raw simulated security events.
   - **Fields**:
     - `id`: `int` (PK)
     - `timestamp`: `datetime` (UTC)
     - `source_ip`: `VARCHAR(45)` (IPv4/IPv6, indexed)
     - `destination_ip`: `VARCHAR(45)`
     - `destination_port`: `int` (nullable, check constraint: 0–65535, indexed)
     - `username`: `VARCHAR(100)` (nullable)
     - `event_type`: `VARCHAR(50)` (indexed)
     - `description`: `TEXT` (nullable)
     - `severity`: `LogSeverity` Enum (indexed)
     - `command_line`: `TEXT` (nullable, process command line for endpoint events)
     - `raw_log`: `TEXT` (nullable)
   - **Indexes**: `ix_security_logs_timestamp`, `ix_security_logs_severity`, `ix_security_logs_source_ip`, `ix_security_logs_event_type`, `ix_security_logs_destination_port`.

2. **`MitreTechnique` (`mitre_techniques`)**
   - Read-only catalog of MITRE ATT&CK techniques for threat mapping (seeded idempotently on startup).
   - **Fields**: `id` (PK), `technique_id` (VARCHAR 20, unique, indexed, e.g. `T1110`, `T1078`, `T1046`, `T1059.001`), `technique_name` (VARCHAR 200), `tactic` (VARCHAR 100), `description` (TEXT).
   - **Relationships**: `alerts` (one-to-many relationship with `SecurityAlert`).

3. **`SecurityAlert` (`security_alerts`)**
   - High-priority security incidents flagged for analyst review.
   - **Fields**: `id` (PK), `title` (VARCHAR 200), `description` (TEXT), `severity` (`AlertSeverity` Enum), `status` (`AlertStatus` Enum), `source_ip` (VARCHAR 45, nullable), `detection_time` (UTC datetime), `mitre_technique_id` (FK to `mitre_techniques.id`, nullable).
   - **Indexes**: `ix_security_alerts_severity`, `ix_security_alerts_status`, `ix_security_alerts_detection_time`.
   - **Relationships**: `mitre_technique` (many-to-one relationship with `MitreTechnique`).

---

## Getting Started & Startup Instructions

### 1. Environment Configuration
The backend enforces a **secure-by-default** stance: `ENVIRONMENT` defaults to `"production"` in [`config.py`](backend/app/core/config.py) if unset. In production mode, debug features such as `POST /api/v1/logs/generate` are disabled (returns 404).

To enable local development features:
```bash
# In backend directory, create .env from .env.example
cp backend/.env.example backend/.env    # macOS/Linux
# or in Windows PowerShell:
Copy-Item backend/.env.example backend/.env
```
Ensure `ENVIRONMENT=development` is set in `backend/.env`.

### 2. Backend Startup
```bash
cd backend
python -m venv venv
# Activate virtual environment:
# Windows:
.\venv\Scripts\activate
# macOS/Linux:
# source venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### 3. Frontend Startup
```bash
cd frontend
npm install
npm run dev
```
The frontend Vite dev server will run at `http://localhost:5173` and automatically proxy `/api` calls to `http://127.0.0.1:8000`.

---

## Resetting the Development Database

Because MiniSOC strictly uses synthetic security logs and has no migration tool (e.g. Alembic), database schema updates are applied by resetting the local SQLite file:

```bash
# 1. Stop any running backend server (e.g. Ctrl+C in terminal)
# 2. Delete the SQLite database file:
rm backend/minisoc.db          # macOS/Linux
# or in Windows PowerShell:
Remove-Item backend/minisoc.db

# 3. Restart the backend server.
# The lifespan init_db() handler will automatically recreate all tables
# and idempotently seed the baseline MITRE ATT&CK techniques.
```

---

## Threat Detection Engine

The detection engine lives in [`backend/app/services/detection/`](backend/app/services/detection/) and is architected around the **Open/Closed Principle**: new detection rules can be added by implementing `BaseDetectionRule` without modifying the core `DetectionEngine` execution pipeline.

### Rules Implemented:
- **Rule A: Brute Force (`T1110`)**
  - **Logic**: $\ge 5$ `auth_failure` events from the same `source_ip` within 5 minutes.
  - **Severity**: `HIGH`.
- **Rule B: Successful Login After Brute Force (`T1078`)**
  - **Logic**: A successful login (`auth_success`) from an IP that triggered Rule A within 10 minutes.
  - **Severity**: `CRITICAL`.
- **Rule C: Port Scan (`T1046`)**
  - **Logic**: $\ge 10$ distinct `destination_port` values targeted by the same `source_ip` within 2 minutes.
  - **Severity**: `MEDIUM`.
- **Rule D: Suspicious PowerShell (`T1059.001`)**
  - **Logic**: Process creation where `command_line` contains indicators such as `-EncodedCommand`, `-enc`, `IEX`, `Invoke-Expression`, `DownloadString`, `-WindowStyle Hidden`, or `-ExecutionPolicy Bypass` (case-insensitive matching). Benign commands do not alert.
  - **Severity**: `HIGH`.

All thresholds and sliding time windows are configurable via environment variables or [`app/core/config.py`](backend/app/core/config.py).

### Structured Incident Deduplication & Window Merging
- **Structured Incident Key**: Composed of `rule_id`, `entity` (`source_ip`), and `incident_start` (timestamp of the earliest event in the merged cluster).
- **Overlapping Window Merging**: Detection rules dynamically merge overlapping sliding windows into a single unified incident cluster per entity.
- **Deduplication & In-Place Updates**: When detection runs again, if an open incident exists for the same `rule_id` and `entity` whose active window overlaps or is within duration $W$ of the cluster, the existing alert is updated in-place (updating event count, latest timestamp, and evidence in description) rather than creating duplicate alerts.
- **Template Independence**: Deduplication does not depend on description text formatting. Modifying the description template does not break deduplication.
- **Subsequent Attacks**: A new attack from the same IP occurring after the active window has fully elapsed ($> W$) correctly spawns a separate, distinct alert.

---

## Synthetic Log Generator

The platform includes a deterministic synthetic log generator located in [`app/services/log_generator.py`](backend/app/services/log_generator.py):
- Generates benign background telemetry (successful logins, web traffic, administrative PowerShell).
- Injects 4 realistic attack scenarios (Brute Force, Compromised Account, Port Scan, Obfuscated PowerShell).
- Uses only safe private/documentation IP spaces (`10.0.0.0/8`, `192.168.0.0/16`, `203.0.113.0/24`, `198.51.100.0/24`).
- Supports random seeds for 100% reproducible demo data.

### CLI Usage:
```bash
python scripts/generate_logs.py --seed 42
```

---

## API Endpoints (v1)

### Health
- `GET /api/v1/health` — Service health probe.

### Security Logs
- `GET /api/v1/logs` — List security logs with pagination (`skip >= 0`, `1 <= limit <= 100`) and optional filters (`severity`, `event_type`, `source_ip`).
- `GET /api/v1/logs/{log_id}` — Get single log by ID.
- `POST /api/v1/logs` — Ingest a security log (validates IPs with `IPvAnyAddress`, 201 Created).
- `POST /api/v1/logs/generate` — Generate synthetic logs. **Available ONLY when `ENVIRONMENT=development`** (returns 404 in any other environment).
- `DELETE /api/v1/logs/{log_id}` — Delete a log by ID (204 No Content).

### Security Alerts
- `GET /api/v1/alerts` — List security alerts with pagination (`skip >= 0`, `1 <= limit <= 100`) and optional filters (`severity`, `status`). Eagerly loads associated MITRE technique.
- `GET /api/v1/alerts/{alert_id}` — Get single alert with MITRE technique details.
- `POST /api/v1/alerts` — Create a new security alert (validates `mitre_technique_id` foreign key exists, 201 Created / 422 Unprocessable Entity).
- `PATCH /api/v1/alerts/{alert_id}` — Partially update alert status, severity, or description only (`extra="forbid"` returns 422 for unauthorized fields).
- `DELETE /api/v1/alerts/{alert_id}` — Delete an alert (204 No Content).

### Threat Detection
- `POST /api/v1/detection/run` — Executes all registered detection rules over stored logs and persists deduplicated alerts mapped to MITRE ATT&CK techniques. Returns summary statistics.

### MITRE Techniques (Read-Only)
- `GET /api/v1/mitre` — List all MITRE ATT&CK techniques, optionally filtered by `tactic`.
- `GET /api/v1/mitre/{technique_id}` — Get technique details by T-code (e.g. `T1059.001`).

---

## Testing

The backend test suite runs against an **isolated in-memory SQLite database** (`sqlite:///:memory:`) using `StaticPool` and transactional rollbacks, ensuring development databases are never modified.

```bash
cd backend
venv\Scripts\activate
pytest -v
```

All 57 unit and integration tests verify:
- Enums (`LogSeverity`, `AlertSeverity`, `AlertStatus`).
- Input validation: IPvAnyAddress, port bounds (0–65535), pagination limits (`limit=101`, `skip=-1` → 422).
- Timezone-aware ISO 8601 UTC timestamp serialization (`Z` or `+00:00`) for both logs and alerts.
- Detection rules: exact threshold vs one-below threshold, true sliding window boundary conditions, case-insensitive PowerShell obfuscation and flags (`-e`, `-ec`, `-ep bypass`, `iEx`), benign PowerShell command protection (`Get-EventLog`).
- PowerShell multi-command evidence preservation: full command text, timestamps, and matched indicators preserved without overwriting.
- Deduplication status scope: alerts with status `open` or `investigating` absorb new events in-place; alerts with status `resolved` or `false_positive` do not absorb events (spawn new alerts).
- Foreign key resolution and MITRE technique linking for all 4 detection rules.
- Per-incident deduplication logic (same logs processed twice produce 0 duplicates; new attack outside window produces new alert).
- Secure default configuration (`ENVIRONMENT=production` by default; `POST /api/v1/logs/generate` returns 404 unless `ENVIRONMENT=development`).
- Generator reproducibility with fixed seeds.
- Sanitized global exception handler (500 without leaking stack traces).

---

## Project Structure

```
MiniSoc/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   └── v1/            # Health, Logs, Alerts, MITRE, Detection endpoints
│   │   ├── core/              # Settings & Enums (Severity, Status)
│   │   ├── db/                # Engine, PRAGMA foreign keys, init_db
│   │   ├── models/            # SQLAlchemy 2.x models (SecurityLog, Alert, Mitre)
│   │   ├── repositories/      # Data access layer
│   │   ├── schemas/           # Pydantic v2 schemas
│   │   ├── services/
│   │   │   ├── detection/     # Modular Threat Detection Engine & Rules
│   │   │   │   ├── rules/     # T1110, T1078, T1046, T1059.001 rules
│   │   │   │   ├── base.py    # Common detection rule interface
│   │   │   │   └── engine.py  # Orchestrator & deduplicator
│   │   │   └── log_generator.py # Synthetic log generator
│   │   └── main.py            # FastAPI entry point, CORS & 500 handler
│   ├── tests/                 # 45 isolated Pytest tests
│   ├── requirements.txt
│   ├── pyproject.toml
│   └── .env.example
├── frontend/
│   ├── src/                   # React + TypeScript + Tailwind
│   ├── package.json
│   └── vite.config.ts         # Vite proxy setup
├── scripts/
│   └── generate_logs.py       # CLI synthetic log generator
├── docs/
├── .gitignore
└── README.md
```

## License

This project is for educational and cybersecurity research purposes.

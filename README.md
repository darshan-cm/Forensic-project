# ForensicGuard

**Windows Endpoint Forensics and Security Monitoring**

ForensicGuard is a Windows desktop application that collects selected endpoint
telemetry, applies rule-based risk analysis, stores forensic events and
supporting evidence locally, and produces session-scoped PDF reports. It
provides monitoring and investigation support; it is not an endpoint
prevention product or a guarantee that all malicious activity will be detected.

## Objectives

- Observe selected file, process, active-window, removable-device, transfer,
  and Windows security activity.
- Preserve available telemetry in local SQLite databases.
- Evaluate supported events with the existing risk engine and identify
  triggered rules.
- Present monitoring and risk information in an authenticated desktop
  dashboard.
- Associate telemetry generated during an application session and produce a
  compact, offline forensic PDF before logout.

## Features

- **Authentication:** Supabase email/password sign-in and account creation
  using a publishable/anon client key.
- **Endpoint monitoring:** Windows-specific monitoring for selected user
  folders, processes, active-window changes, file-copy activity, USB/removable
  devices, and configured Windows security events.
- **Risk analysis:** Event-driven assessment using the existing risk engine,
  registered rule IDs/names, severity/score, and stored evidence where
  supported.
- **Local storage:** Forensic events in `database/forensic.db`; risk
  assessments and evidence in `database/riskalert.db`.
- **Session reports:** A session ID and session metadata are maintained locally.
  New event and risk row IDs are associated through files under
  `reports/.sessions/`; the existing SQLite schema is not changed by report
  generation. Historical records are not assigned to a session.
- **PDF workflow:** Generate a report without logging out, or use **Generate
  Report & Logout**. The PDF is written to `reports/` and verified before
  logout. If generation fails, the user remains signed in.
- **Open and save a copy:** On successful report generation, the GUI displays
  the filename and path and offers **Open Report** (the Windows default PDF
  handler) and **Save/Download Report** (a Windows save-file dialog). Saving
  copies the PDF; it does not remove the original from `reports/`.
- **Unicode-safe console logging:** Logger output configures UTF-8 where
  supported and safely escapes characters the console cannot encode.
- **ML utilities:** Feature/model training and scenario utilities are present.
  They should not be interpreted as proof that every live event is evaluated
  by a trained ML model.

## Architecture

```text
Windows monitors
  ├─ file and file-transfer observers
  ├─ process and active-window polling
  ├─ USB/removable-device checks
  └─ Windows security-event collection
          │
          ▼
Event logger ──► local forensic.db ──► event queue / risk engine
                                         │
                                         ├─► riskalert.db assessments/evidence
                                         └─► alert processing where configured
          │
          ▼
Authenticated Qt dashboard ──► session association files ──► PDF in reports/
```

Supabase is used for authentication. Endpoint events, risk assessments,
session associations, and generated reports are local; this feature does not
require a Supabase schema migration.

## Detection Rule Registry (50 Rules)

The registry in `detection/rule_registry.py` is the authoritative list of
rule IDs, names, and current implementation-status labels. **FULL** means the
rule is marked full in that registry, not that every Windows event source or
endpoint configuration guarantees complete telemetry. **PARTIAL** indicates
limited logic and/or telemetry. **PENDING** rules are not represented as
production-complete; some have targeted tests or related logic, but remain
pending in the registry.

| ID | Rule | Registry status |
|---:|---|---|
| 1 | Large File Copy | PENDING |
| 2 | Multiple Large Files Copy | PENDING |
| 3 | Bulk File Copy | PENDING |
| 4 | File Paste from External Source | PENDING |
| 5 | Mass File Modification | PENDING |
| 6 | Sensitive File Modification | PARTIAL |
| 7 | Mass File Deletion | PARTIAL |
| 8 | Sensitive File Deletion | PARTIAL |
| 9 | Permanent File Deletion | PARTIAL |
| 10 | Mass File Rename | PARTIAL |
| 11 | File Extension Change | FULL |
| 12 | Mass File Move | PARTIAL |
| 13 | Sensitive Folder Access | PARTIAL |
| 14 | Mass File Access | PARTIAL |
| 15 | Unusual File Access | PARTIAL |
| 16 | After-Hours File Activity | PARTIAL |
| 17 | USB File Transfer | FULL |
| 18 | External Drive Transfer | FULL |
| 19 | Network File Transfer | PARTIAL |
| 20 | Cloud Upload | PARTIAL |
| 21 | External Email Transfer | PARTIAL |
| 22 | Large Data Upload | PARTIAL |
| 23 | Mass Download | PARTIAL |
| 24 | Permission Change | PARTIAL |
| 25 | Ownership Change | PARTIAL |
| 26 | Hidden File Creation | FULL |
| 27 | Executable File Modification | FULL |
| 28 | Configuration File Modification | FULL |
| 29 | Backup File Deletion | PARTIAL |
| 30 | Snapshot/Restore Point Deletion | PARTIAL |
| 31 | Mass Encryption | PARTIAL |
| 32 | Rapid Rename + Encryption | PARTIAL |
| 33 | Copy + Delete Original | PARTIAL |
| 34 | Access + External Transfer | PARTIAL |
| 35 | Privilege Change + File Activity | PARTIAL |
| 36 | New Device Activity | PARTIAL |
| 37 | Unusual Location Activity | PARTIAL |
| 38 | Dormant Account Activity | PARTIAL |
| 39 | Failed Login + File Activity | PARTIAL |
| 40 | Unusual Activity Spike | PARTIAL |
| 41 | Multiple Suspicious Operations | PARTIAL |
| 42 | High-Risk Process File Activity | PARTIAL |
| 43 | Protected File Access | PARTIAL |
| 44 | System File Modification | PARTIAL |
| 45 | Mass Folder Deletion | PARTIAL |
| 46 | Mass Folder Creation | PARTIAL |
| 47 | Mass File Creation | PARTIAL |
| 48 | File Activity Burst | PARTIAL |
| 49 | Unusual File Type Activity | PARTIAL |
| 50 | Combined Risk Detection | PARTIAL |

Several detections depend on signals the current monitor set may not provide,
including file-read/access events, ACL and ownership changes, reliable
cloud/email upload telemetry, account-history baselines, and process-to-file
attribution. Encryption-related rules identify supported patterns; they do
not establish that file contents were cryptographically encrypted. Check each
rule's `required_telemetry` field and the monitor scope before relying on a
detection.

## Risk Assessments and Evidence

The risk engine evaluates supported trigger events and returns a score,
severity, evidence, and any triggered rule metadata. The event-risk handler
stores rule-tagged assessments and related evidence in `riskalert.db`. The
forensic event log is maintained separately in `forensic.db`. Dashboard
refresh is not intended to create generic assessments by itself.

Databases are local runtime data and are intentionally ignored by Git. The
application may initialize or update them while monitoring. Keep a separate
verified backup before maintenance; do not remove or replace a database to
troubleshoot the application.

## Session Forensic PDF Reports

After successful authentication, the dashboard starts a unique session and
records the available authenticated user identifier, session start, end, and
report information without storing passwords or auth secrets. New event and
assessment row IDs are appended to a local session association ledger where
the in-process event pipeline can associate them. Existing historical rows
are not inferred into the session.

The PDF summarizes observed normal activity and triggered suspicious activity
separately, includes risk/evidence details and a compact timeline, and presents
a deterministic **Forensic Analytical Summary** based on the available stored
telemetry. It is not generated by an external AI/LLM. Missing telemetry is not
treated as proof that activity was safe.

The report flow is:

1. Choose **Generate Forensic Report** to generate without logging out, or
   **Generate Report & Logout** to generate before logout.
2. ForensicGuard waits briefly for queued event assessments to complete,
   writes a uniquely named PDF under `reports/`, and verifies the file.
3. The success dialog shows the report name/path and offers **Open Report** or
   **Save/Download Report**. The save action creates a copy at the selected
   location while retaining the original under `reports/`.
4. The combined logout action signs out only after report generation and
   verification succeed. A generation failure blocks logout.

Generated PDFs and session metadata are local artifacts and are excluded from
Git. Do not include them in a commit.

## Requirements

- Windows 10 or Windows 11.
- Python 3.11 or newer supported by the pinned package versions.
- A configured Supabase project for sign-in/account creation.
- Windows permissions and event-log availability appropriate to the monitors
  being used.

The monitor implementations use Windows APIs and Windows-specific libraries;
the application is not a cross-platform monitoring agent.

## Installation and Setup

From PowerShell, go to the project directory and create/activate a virtual
environment:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Create a local `.env` file in the project root. Do not commit it:

```dotenv
SUPABASE_URL=https://YOUR_PROJECT_REF.supabase.co
SUPABASE_PUBLISHABLE_KEY=YOUR_PUBLISHABLE_OR_ANON_KEY
```

Use only a Supabase publishable/anon client key in this desktop application.
Never place a `service_role` key, password, or other privileged secret in
source code or a distributed client. The application loads `.env` from the
project root.

## Run

From the activated virtual environment and project root:

```powershell
python main.py
```

`main.py` starts the configured monitor/event-worker threads and opens the
ForensicGuard sign-in window. After successful sign-in, the dashboard is shown.
Monitoring and available telemetry depend on the Windows machine, permissions,
watched paths, and the configured event sources.

## Safe Validation

The focused, non-destructive test suites use temporary fixtures/databases and
can be run from the project root:

```powershell
python -m unittest -v `
  test_rule_registry `
  test_copy_rules `
  test_rules_4_5 `
  test_rules_6_25 `
  test_rules_26_50 `
  test_forensic_report `
  test_logger_encoding
```

These tests do not substitute for validation on every Windows endpoint or a
live authenticated account. Do not run `test_deduplication.py` as part of this
safe test set.

## Project Structure

```text
ForensicGuard/
├── alerts/                 # Alert processing
├── auth/                   # Login and signup UI
├── database/               # SQLite database source and local runtime DBs
├── detection/              # Risk engine, rule registry, detection helpers
├── event_engine/           # Event queue and worker
├── features/               # Feature aggregation for ML utilities
├── gui/                    # Qt dashboard and monitor controller
├── ml/                     # Dataset-building utilities
├── models/                 # Local model artifacts
├── monitors/               # Windows monitoring modules
├── reports/                # Session report source and generated PDFs
├── supabase/               # Supabase client/authentication integration
├── training/               # Model training utilities
├── utils/                  # Logging and shared helpers
├── main.py                 # Application entry point
├── requirements.txt
├── test_forensic_report.py
├── test_logger_encoding.py
└── README.md
```

## Safety and Limitations

- ForensicGuard focuses on monitoring, detection, evidence collection, risk
  assessment, and reporting. It does **not** provide guaranteed prevention or
  pre-operation blocking. True OS-level blocking before a file operation
  requires deeper Windows enforcement, such as a properly designed and
  deployed filesystem minifilter driver.
- Monitoring is scoped and telemetry-dependent. File access, network/cloud
  transfer, email, permission, ownership, and some correlation detections may
  be partial or unavailable; see the registry status and telemetry notes above.
- A generated report only describes data available to ForensicGuard during
  the associated session. It is not a guarantee that no suspicious activity
  occurred.
- No external AI/LLM service is used to author the forensic analysis section.
- Authentication requires a reachable, correctly configured Supabase project.
  Authenticated GUI behavior must be tested with an authorized account; no
  credentials are included in this repository.
- Local SQLite databases, reports, backups, `.env`, and session metadata can
  contain sensitive information. Protect and back them up according to local
  policy; they are excluded from commits by `.gitignore`.

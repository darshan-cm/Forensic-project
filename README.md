# 🛡️ ForensicGuard

## AI-Powered Real-Time Endpoint Forensics & Security Monitoring

ForensicGuard is a Windows-based real-time endpoint monitoring and digital forensics system designed to continuously observe endpoint activity, collect forensic evidence, detect suspicious behavior, and assess security risk using machine-learning-based detection and a forensic risk engine.

---

## 🎯 Project Objectives

### Objective 1 — Real-Time Endpoint Monitoring & Digital Forensics

Monitor and record endpoint activities in real time, including:

- File creation
- File modification
- File deletion
- File renaming
- File-copy activity
- USB device connection/disconnection
- Process/application activity
- Active-window changes
- Windows security events
- Endpoint activity relevant to digital forensics

All collected events are stored in an SQLite database for investigation and evidence analysis.

### Objective 2 — AI/ML-Based Suspicious Behavior Detection

Use machine-learning models and aggregated endpoint features to identify potentially suspicious user behavior and classify endpoint activity.

The trained model is stored in:

```text
models/forensicguard_rf.pkl
🏗️ Project Architecture
                    ┌─────────────────────────┐
                    │     Windows Endpoint    │
                    └────────────┬────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              │                  │                  │
              ▼                  ▼                  ▼
       Process Monitor     File Monitor       USB Monitor
              │                  │                  │
              ▼                  ▼                  ▼
       Active Window      File Transfer      Security Monitor
          Monitor             Monitor              │
              │                  │                  │
              └──────────────────┼──────────────────┘
                                 │
                                 ▼
                       ┌───────────────────┐
                       │   Event Logger    │
                       └─────────┬─────────┘
                                 │
                                 ▼
                       ┌───────────────────┐
                       │   SQLite Database │
                       │   forensic.db     │
                       └─────────┬─────────┘
                                 │
                    ┌────────────┴────────────┐
                    │                         │
                    ▼                         ▼
            Feature Aggregator          Risk Engine
                    │                         │
                    ▼                         ▼
             ML Detection              Risk Assessment
                    │                         │
                    └────────────┬────────────┘
                                 │
                                 ▼
                       ┌───────────────────┐
                       │ ForensicGuard GUI │
                       │    Dashboard      │
                       └───────────────────┘
📁 Project Structure
ForensicGuard/
│
├── dashboard/
│   ├── app.py
│   ├── static/
│   └── templates/
│
├── database/
│   ├── database.py
│   └── forensic.db
│
├── detection/
│   ├── ml_detector.py
│   ├── process_detector.py
│   ├── risk_engine.py
│   ├── final_scenario_test.py
│   ├── model_scenario_test.py
│   ├── rf_scenario_test.py
│   └── rf_test.py
│
├── event_engine/
│   ├── engine.py
│   └── worker.py
│
├── features/
│   └── feature_aggregator.py
│
├── gui/
│   ├── app.py
│   ├── controller.py
│   ├── dashboard.py
│   ├── main_window.py
│   ├── styles.py
│   └── ui.py
│
├── ml/
│   ├── build_dataset.py
│   └── forensicguard_dataset.csv
│
├── models/
│   ├── forensicguard_rf.pkl
│   └── forensicguard_rf_backup.pkl
│
├── monitors/
│   ├── active_window.py
│   ├── browser_monitor.py
│   ├── file_monitor.py
│   ├── file_transfer_monitor.py
│   ├── network_monitor.py
│   ├── powershell_monitor.py
│   ├── process_monitor.py
│   ├── security_monitor.py
│   └── usb_monitor.py
│
├── training/
│   ├── rebuild_objective2.py
│   └── train_final_objective2.py
│
├── utils/
│   ├── hash_util.py
│   ├── helpers.py
│   └── logger.py
│
├── exports/
├── logs/
│
├── main.py
├── gui_test.py
├── requirements.txt
├── requirements.md
├── README.md
└── .gitignore
💻 System Requirements
Operating System
Windows 10
Windows 11

ForensicGuard currently depends on Windows-specific functionality such as Windows APIs, WMI, Windows Security Events, USB device information, and Windows Explorer.

Python

Recommended:

Python 3.11.x

Check your Python version:

python --version
📦 Installation
1. Clone or extract the project

Open PowerShell and navigate to the project directory:

cd path\to\ForensicGuard
2. Create a virtual environment
python -m venv .venv
3. Activate the virtual environment
.venv\Scripts\Activate.ps1

If PowerShell prevents activation:

Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

Then activate again:

.venv\Scripts\Activate.ps1
4. Install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt
▶️ Running ForensicGuard
Start the Real-Time Monitoring System

From the project root:

python main.py

This starts the endpoint monitoring components.

The system monitors:

Processes
Active windows
Files
File transfers
USB devices
Windows security events
🖥️ Start the GUI Dashboard

Open another PowerShell terminal in the project directory.

Activate the virtual environment:

.venv\Scripts\Activate.ps1

Then run:

python gui_test.py

The dashboard provides visualization of collected forensic activity.

## Session Forensic Reports

After an authenticated sign-in, the dashboard starts a session-scoped report
window. Use **Generate Forensic Report** to save a compact offline PDF without
signing out, or **Generate Report & Logout** to generate and verify the PDF
before signing out. Reports are saved under `reports/` and summarize only
telemetry recorded during that session. The AI-assisted analysis is
rule-based and grounded in the existing event, risk-assessment, and evidence
records; no external AI service is required.

🧠 Run the Risk Engine

To independently run the forensic risk assessment:

python -m detection.risk_engine

The risk engine generates:

Risk level
Risk score
USB activity
File-copy activity
Transfer size
Security-event indicators
Forensic evidence
🤖 Machine Learning

ForensicGuard contains a trained Random Forest model for Objective 2.

Model location:

models/forensicguard_rf.pkl

The feature aggregation system prepares the endpoint activity features expected by the trained model.

The ML-related files are located in:

features/
ml/
models/
training/
detection/
🗄️ Database

ForensicGuard uses SQLite for forensic event storage.

Database:

database/forensic.db

The database stores collected endpoint events such as:

Timestamp
Event source
Event ID
Action
Application
Event details

The database is automatically initialized by the application.

SQLite does not require a separate database server.

🔍 Monitors
Process Monitor

Tracks meaningful user-facing application process activity.

Examples include:

Chrome
Microsoft Edge
Firefox
VS Code
WhatsApp
Discord
Microsoft Office
AnyDesk
File Monitor

Monitors selected user directories for:

File creation
File modification
File deletion
File renaming

Monitored locations include:

Desktop
Documents
Downloads
Pictures
File Transfer Monitor

Detects file-copy activity from Windows Explorer and records information such as:

Number of files copied
File names
Total transfer size
USB Monitor

Detects USB device:

Connection
Disconnection

The monitor records device information such as:

Device name
Vendor ID (VID)
Product ID (PID)
Connection status
Active Window Monitor

Records changes in the active Windows application/window.

Security Monitor

Collects relevant Windows security events used for forensic analysis and ML feature generation.

📊 Forensic Events

Events are stored in:

database/forensic.db

The GUI can display the collected events and export event records as CSV.

CSV exports are stored/created through the project's export functionality.

🧪 Testing

Various testing scripts are available under:

detection/

and the project root.

Examples:

python -m detection.risk_engine

Individual monitoring modules can also be tested independently when required.

⚠️ Important Notes
Windows Only

ForensicGuard is designed for Windows endpoints.

USB/MTP Devices

Android phones connected through USB may appear through Windows MTP/File Explorer rather than as a normal drive. Therefore, some MTP file-transfer operations may not expose normal filesystem events.

Permissions

Some Windows security and system-monitoring functionality may require appropriate Windows permissions.

Database

The SQLite database is continuously updated while monitoring is running.

Do not manually modify the database while ForensicGuard is actively writing events.

🧹 Clean Installation

Do NOT share the following generated/environment files:

.venv/
__pycache__/
*.pyc

A teammate should create their own virtual environment and install dependencies using:

python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
🚀 Quick Start
cd ForensicGuard

python -m venv .venv

.venv\Scripts\Activate.ps1

pip install -r requirements.txt

python main.py

For the GUI:

python gui_test.py

For risk assessment:

python -m detection.risk_engine
🛡️ ForensicGuard

AI-Powered Real-Time Endpoint Forensics & Security Monitoring


## `.gitignore`

```gitignore
# ============================================================
# FORENSICGUARD - GITIGNORE
# ============================================================

# Python virtual environment
.venv/
venv/
env/
ENV/

# Python cache
__pycache__/
*.py[cod]
*$py.class

# Distribution / packaging
build/
dist/
*.egg-info/
.eggs/

# ============================================================
# DATABASE
# ============================================================

# Runtime forensic database
database/forensic.db
database/forensic.db-journal
database/forensic.db-wal
database/forensic.db-shm

# ============================================================
# LOGS
# ============================================================

logs/*
*.log

# Keep the logs directory itself
!logs/.gitkeep

# ============================================================
# GENERATED EXPORTS
# ============================================================

exports/*
*.csv

# Keep the exports directory itself
!exports/.gitkeep

# ============================================================
# IDE
# ============================================================

.vscode/
.idea/

# Visual Studio
.vs/

# ============================================================
# OS GENERATED FILES
# ============================================================

.DS_Store
Thumbs.db
desktop.ini

# ============================================================
# TEMPORARY FILES
# ============================================================

*.tmp
*.temp
*.bak
*.swp
*.swo
*.cache

# ============================================================
# Jupyter
# ============================================================

.ipynb_checkpoints/

# ============================================================
# ENVIRONMENT / SECRETS
# ============================================================

.env
.env.*
!.env.example
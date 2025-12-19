# AVRPS — Advanced Vulnerability Remediation and Patching System

AVRPS (Advanced Vulnerability Remediation and Patching System) is an enterprise-grade, cross-platform vulnerability management tool for detecting, prioritizing, remediating, and reporting software vulnerabilities across Linux, Windows, and macOS.

**Version:** 3.0.0  
**Date:** 2025-12-19

**Author:** [MrAmirRezaie](https://github.com/MrAmirRezaie)  
**Repository:** [https://github.com/MrAmirRezaie/AVRPS](https://github.com/MrAmirRezaie/AVRPS)  
**License:** [MIT](LICENSE)

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Sample Output](#sample-output)
- [How It Was Written (Development Process)](#how-it-was-written-development-process)
- [Execution Location & Conditions](#execution-location--conditions)
- [Configuration](#configuration)
- [Files & Layout](#files--layout)
- [Testing & Verification](#testing--verification)
- [Contributing](#contributing)
- [Security & Responsible Disclosure](#security--responsible-disclosure)
- [Troubleshooting](#troubleshooting)
- [Changelog](#changelog)
- [Author & Contact](#author--contact)

---

## Overview

AVRPS is a modular framework that ingests CVE data (local/NVD), scans system packages and files, matches vulnerabilities to installed software, scores confidence, and offers automated remediation with snapshot/rollback support and multi-format reporting.

## Features

- Cross-platform scanning: Linux, Windows, macOS
- Local and remote CVE ingestion (NVD integration optional)
- Confidence scoring and fuzzy matching to reduce false positives
- Automated patch application with snapshot/rollback and verification
- SQLite-backed history and reporting (JSON/HTML/TXT)
- Pluggable architecture for detectors, data sources, and handlers

## Requirements

- Python 3.7+ (3.12 tested during development)
- Recommended packages (install via `pip` or `requirements.txt`):
  - `requests`
  - `urllib3`
  - `tqdm`
  - `colorama`
  - `psutil`
  - `packaging`
  - `pyyaml`
  - `pywin32` (Windows only — for file version lookups)

AVRPS runs in degraded mode when optional packages are missing; network features, colored console output, and some system introspection capabilities will be limited.

## Installation

Clone the repository and create a virtual environment in the repository root (recommended):

```bash
git clone https://github.com/MrAmirRezaie/AVRPS.git
cd AVRPS
python -m venv .venv
```

Activate the virtual environment:

```powershell
# Windows
.venv\Scripts\Activate.ps1  # PowerShell
.venv\Scripts\activate.bat  # CMD
```

```bash
# macOS/Linux
source .venv/bin/activate
```

Install dependencies (recommended):

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

Or install packages individually:

```bash
pip install requests urllib3 tqdm colorama psutil packaging pyyaml
# Windows-only
pip install pywin32
```

## Quick Start

Run a quick dry-run scan (no changes applied):

```powershell
.venv\Scripts\python.exe AVRPS.py --scan --dry-run
```

Run a scan and remediate (requires administrative privileges):

```powershell
.venv\Scripts\python.exe AVRPS.py --scan --remediate
```

Generate a report after scanning:

```powershell
.venv\Scripts\python.exe AVRPS.py --scan --report --report-dir reports
```

Use `--config path/to/config.ini` to point to a custom configuration file or `--help` for the full CLI.

## Sample Output

Example console output for a successful dry-run scan:

```text
2025-12-19 10:00:12 - INFO - AVRPS - Loaded configuration from avrps_config.ini
2025-12-19 10:00:12 - INFO - AVRPS - Database initialized (in-memory)
2025-12-19 10:00:13 - INFO - AVRPS - Scanning 234 installed packages (deep scan: false)
[####################] 100% | Scanning packages
2025-12-19 10:00:25 - WARNING - AVRPS - Found 2 potential vulnerabilities (CVE-2025-XXXXX, CVE-2025-YYYYY)
2025-12-19 10:00:25 - INFO - AVRPS - Dry-run remediation completed (no changes applied)
Report saved: reports/scan-2025-12-19T100025.json
```

When remediation is applied (not dry-run), output will include patch application steps and verification results, concluding with `PATCH RESULT: SUCCESS` or `PATCH RESULT: FAILED` and details.

## How It Was Written (Development Process)

The tool was developed iteratively with emphasis on cross-platform compatibility, safe defaults, and testability. High-level process:

1. Architecture: define core managers (configuration, database, cache, scanner, detector, patch manager).
2. Implement core scanning and detection logic in modular, testable units inside `AVRPS.py` and supporting modules.
3. Add defensive dependency handling & platform guards to gracefully degrade or skip platform-specific features.
4. Create lightweight tests and a verification script to catch runtime/import issues early.
5. Iterate based on test results and manual runs; add documentation and packaging metadata.

Design notes:

- System-modifying operations default to `--dry-run` and require explicit confirmation for remediation.
- External network interactions are opt-in and rate-limited; local cache is preferred.
- Windows-only operations (e.g., file version lookups) are encapsulated and optional.

## Execution Location & Conditions

- Always execute from the **repository root** (where `AVRPS.py` lives) to ensure relative paths resolve correctly.
- Recommended to run inside the virtual environment created with `python -m venv .venv`.
- Remediation actions require elevated privileges (Administrator on Windows, root/sudo on Unix-like systems).
- Ensure `avrps_config.ini` exists (it will be auto-created with defaults if missing) or pass `--config` to use a custom file.
- For Windows features, install `pywin32` in the venv to enable file version lookups.

## Configuration

The configuration file `avrps_config.ini` contains sections:

- `[general]` — `log_level`, `database_path`, `max_workers`, `timeout`, `backup_enabled`
- `[scanning]` — `deep_scan`, `scan_timeout`, `cve_check_enabled`
- `[patching]` — `auto_patch`, `dry_run_default`, `create_snapshots`, `rollback_enabled`
- `[reporting]` — `report_format`, `report_dir`, `save_reports`

Defaults are generated automatically by `ConfigurationManager` on first run. Edit the file to tune behavior.

## Files & Layout

- `AVRPS.py` — Main application and orchestrator (entry point).
- `avrps_config.ini` — Configuration (auto-generated).
- `requirements.txt` — Recommended packages.
- `pyproject.toml` — Packaging metadata.
- `LICENSE` — MIT license text.
- `tests/` — Unit tests using `pytest`.
- `tools/verify_startup.py` — Quick verification script.
- `test_cve.json` — Local CVE sample for verification.

## Testing & Verification

Run tests with `pytest` inside the venv:

```powershell
.venv\Scripts\Activate.ps1
.venv\Scripts\python.exe -m pytest -q
```

Run the startup verification script:

```powershell
.venv\Scripts\python.exe tools/verify_startup.py
```

Both are designed to be quick checks for runtime and import errors.

## Contributing

Contributions are welcome. Please:

1. Fork the repository.
2. Create a feature branch and add tests for non-trivial changes.
3. Run tests and verification script locally.
4. Open a PR with a clear description and changelog entry.

See [CONTRIBUTING.md](CONTRIBUTING.md) for more details.

## Security & Responsible Disclosure

If you discover a security vulnerability, open a private issue on the repository or contact the author directly. Do not publish exploit details publicly until a fix is available.

## Troubleshooting

- If you see import errors, activate the venv and install dependencies: `pip install -r requirements.txt`.
- On Windows, if file-version lookups fail, install `pywin32`.
- If network features fail, verify `requests` and `urllib3` are installed and proxy settings are correct.

## Changelog

- **v3.0.0** — 2025-12-19: Major refactor; cross-platform support; snapshot/rollback; improved detection algorithms.

---

## Author & Contact

[MrAmirRezaie](https://github.com/MrAmirRezaie)  
Date: 2025-12-19  
Version: 3.0.0
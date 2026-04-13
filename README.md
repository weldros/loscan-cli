# Log Scanner

A high-performance log file scanner that detects malicious patterns, missing timestamps, corruption, and time-gaps in large log files. Generates reports in multiple formats (JSON, CSV, HTML, YAML, SQLite).

## Features

- **Single-pass streaming scan** — processes 1M+ line files in seconds
- **Multi-format exports** — JSON, CSV, HTML, YAML, SQLite database
- **Pattern detection**:
  - Malicious patterns (SQL injection, command injection, XSS, path traversal)
  - Error keywords (error, failed, fatal, panic, denied, unauthorized, etc.)
  - Corruption (invalid UTF-8, control characters, excessively long lines)
  - Time-gap detection (flags periods >5 minutes with no log entries)
- **Multiple timestamp formats** — Apache brackets `[Mon Dec 04 04:52:12 2005]`, ISO 8601, Unix timestamps
- **Interactive format selection** — choose desired export formats or default to all
- **Terminal dashboard** — open a curses summary view after the scan with `--tui`

## Quick Start

### Linux / macOS
```bash
bash run_log_scanner.sh
```
Then enter:
1. Path to your .log file
2. Desired output formats (e.g., `json,csv` or leave blank for all)

Reports are saved to the `error/` directory.

### Windows (PowerShell)
```powershell
powershell -ExecutionPolicy Bypass -File run_log_scanner.ps1
```
Then enter prompts as above.

### Windows (Command Prompt)
```cmd
run_log_scanner.bat
```
Then enter prompts as above.

## Installation

### Requirements
- Python 3.8+
- `python3` in PATH (or use full path to Python executable)

### Setup
```bash
git clone <repository>
cd devopia26
chmod +x run_log_scanner.sh  # On Linux/macOS only
```

## Example Usage

**Bash:**
```bash
$ bash run_log_scanner.sh
Enter path to .log file: /var/log/apache/access.log
Enter output formats (json,csv,html,yaml,db) or leave blank for all: json,csv
# Generates:
# - error/access.log_report.json
# - error/access.log_report.csv
```

**PowerShell:**
```powershell
PS> powershell -ExecutionPolicy Bypass -File run_log_scanner.ps1
Enter path to .log file: C:\Logs\app.log
Enter output formats (json,csv,html,yaml,db) or leave blank for all:
# Generates all 5 formats (default when blank)
```

## Output Formats

| Format | Use Case |
|--------|----------|
| **JSON** | Structured data, API integration, web uploads |
| **CSV** | Spreadsheet analysis, filtering |
| **HTML** | Visual inspection, sharing reports |
| **YAML** | Configuration, compact readability (auto-generated only if <250KB) |
| **SQLite (.db)** | Time-series graphing, timeline bucketing, backend ingestion |

## Report Structure

Each finding includes:
- **timestamp** — extracted from log entry (if parseable)
- **matched_phrases** — keywords/patterns matched
- **line_number** — position in original log file
- **category** — malicious, error, corruption, time_gap
- **severity** — low, medium, high (based on pattern scoring)
- **score** — numeric confidence (0-100)
- **message** — human-readable summary

## Architecture

```
run_log_scanner.{sh,ps1,bat}  ← User entry point (interactive prompts)
  ↓
scripts/log_scanner.py  ← CLI orchestrator
  ├─ scripts/scanner_core.py  ← Streaming scan engine
  └─ scripts/reporting.py  ← Multi-format exporter
        ├─→ error/report.json
        ├─→ error/report.csv
        ├─→ error/report.html
        ├─→ error/report.yaml (if <250KB)
        └─→ error/report.db (SQLite)
```

## Advanced Usage

### Command-line Direct (Skip Interactive Prompts)
```bash
python3 scripts/log_scanner.py /path/to/logfile.log --output-dir ./error --formats json,csv
```

### Terminal Dashboard

Open the dashboard after a scan:

```bash
python3 scripts/log_scanner.py /path/to/logfile.log --tui
```

Or open it directly from the generated metrics artifact:

```bash
python3 scripts/tui_dashboard.py error/logfile_error_report_dashboard_metrics.json
```

### Supported Format Values
- `json` — JSON export
- `csv` — CSV export
- `html` — HTML export
- `yaml` — YAML export
- `db` — SQLite database export

Leave `--formats` empty or omit to generate all formats.

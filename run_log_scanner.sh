#!/usr/bin/env bash
set -euo pipefail

# Check Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is not installed. Installing..."
    if command -v apt &> /dev/null; then
        sudo apt update && sudo apt install -y python3
    elif command -v brew &> /dev/null; then
        brew install python3
    else
        echo "Cannot auto-install Python 3. Please install Python 3.8+ manually."
        exit 1
    fi
fi

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
reports_dir="$HOME/Documents/reports"

if [[ ! -d "$reports_dir" ]]; then
  mkdir -p "$reports_dir"
fi

read -r -p "Enter path to .log file: " log_file

if [[ -z "$log_file" ]]; then
  echo "No input file provided."
  exit 1
fi

if [[ ! -f "$log_file" ]]; then
  echo "File not found: $log_file"
  exit 1
fi

read -r -p "Set report username (leave blank to disable login): " report_username
if [[ -n "$report_username" ]]; then
  read -r -s -p "Set report password: " report_password
  echo
fi
read -r -p "Enter output formats (json,csv,html,db) or leave blank for all: " formats
read -r -p "Enable web output (DB/auth)? [y/N]: " web_choice
web_flag=""
if [[ "${web_choice,,}" == "y" || "${web_choice,,}" == "yes" ]]; then
  web_flag="--web"
fi

if [[ -z "$formats" ]]; then
  if [[ -n "${report_username:-}" ]]; then
    python3 "$repo_dir/scripts/log_scanner.py" "$log_file" --output-dir "$reports_dir" --tui $web_flag --report-username "$report_username" --report-password "$report_password"
  else
    python3 "$repo_dir/scripts/log_scanner.py" "$log_file" --output-dir "$reports_dir" --tui $web_flag
  fi
else
  if [[ -n "${report_username:-}" ]]; then
    python3 "$repo_dir/scripts/log_scanner.py" "$log_file" --output-dir "$reports_dir" --formats "$formats" --tui $web_flag --report-username "$report_username" --report-password "$report_password"
  else
    python3 "$repo_dir/scripts/log_scanner.py" "$log_file" --output-dir "$reports_dir" --formats "$formats" --tui $web_flag
  fi
fi
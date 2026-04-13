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

if [[ ! -d "$repo_dir/error" ]]; then
  mkdir -p "$repo_dir/error"
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
read -r -p "Enter output formats (json,csv,html,yaml,db) or leave blank for all: " formats

if [[ -z "$formats" ]]; then
  if [[ -n "${report_username:-}" ]]; then
    python3 "$repo_dir/scripts/log_scanner.py" "$log_file" --output-dir "$repo_dir/error" --tui --report-username "$report_username" --report-password "$report_password"
  else
    python3 "$repo_dir/scripts/log_scanner.py" "$log_file" --output-dir "$repo_dir/error" --tui
  fi
else
  if [[ -n "${report_username:-}" ]]; then
    python3 "$repo_dir/scripts/log_scanner.py" "$log_file" --output-dir "$repo_dir/error" --formats "$formats" --tui --report-username "$report_username" --report-password "$report_password"
  else
    python3 "$repo_dir/scripts/log_scanner.py" "$log_file" --output-dir "$repo_dir/error" --formats "$formats" --tui
  fi
fi
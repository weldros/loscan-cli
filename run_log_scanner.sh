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

if command -v nproc &> /dev/null; then
  total_workers="$(nproc)"
else
  total_workers="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"
fi

total_ram_mb=""
if [[ -r /proc/meminfo ]]; then
  total_ram_kb="$(awk '/MemTotal:/ {print $2; exit}' /proc/meminfo)"
  if [[ -n "$total_ram_kb" ]]; then
    total_ram_mb=$((total_ram_kb / 1024))
  fi
elif command -v sysctl &> /dev/null; then
  total_ram_bytes="$(sysctl -n hw.memsize 2>/dev/null || true)"
  if [[ "$total_ram_bytes" =~ ^[0-9]+$ ]]; then
    total_ram_mb=$((total_ram_bytes / 1024 / 1024))
  fi
fi

if [[ -n "$total_ram_mb" && "$total_ram_mb" -gt 0 ]]; then
  ram_safe_max_workers=$((total_ram_mb / 1024))
  if (( ram_safe_max_workers < 1 )); then
    ram_safe_max_workers=1
  fi
else
  ram_safe_max_workers="$total_workers"
fi

default_workers=$(((total_workers + 1) / 2))
if (( default_workers < 1 )); then
  default_workers=1
fi
if (( default_workers > ram_safe_max_workers )); then
  default_workers="$ram_safe_max_workers"
fi

max_workers_allowed="$total_workers"
if (( ram_safe_max_workers < max_workers_allowed )); then
  max_workers_allowed="$ram_safe_max_workers"
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

read -r -p "Enter output directory [Default: $reports_dir]: " output_dir_input
output_dir="${output_dir_input:-$reports_dir}"
mkdir -p "$output_dir"

if [[ -n "$total_ram_mb" ]]; then
  read -r -p "Number of workers (CPU: $total_workers, RAM: ${total_ram_mb}MB, RAM-safe max: $ram_safe_max_workers, default: $default_workers): " workers_input
else
  read -r -p "Number of workers (CPU: $total_workers, default: $default_workers): " workers_input
fi

if [[ -z "$workers_input" ]]; then
  workers="$default_workers"
elif [[ "$workers_input" =~ ^[0-9]+$ ]] && (( workers_input > 0 )); then
  workers="$workers_input"
else
  echo "Invalid worker count '$workers_input'. Using default: $default_workers"
  workers="$default_workers"
fi

if (( workers > max_workers_allowed )); then
  echo "Adjusting workers from $workers to $max_workers_allowed based on CPU/RAM limits."
  workers="$max_workers_allowed"
fi

read -r -p "Set report username (leave blank to disable login): " report_username
if [[ -n "$report_username" ]]; then
  read -r -s -p "Set report password: " report_password
  echo
fi
read -r -p "Enter output formats (json,csv,html,db) or leave blank for all: " formats
read -r -p "Enable web GUI output (DB/auth)? [Y/n]: " web_choice
web_flag=""
if [[ -z "$web_choice" || "${web_choice,,}" == "y" || "${web_choice,,}" == "yes" ]]; then
  web_flag="--web"
fi

cmd=(python3 "$repo_dir/scripts/log_scanner.py" "$log_file" --output-dir "$output_dir" --tui --workers "$workers")

if [[ -n "$formats" ]]; then
  cmd+=(--formats "$formats")
fi

if [[ -n "$web_flag" ]]; then
  cmd+=("$web_flag")
fi

if [[ -n "${report_username:-}" ]]; then
  cmd+=(--report-username "$report_username" --report-password "${report_password:-}")
fi

"${cmd[@]}"
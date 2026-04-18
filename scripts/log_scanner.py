#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from reporting import StreamingReportWriter, normalize_requested_formats
from scanner_core import scan_log_file
from tui_dashboard import launch_dashboard


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="Scan .log files and write error reports.")
	parser.add_argument("log_path", type=Path, help="Path to input .log file")
	parser.add_argument(
		"--output-dir",
		type=Path,
		default=None,
		help="Directory for JSON error report output",
	)
	parser.add_argument(
		"--error-report",
		type=Path,
		default=None,
		help="Full path for JSON error report output",
	)
	parser.add_argument(
		"--formats",
		type=str,
		default=None,
		help="Comma-separated formats: json,csv,html,db (default: all)",
	)
	parser.add_argument(
		"--report-username",
		type=str,
		default=None,
		help="Username required to unlock the generated HTML report",
	)
	parser.add_argument(
		"--report-password",
		type=str,
		default=None,
		help="Password required to unlock the generated HTML report",
	)
	parser.add_argument(
		"--tui",
		action="store_true",
		help="Open the terminal dashboard after the scan completes",
	)
	parser.add_argument(
		"--web",
		action="store_true",
		help="Enable web-facing artifacts (DB and auth output)",
	)
	parser.add_argument(
		"--workers",
		type=int,
		default=None,
		help="Worker threads for scanning (default: CPU core count)",
	)
	return parser.parse_args()


def print_report(summary, report_username: str | None = None) -> None:
	print("\n=== Log Scan Summary ===")
	print(f"File: {summary.file}")
	print(f"Total lines scanned: {summary.total_lines}")
	print(f"Malicious findings: {summary.malicious_findings}")
	print(f"Error-log findings: {summary.error_log_findings}")
	print(f"Attack pattern findings: {summary.attack_pattern_findings}")
	print(f"Timestamp findings: {summary.timestamp_findings}")
	print(f"Time gap findings: {summary.time_gap_findings}")
	print(f"  - Gaps >500s (CRITICAL): {summary.time_gap_count_gt500}")
	print(f"  - Gaps 300-500s (HIGH): {summary.time_gap_count_300_to_500}")
	print(f"  - Gaps >300s (total): {summary.time_gap_count_gt300}")
	print(f"Corruption findings: {summary.corruption_findings}")
	print(f"Missing key findings: {summary.missing_key_findings}")
	if report_username:
		print(f'Error report uploaded to username "{report_username}". Please visit "our site url".')
	if summary.timestamp_mode == "not_applicable":
		print("Timestamp checks: skipped because no timestamps were detected in the file")
	print("Severity breakdown:")
	for sev in ("critical", "high", "medium", "low"):
		print(f"  - {sev}: {summary.severity_breakdown.get(sev, 0)}")
	print(f"Total findings: {sum(summary.severity_breakdown.values())}")


def write_frontend_auth(outputs: dict[str, Path], report_username: str | None, report_password: str | None) -> Path | None:
	if not report_username or not report_password:
		return None
	repo_root = Path(__file__).resolve().parents[1]
	auth_dir = repo_root / "private_auth"
	auth_dir.mkdir(parents=True, exist_ok=True)
	auth_path = auth_dir / "frontend_auth.json"
	auth_path.write_text(
		json.dumps({"username": report_username, "password": report_password}, indent=2),
		encoding="utf-8",
	)
	return auth_path


def main() -> int:
	args = parse_args()
	script_start_time = time.perf_counter()

	if not args.log_path.exists() or not args.log_path.is_file():
		print(f"Error: file not found: {args.log_path}")
		return 1

	requested_formats = normalize_requested_formats(args.formats.split(",") if args.formats else None)
	if not args.web and "db" in requested_formats:
		requested_formats = [fmt for fmt in requested_formats if fmt != "db"]
		print("Info: DB output requires web mode. Skipping DB because --web was not provided.")

	writer = StreamingReportWriter(
		args.log_path,
		requested_formats=requested_formats,
		output_dir=args.output_dir,
		explicit_path=args.error_report,
		report_username=args.report_username,
		report_password=args.report_password,
		include_dashboard_metrics=args.tui,
		script_start_time=script_start_time,
	)

	_, summary = scan_log_file(
		args.log_path,
		collect_findings=False,
		finding_sink=writer.consume,
		workers=args.workers,
	)
	outputs = writer.finalize(summary)
	auth_path = write_frontend_auth(outputs, args.report_username, args.report_password) if args.web else None
	show_text_summary = True
	if args.tui and "dashboard_metrics" in outputs:
		try:
			website_message = 'Report has been generated at the website. Please visit the webpage.'
			if args.report_username:
				website_message = f'Error report uploaded to username "{args.report_username}". Please visit the webpage.'
			show_text_summary = not launch_dashboard(
				outputs["dashboard_metrics"],
				report_path=outputs.get("json"),
				summary=summary,
				footer_message=website_message,
			)
		except Exception as exc:
			print(f"TUI dashboard unavailable: {exc}")
	if show_text_summary:
		print_report(summary, args.report_username)
	print("\nGenerated report artifacts:")
	for kind in ("json", "csv", "html", "db", "dashboard_metrics"):
		if kind in outputs:
			print(f"  - {kind.upper()}: {outputs[kind]}")
	if auth_path is not None:
		print(f"  - FRONTEND_AUTH: {auth_path}")
	return 0


if __name__ == "__main__":
	raise SystemExit(main())

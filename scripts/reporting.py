from __future__ import annotations

import csv
import gzip
import json
import re
import sqlite3
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any, Callable, Iterable

from scanner_core import MALICIOUS_PATTERNS, Finding, ScanSummary, parse_timestamp_text

SUPPORTED_FORMATS = ("json", "csv", "html", "db")
DASHBOARD_INTERVAL_COUNT = 12
MALICIOUS_IP_CATEGORIES = {"malicious", "attack_pattern", "time_gap"}


def _format_attack_label(pattern_name: str) -> str:
	if pattern_name == "sql_injection":
		return "SQL injection"
	if pattern_name == "command_injection":
		return "command injection"
	if pattern_name == "path_traversal":
		return "path traversal"
	if pattern_name == "xss_payload":
		return "XSS payload"
	return pattern_name.replace("_", " ")


MALICIOUS_PATTERN_LABELS = {
	reason: _format_attack_label(pattern_name)
	for pattern_name, _, reason, _ in MALICIOUS_PATTERNS
}


def default_error_report_dir(log_path: Path) -> Path:
	return Path.home() / "Documents" / "reports"


def ensure_suffix(path: Path, suffix: str) -> Path:
	return path if path.suffix.lower() == suffix.lower() else path.with_suffix(suffix)


def unique_report_path(path: Path, suffix: str) -> Path:
	candidate = ensure_suffix(path, suffix)
	if not candidate.exists():
		return candidate

	stem = candidate.stem
	parent = candidate.parent
	index = 1
	while True:
		next_candidate = parent / f"{stem}({index}){suffix}"
		if not next_candidate.exists():
			return next_candidate
		index += 1


def resolve_report_base(log_path: Path, output_dir: Path | None = None, explicit_path: Path | None = None) -> Path:
	if explicit_path is not None:
		return explicit_path.with_suffix("")
	base_dir = output_dir if output_dir is not None else default_error_report_dir(log_path)
	return base_dir / f"{log_path.stem}_error_report"


def normalize_requested_formats(requested_formats: list[str] | None) -> list[str]:
	if not requested_formats:
		return list(SUPPORTED_FORMATS)

	normalized = [fmt.strip().lower() for fmt in requested_formats if fmt.strip()]
	valid = [fmt for fmt in normalized if fmt in SUPPORTED_FORMATS]
	return valid if valid else list(SUPPORTED_FORMATS)


def _summary_payload(summary: ScanSummary) -> dict[str, Any]:
	return {
		"malicious_findings": summary.malicious_findings,
		"error_log_findings": summary.error_log_findings,
		"timestamp_findings": summary.timestamp_findings,
		"time_gap_findings": summary.time_gap_findings,
		"time_gap_count_gt500": summary.time_gap_count_gt500,
		"time_gap_count_300_to_500": summary.time_gap_count_300_to_500,
		"time_gap_count_gt300": summary.time_gap_count_gt300,
		"attack_pattern_findings": summary.attack_pattern_findings,
		"corruption_findings": summary.corruption_findings,
		"missing_key_findings": summary.missing_key_findings,
		"timestamp_mode": summary.timestamp_mode,
	}


def _finding_to_dict(finding: Finding) -> dict[str, Any]:
	return {
		"line_number": finding.line_number,
		"category": finding.category,
		"severity": finding.severity,
		"score": finding.score,
		"timestamp": finding.timestamp,
		"matched_phrases": list(finding.matched_phrases),
		"message": finding.message,
		"ip_address": finding.ip_address,
	}


def _finding_from_dict(raw: dict[str, Any]) -> Finding:
	phrases = raw.get("matched_phrases")
	if isinstance(phrases, list):
		matched_phrases = [str(item) for item in phrases]
	else:
		matched_phrases = []
	return Finding(
		line_number=int(raw.get("line_number", 0)),
		category=str(raw.get("category", "unknown")),
		severity=str(raw.get("severity", "low")),
		score=int(raw.get("score", 0)),
		timestamp=raw.get("timestamp") if raw.get("timestamp") is None else str(raw.get("timestamp")),
		matched_phrases=matched_phrases,
		message=str(raw.get("message", "")),
		ip_address=raw.get("ip_address") if raw.get("ip_address") is None else str(raw.get("ip_address")),
	)


def _iter_findings_from_jsonl(path: Path) -> Iterable[Finding]:
	open_fn = gzip.open if path.suffix.lower() == ".gz" else Path.open
	with open_fn(path, "rt", encoding="utf-8") as handle:
		for line in handle:
			line = line.strip()
			if not line:
				continue
			raw = json.loads(line)
			if isinstance(raw, dict):
				yield _finding_from_dict(raw)


def _split_ips(ip_field: str | None) -> list[str]:
	if not ip_field:
		return []
	return [part.strip() for part in ip_field.split(",") if part.strip()]


def _extract_gap_seconds(finding: Finding) -> int:
	for phrase in finding.matched_phrases:
		match = re.search(r"gap>(\d+)sec", phrase)
		if match:
			return int(match.group(1))
	return 0


def _is_malicious_for_ip(finding: Finding) -> bool:
	return finding.category == "error_log"


@dataclass
class DashboardMetricAccumulator:
	first_ts: datetime | None = None
	last_ts: datetime | None = None
	event_records: list[tuple[datetime, bool, int]] = field(default_factory=list)
	ip_stats: dict[str, dict[str, Any]] = field(default_factory=dict)
	ip_category_counts: dict[tuple[str, str], int] = field(default_factory=lambda: defaultdict(int))
	error_phrase_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))
	malicious_pattern_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))
	top_attack_patterns: list[str] = field(default_factory=list)

	def consume(self, finding: Finding) -> None:
		parsed = parse_timestamp_text(finding.timestamp)
		is_malicious = _is_malicious_for_ip(finding)
		gap_seconds = _extract_gap_seconds(finding) if finding.category == "time_gap" else 0

		if parsed is not None:
			if self.first_ts is None or parsed < self.first_ts:
				self.first_ts = parsed
			if self.last_ts is None or parsed > self.last_ts:
				self.last_ts = parsed
			self.event_records.append((parsed, is_malicious, gap_seconds))

		for ip in _split_ips(finding.ip_address):
			if ip not in self.ip_stats:
				self.ip_stats[ip] = {
					"ip_address": ip,
					"total_requests": 0,
					"malicious_request_count": 0,
					"critical_findings": 0,
					"high_findings": 0,
					"first_seen": None,
					"last_seen": None,
				}
			entry = self.ip_stats[ip]
			entry["total_requests"] += 1
			if is_malicious:
				entry["malicious_request_count"] += 1
			if finding.severity == "critical":
				entry["critical_findings"] += 1
			if finding.severity == "high":
				entry["high_findings"] += 1
			if parsed is not None:
				iso = parsed.isoformat()
				entry["first_seen"] = iso if entry["first_seen"] is None or iso < entry["first_seen"] else entry["first_seen"]
				entry["last_seen"] = iso if entry["last_seen"] is None or iso > entry["last_seen"] else entry["last_seen"]
			self.ip_category_counts[(ip, finding.category)] += 1

		for phrase in finding.matched_phrases:
			self.error_phrase_counts[phrase] += 1

		if finding.category == "malicious" and finding.matched_phrases:
			attack_label = MALICIOUS_PATTERN_LABELS.get(finding.matched_phrases[0], finding.matched_phrases[0])
			self.malicious_pattern_counts[attack_label] += 1

		if finding.category == "attack_pattern" and len(self.top_attack_patterns) < 10:
			self.top_attack_patterns.append(finding.message)

	def finalize(self, summary: ScanSummary, script_runtime_seconds: float | None = None) -> dict[str, Any]:
		log_span_seconds = int((self.last_ts - self.first_ts).total_seconds()) if self.first_ts and self.last_ts else 0
		display_runtime_seconds = max(0.0, float(script_runtime_seconds)) if script_runtime_seconds is not None else float(log_span_seconds)
		interval_count = DASHBOARD_INTERVAL_COUNT
		interval_seconds = max(1, log_span_seconds // interval_count) if log_span_seconds > 0 else 1

		buckets: list[dict[str, Any]] = []
		if self.first_ts and self.last_ts:
			span = self.last_ts - self.first_ts
			for idx in range(interval_count):
				start = self.first_ts + (idx * span / interval_count)
				end = self.first_ts + ((idx + 1) * span / interval_count)
				buckets.append(
					{
						"index": idx,
						"interval_start": start.isoformat(),
						"interval_end": end.isoformat(),
						"total_events": 0,
						"malicious_events": 0,
						"downtime_seconds": 0,
						"uptime_percent": 100.0,
					}
				)

		def bucket_index(ts: datetime) -> int:
			if not self.first_ts or log_span_seconds <= 0:
				return 0
			offset = int((ts - self.first_ts).total_seconds())
			raw = (offset * interval_count) // max(1, log_span_seconds)
			return min(interval_count - 1, max(0, raw))

		for parsed, is_malicious, gap_seconds in self.event_records:
			if buckets:
				idx = bucket_index(parsed)
				bucket = buckets[idx]
				bucket["total_events"] += 1
				if is_malicious:
					bucket["malicious_events"] += 1
				if gap_seconds:
					bucket["downtime_seconds"] += gap_seconds

		for bucket in buckets:
			downtime = min(bucket["downtime_seconds"], interval_seconds)
			bucket["uptime_percent"] = round(max(0.0, 100.0 - (downtime / interval_seconds * 100.0)), 2)

		ip_metrics = sorted(
			self.ip_stats.values(),
			key=lambda item: (item["malicious_request_count"], item["total_requests"], item["critical_findings"]),
			reverse=True,
		)
		top_attack_conclusion = None
		top_attack_count = 0
		if self.malicious_pattern_counts:
			top_attack_conclusion, top_attack_count = sorted(
				self.malicious_pattern_counts.items(),
				key=lambda item: (item[1], item[0]),
				reverse=True,
			)[0]
		error_phrase_frequency = [
			{"phrase": phrase, "occurrences": count}
			for phrase, count in sorted(self.error_phrase_counts.items(), key=lambda item: item[1], reverse=True)
		]
		ip_error_correlation = [
			{"ip_address": ip, "category": category, "occurrences": count}
			for (ip, category), count in sorted(self.ip_category_counts.items(), key=lambda item: item[1], reverse=True)
		]

		total_downtime_seconds = sum(bucket["downtime_seconds"] for bucket in buckets)
		availability_percent = 100.0
		if log_span_seconds > 0:
			availability_percent = round(
				max(0.0, 100.0 - ((min(total_downtime_seconds, log_span_seconds) / log_span_seconds) * 100.0)),
				2,
			)

		return {
			"trend_metadata": {
				"source_file": summary.file,
				"runtime_seconds": display_runtime_seconds,
				"log_span_seconds": log_span_seconds,
				"first_timestamp": self.first_ts.isoformat() if self.first_ts else None,
				"last_timestamp": self.last_ts.isoformat() if self.last_ts else None,
				"interval_count": interval_count,
				"interval_seconds": interval_seconds,
				"availability_percent": availability_percent,
				"time_gap_count_gt500": summary.time_gap_count_gt500,
				"time_gap_count_gt300": summary.time_gap_count_gt300,
				"top_attack_conclusion": top_attack_conclusion,
				"top_attack_count": top_attack_count,
			},
			"time_series": buckets,
			"uptime_trend": [
				{"x_seconds": idx * interval_seconds, "uptime_percent": bucket["uptime_percent"]}
				for idx, bucket in enumerate(buckets)
			],
			"ip_request_metrics": ip_metrics,
			"ip_filtering": {
				"filter_field": "malicious_request_count",
				"description": "Filter IPs by malicious request volume to detect potential hacking attempts",
			},
			"error_phrase_frequency": error_phrase_frequency,
			"ip_error_correlation": ip_error_correlation,
			"top_findings": {
				"top_ips": ip_metrics[:10],
				"top_error_phrases": error_phrase_frequency[:10],
				"top_attack_patterns": self.top_attack_patterns,
			},
		}


class StreamingReportWriter:
	def __init__(
		self,
		log_path: Path,
		requested_formats: list[str] | None = None,
		output_dir: Path | None = None,
		explicit_path: Path | None = None,
		report_username: str | None = None,
		report_password: str | None = None,
		include_dashboard_metrics: bool = False,
		script_start_time: float | None = None,
	) -> None:
		self.log_path = log_path
		self.base = resolve_report_base(log_path, output_dir=output_dir, explicit_path=explicit_path)
		self.formats = normalize_requested_formats(requested_formats)
		self.report_username = report_username
		self.report_password = report_password
		self.include_dashboard_metrics = include_dashboard_metrics or "db" in self.formats
		self.script_start_time = script_start_time
		self.accumulator = DashboardMetricAccumulator()
		self.outputs: dict[str, Path] = {}
		self._json_handle = None
		self._json_first = True
		self._csv_writer = None
		self._csv_handle = None
		self._html_handle = None
		self._db_conn = None
		self._db_cursor = None
		self._db_scan_id: int | None = None
		self._total_errors = 0
		self._errors_by_category: dict[str, int] = {}
		self._init_outputs()

	def _init_outputs(self) -> None:
		if "json" in self.formats:
			path = unique_report_path(self.base.with_suffix(".json"), ".json")
			path.parent.mkdir(parents=True, exist_ok=True)
			self._json_handle = path.open("w", encoding="utf-8")
			self.outputs["json"] = path
			self._json_handle.write("{\n")
			self._json_handle.write(f'  "source_file": {json.dumps(str(self.log_path))},\n')
			self._json_handle.write('  "errors": [\n')

		if "csv" in self.formats:
			path = unique_report_path(self.base.with_suffix(".csv"), ".csv")
			path.parent.mkdir(parents=True, exist_ok=True)
			self._csv_handle = path.open("w", encoding="utf-8", newline="")
			self._csv_writer = csv.writer(self._csv_handle)
			self._csv_writer.writerow(["line_number", "category", "severity", "score", "timestamp", "ip_address", "matched_phrases", "message"])
			self.outputs["csv"] = path

		if "html" in self.formats:
			path = unique_report_path(self.base.with_suffix(".html"), ".html")
			path.parent.mkdir(parents=True, exist_ok=True)
			self._html_handle = path.open("w", encoding="utf-8")
			self.outputs["html"] = path
			requires_auth = bool(self.report_username and self.report_password)
			content_style = "style=\"display:none;\"" if requires_auth else ""
			auth_block = ""
			if requires_auth:
				auth_block = """
	<div id=\"auth\" class=\"auth\">
		<h2>Unlock Report</h2>
		<p>Enter your report credentials.</p>
		<label for=\"username\">Username</label>
		<input id=\"username\" type=\"text\" autocomplete=\"username\" />
		<label for=\"password\">Password</label>
		<input id=\"password\" type=\"password\" autocomplete=\"current-password\" />
		<button type=\"button\" onclick=\"unlockReport()\">Open Report</button>
		<div id=\"authError\" class=\"auth-error\"></div>
	</div>
		"""
			self._html_handle.write(f"""<!doctype html>
<html lang=\"en\">
<head>
	<meta charset=\"utf-8\" />
	<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
	<title>Log Error Report</title>
	<style>
		body {{ font-family: Arial, sans-serif; margin: 24px; }}
		h1 {{ margin-bottom: 8px; }}
		h2 {{ margin: 0 0 6px; }}
		.meta {{ margin-bottom: 16px; }}
		table {{ border-collapse: collapse; width: 100%; }}
		th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 13px; }}
		th {{ background: #f4f4f4; }}
		tr:nth-child(even) {{ background: #fafafa; }}
		.auth {{ max-width: 360px; border: 1px solid #ddd; padding: 16px; border-radius: 8px; margin-bottom: 18px; }}
		.auth label {{ display: block; margin-top: 10px; font-weight: 600; }}
		.auth input {{ width: 100%; padding: 8px; margin-top: 6px; box-sizing: border-box; }}
		.auth button {{ margin-top: 12px; padding: 8px 12px; cursor: pointer; }}
		.auth-error {{ margin-top: 10px; color: #b00020; font-size: 13px; }}
	</style>
</head>
<body>
	<h1>Log Error Report</h1>
	{auth_block}
	<div id=\"content\" {content_style}>
		<table>
			<thead>
				<tr>
					<th>Line</th><th>Category</th><th>Severity</th><th>Score</th><th>Timestamp</th><th>IP Address</th><th>Phrases</th><th>Message</th>
				</tr>
			</thead>
			<tbody>
""")

		if "db" in self.formats:
			path = unique_report_path(self.base.with_suffix(".db"), ".db")
			path.parent.mkdir(parents=True, exist_ok=True)
			self._db_conn = sqlite3.connect(path)
			self._db_cursor = self._db_conn.cursor()
			self.outputs["db"] = path
			self._db_cursor.execute("PRAGMA journal_mode=WAL")
			self._db_cursor.execute("PRAGMA synchronous=NORMAL")
			self._db_cursor.execute("PRAGMA temp_store=MEMORY")
			self._db_cursor.execute(
				"""
				CREATE TABLE IF NOT EXISTS scan_meta (
					scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
					source_file TEXT NOT NULL,
					total_lines INTEGER NOT NULL,
					first_timestamp TEXT,
					last_timestamp TEXT,
					duration_seconds REAL,
					created_at TEXT DEFAULT CURRENT_TIMESTAMP
				)
				"""
			)
			self._db_cursor.execute(
				"""
				CREATE TABLE IF NOT EXISTS timestamp_events (
					event_id INTEGER PRIMARY KEY AUTOINCREMENT,
					scan_id INTEGER NOT NULL,
					line_number INTEGER NOT NULL,
					timestamp TEXT NOT NULL,
					category TEXT NOT NULL,
					severity TEXT NOT NULL,
					message TEXT,
					FOREIGN KEY(scan_id) REFERENCES scan_meta(scan_id)
				)
				"""
			)
			self._db_cursor.execute(
				"""
				CREATE TABLE IF NOT EXISTS time_gap_events (
					gap_id INTEGER PRIMARY KEY AUTOINCREMENT,
					scan_id INTEGER NOT NULL,
					line_number INTEGER NOT NULL,
					timestamp TEXT,
					gap_seconds INTEGER NOT NULL,
					severity TEXT,
					message TEXT,
					FOREIGN KEY(scan_id) REFERENCES scan_meta(scan_id)
				)
				"""
			)
			self._db_cursor.execute(
				"""
				CREATE TABLE IF NOT EXISTS ip_request_metrics (
					metric_id INTEGER PRIMARY KEY AUTOINCREMENT,
					scan_id INTEGER NOT NULL,
					ip_address TEXT NOT NULL,
					total_requests INTEGER NOT NULL,
					malicious_request_count INTEGER NOT NULL,
					critical_findings INTEGER NOT NULL,
					high_findings INTEGER NOT NULL,
					first_seen TEXT,
					last_seen TEXT,
					FOREIGN KEY(scan_id) REFERENCES scan_meta(scan_id)
				)
				"""
			)
			self._db_cursor.execute(
				"""
				CREATE TABLE IF NOT EXISTS error_phrase_metrics (
					metric_id INTEGER PRIMARY KEY AUTOINCREMENT,
					scan_id INTEGER NOT NULL,
					phrase TEXT NOT NULL,
					occurrences INTEGER NOT NULL,
					FOREIGN KEY(scan_id) REFERENCES scan_meta(scan_id)
				)
				"""
			)
			self._db_cursor.execute(
				"""
				CREATE TABLE IF NOT EXISTS ip_category_metrics (
					metric_id INTEGER PRIMARY KEY AUTOINCREMENT,
					scan_id INTEGER NOT NULL,
					ip_address TEXT NOT NULL,
					category TEXT NOT NULL,
					occurrences INTEGER NOT NULL,
					FOREIGN KEY(scan_id) REFERENCES scan_meta(scan_id)
				)
				"""
			)
			self._db_cursor.execute(
				"""
				CREATE TABLE IF NOT EXISTS uptime_intervals (
					interval_id INTEGER PRIMARY KEY AUTOINCREMENT,
					scan_id INTEGER NOT NULL,
					interval_index INTEGER NOT NULL,
					interval_start TEXT,
					interval_end TEXT,
					total_events INTEGER NOT NULL,
					malicious_events INTEGER NOT NULL,
					downtime_seconds INTEGER NOT NULL,
					uptime_percent REAL NOT NULL,
					FOREIGN KEY(scan_id) REFERENCES scan_meta(scan_id)
				)
				"""
			)
			self._db_cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip_malicious_requests ON ip_request_metrics (scan_id, malicious_request_count DESC)")
			self._db_cursor.execute(
				"INSERT INTO scan_meta (source_file, total_lines, first_timestamp, last_timestamp, duration_seconds) VALUES (?, ?, ?, ?, ?)",
				(str(self.log_path), 0, None, None, None),
			)
			self._db_scan_id = int(self._db_cursor.lastrowid)
			self._db_conn.commit()

	def consume(self, finding: Finding) -> None:
		self.accumulator.consume(finding)
		self._total_errors += 1
		self._errors_by_category[finding.category] = self._errors_by_category.get(finding.category, 0) + 1

		if self._json_handle is not None:
			if not self._json_first:
				self._json_handle.write(",\n")
			self._json_handle.write(f"    {json.dumps(_finding_to_dict(finding))}")
			self._json_first = False

		if self._csv_writer is not None:
			self._csv_writer.writerow([
				finding.line_number,
				finding.category,
				finding.severity,
				finding.score,
				finding.timestamp or "",
				finding.ip_address or "",
				";".join(finding.matched_phrases),
				finding.message,
			])

		if self._html_handle is not None:
			self._html_handle.write(
				"<tr>"
				f"<td>{finding.line_number}</td>"
				f"<td>{escape(finding.category)}</td>"
				f"<td>{escape(finding.severity)}</td>"
				f"<td>{finding.score}</td>"
				f"<td>{escape(finding.timestamp or '')}</td>"
				f"<td>{escape(finding.ip_address or '')}</td>"
				f"<td>{escape(', '.join(finding.matched_phrases))}</td>"
				f"<td>{escape(finding.message)}</td>"
				"</tr>\n"
			)

		if self._db_cursor is not None and self._db_scan_id is not None:
			if finding.timestamp is not None:
				self._db_cursor.execute(
					"INSERT INTO timestamp_events (scan_id, line_number, timestamp, category, severity, message) VALUES (?, ?, ?, ?, ?, ?)",
					(self._db_scan_id, finding.line_number, finding.timestamp, finding.category, finding.severity, finding.message),
				)
			if finding.timestamp is not None and finding.category == "time_gap":
				self._db_cursor.execute(
					"INSERT INTO time_gap_events (scan_id, line_number, timestamp, gap_seconds, severity, message) VALUES (?, ?, ?, ?, ?, ?)",
					(self._db_scan_id, finding.line_number, finding.timestamp, _extract_gap_seconds(finding), finding.severity, finding.message),
				)

	def finalize(self, summary: ScanSummary) -> dict[str, Path]:
		script_runtime = None
		if self.script_start_time is not None:
			script_runtime = max(0.0, time.perf_counter() - self.script_start_time)
		dashboard_metrics = self.accumulator.finalize(summary, script_runtime_seconds=script_runtime)

		if self._json_handle is not None:
			self._json_handle.write("\n  ],\n")
			self._json_handle.write(f'  "total_lines": {summary.total_lines},\n')
			self._json_handle.write(f'  "total_errors": {self._total_errors},\n')
			self._json_handle.write(f'  "errors_by_category": {json.dumps(self._errors_by_category)},\n')
			self._json_handle.write(f'  "errors_by_severity": {json.dumps(summary.severity_breakdown)},\n')
			self._json_handle.write(f'  "summary": {json.dumps(_summary_payload(summary))}\n')
			self._json_handle.write("}\n")
			self._json_handle.close()

		if self._csv_handle is not None:
			self._csv_handle.close()

		if self._html_handle is not None:
			auth_script = ""
			if self.report_username and self.report_password:
				user_js = json.dumps(self.report_username)
				pass_js = json.dumps(self.report_password)
				auth_script = f"""
	<script>
		const REPORT_USER = {user_js};
		const REPORT_PASS = {pass_js};

		function unlockReport() {{
			const enteredUser = document.getElementById('username').value;
			const enteredPass = document.getElementById('password').value;
			if (enteredUser === REPORT_USER && enteredPass === REPORT_PASS) {{
				document.getElementById('auth').style.display = 'none';
				document.getElementById('content').style.display = 'block';
				document.getElementById('authError').textContent = '';
				return;
			}}
			document.getElementById('authError').textContent = 'Invalid username or password.';
		}}
	</script>
		"""
			self._html_handle.write(f"""\
			</tbody>
		</table>
		<div class=\"meta\">Source: {escape(summary.file)}<br/>Total lines: {summary.total_lines}<br/>Total findings: {self._total_errors}</div>
	</div>
	{auth_script}
</body>
</html>
""")
			self._html_handle.close()

		if self._db_conn is not None and self._db_cursor is not None and self._db_scan_id is not None:
			first_ts = dashboard_metrics.get("trend_metadata", {}).get("first_timestamp")
			last_ts = dashboard_metrics.get("trend_metadata", {}).get("last_timestamp")
			duration = None
			if self.accumulator.first_ts is not None and self.accumulator.last_ts is not None and self.accumulator.last_ts > self.accumulator.first_ts:
				duration = (self.accumulator.last_ts - self.accumulator.first_ts).total_seconds()
			self._db_cursor.execute(
				"UPDATE scan_meta SET source_file = ?, total_lines = ?, first_timestamp = ?, last_timestamp = ?, duration_seconds = ? WHERE scan_id = ?",
				(summary.file, summary.total_lines, first_ts, last_ts, duration, self._db_scan_id),
			)
			for row in dashboard_metrics.get("ip_request_metrics", []):
				self._db_cursor.execute(
					"""
					INSERT INTO ip_request_metrics
					(scan_id, ip_address, total_requests, malicious_request_count, critical_findings, high_findings, first_seen, last_seen)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?)
					""",
					(
						self._db_scan_id,
						row.get("ip_address"),
						row.get("total_requests", 0),
						row.get("malicious_request_count", 0),
						row.get("critical_findings", 0),
						row.get("high_findings", 0),
						row.get("first_seen"),
						row.get("last_seen"),
					),
				)
			for row in dashboard_metrics.get("error_phrase_frequency", []):
				self._db_cursor.execute(
					"INSERT INTO error_phrase_metrics (scan_id, phrase, occurrences) VALUES (?, ?, ?)",
					(self._db_scan_id, row.get("phrase"), row.get("occurrences", 0)),
				)
			for row in dashboard_metrics.get("ip_error_correlation", []):
				self._db_cursor.execute(
					"INSERT INTO ip_category_metrics (scan_id, ip_address, category, occurrences) VALUES (?, ?, ?, ?)",
					(self._db_scan_id, row.get("ip_address"), row.get("category"), row.get("occurrences", 0)),
				)
			for row in dashboard_metrics.get("time_series", []):
				self._db_cursor.execute(
					"""
					INSERT INTO uptime_intervals
					(scan_id, interval_index, interval_start, interval_end, total_events, malicious_events, downtime_seconds, uptime_percent)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?)
					""",
					(
						self._db_scan_id,
						row.get("index", 0),
						row.get("interval_start"),
						row.get("interval_end"),
						row.get("total_events", 0),
						row.get("malicious_events", 0),
						row.get("downtime_seconds", 0),
						row.get("uptime_percent", 100.0),
					),
				)
			self._db_conn.commit()
			self._db_conn.close()

		if self.include_dashboard_metrics:
			metrics_path = unique_report_path(self.base.parent / f"{self.base.name}_dashboard_metrics.json", ".json")
			metrics_path.parent.mkdir(parents=True, exist_ok=True)
			metrics_path.write_text(json.dumps(dashboard_metrics, indent=2), encoding="utf-8")
			self.outputs["dashboard_metrics"] = metrics_path

		return self.outputs


def write_all_reports(
	log_path: Path,
	summary: ScanSummary,
	findings: list[Finding] | None = None,
	findings_jsonl: Path | None = None,
	script_start_time: float | None = None,
	include_dashboard_metrics: bool = False,
	output_dir: Path | None = None,
	explicit_path: Path | None = None,
	requested_formats: list[str] | None = None,
	report_username: str | None = None,
	report_password: str | None = None,
) -> dict[str, Path]:
	if findings_jsonl is None and findings is None:
		raise ValueError("Either findings or findings_jsonl must be provided")

	writer = StreamingReportWriter(
		log_path,
		requested_formats=requested_formats,
		output_dir=output_dir,
		explicit_path=explicit_path,
		report_username=report_username,
		report_password=report_password,
		include_dashboard_metrics=include_dashboard_metrics,
		script_start_time=script_start_time,
	)

	if findings is not None:
		for finding in findings:
			writer.consume(finding)
	else:
		for finding in _iter_findings_from_jsonl(findings_jsonl):
			writer.consume(finding)

	return writer.finalize(summary)

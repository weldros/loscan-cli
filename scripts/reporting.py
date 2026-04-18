from __future__ import annotations

import csv
import gzip
import json
import re
import sqlite3
import time
from collections import defaultdict
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any, Callable, Iterable

from scanner_core import Finding, ScanSummary, parse_timestamp_text

SUPPORTED_FORMATS = ("json", "csv", "html", "db")
DASHBOARD_INTERVAL_COUNT = 12
MALICIOUS_IP_CATEGORIES = {"malicious", "attack_pattern", "time_gap"}


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
	return finding.category in MALICIOUS_IP_CATEGORIES or finding.severity == "critical"


def build_dashboard_metrics(
	summary: ScanSummary,
	iter_findings: Callable[[], Iterable[Finding]],
	script_runtime_seconds: float | None = None,
) -> dict[str, Any]:
	first_ts: datetime | None = None
	last_ts: datetime | None = None
	for finding in iter_findings():
		parsed = parse_timestamp_text(finding.timestamp)
		if parsed is None:
			continue
		if first_ts is None or parsed < first_ts:
			first_ts = parsed
		if last_ts is None or parsed > last_ts:
			last_ts = parsed

	log_span_seconds = int((last_ts - first_ts).total_seconds()) if first_ts and last_ts else 0
	display_runtime_seconds = max(0.0, float(script_runtime_seconds)) if script_runtime_seconds is not None else float(log_span_seconds)
	interval_count = DASHBOARD_INTERVAL_COUNT
	interval_seconds = max(1, log_span_seconds // interval_count) if log_span_seconds > 0 else 1

	buckets: list[dict[str, Any]] = []
	if first_ts and last_ts:
		for idx in range(interval_count):
			start = first_ts + (idx * (last_ts - first_ts) / interval_count)
			end = first_ts + ((idx + 1) * (last_ts - first_ts) / interval_count)
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
		if not first_ts or log_span_seconds <= 0:
			return 0
		offset = int((ts - first_ts).total_seconds())
		raw = (offset * interval_count) // max(1, log_span_seconds)
		return min(interval_count - 1, max(0, raw))

	ip_stats: dict[str, dict[str, Any]] = {}
	ip_category_counts: dict[tuple[str, str], int] = defaultdict(int)
	error_phrase_counts: dict[str, int] = defaultdict(int)
	top_attack_patterns: list[str] = []

	for finding in iter_findings():
		parsed = parse_timestamp_text(finding.timestamp)
		if parsed is not None and buckets:
			idx = bucket_index(parsed)
			bucket = buckets[idx]
			bucket["total_events"] += 1
			if _is_malicious_for_ip(finding):
				bucket["malicious_events"] += 1
			if finding.category == "time_gap":
				bucket["downtime_seconds"] += _extract_gap_seconds(finding)

		for ip in _split_ips(finding.ip_address):
			if ip not in ip_stats:
				ip_stats[ip] = {
					"ip_address": ip,
					"total_requests": 0,
					"malicious_request_count": 0,
					"critical_findings": 0,
					"high_findings": 0,
					"first_seen": None,
					"last_seen": None,
				}
			entry = ip_stats[ip]
			entry["total_requests"] += 1
			if _is_malicious_for_ip(finding):
				entry["malicious_request_count"] += 1
			if finding.severity == "critical":
				entry["critical_findings"] += 1
			if finding.severity == "high":
				entry["high_findings"] += 1
			if parsed is not None:
				iso = parsed.isoformat()
				entry["first_seen"] = iso if entry["first_seen"] is None or iso < entry["first_seen"] else entry["first_seen"]
				entry["last_seen"] = iso if entry["last_seen"] is None or iso > entry["last_seen"] else entry["last_seen"]
			ip_category_counts[(ip, finding.category)] += 1

		for phrase in finding.matched_phrases:
			error_phrase_counts[phrase] += 1

		if finding.category == "attack_pattern" and len(top_attack_patterns) < 10:
			top_attack_patterns.append(finding.message)

	for bucket in buckets:
		downtime = min(bucket["downtime_seconds"], interval_seconds)
		bucket["uptime_percent"] = round(max(0.0, 100.0 - (downtime / interval_seconds * 100.0)), 2)

	ip_metrics = sorted(
		ip_stats.values(),
		key=lambda item: (item["malicious_request_count"], item["total_requests"], item["critical_findings"]),
		reverse=True,
	)
	error_phrase_frequency = [
		{"phrase": phrase, "occurrences": count}
		for phrase, count in sorted(error_phrase_counts.items(), key=lambda item: item[1], reverse=True)
	]
	ip_error_correlation = [
		{"ip_address": ip, "category": category, "occurrences": count}
		for (ip, category), count in sorted(ip_category_counts.items(), key=lambda item: item[1], reverse=True)
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
			"first_timestamp": first_ts.isoformat() if first_ts else None,
			"last_timestamp": last_ts.isoformat() if last_ts else None,
			"interval_count": interval_count,
			"interval_seconds": interval_seconds,
			"availability_percent": availability_percent,
			"time_gap_count_gt500": summary.time_gap_count_gt500,
			"time_gap_count_gt300": summary.time_gap_count_gt300,
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
			"top_attack_patterns": top_attack_patterns,
		},
	}


def write_dashboard_metrics_json(path: Path, metrics: dict[str, Any]) -> Path:
	out = unique_report_path(path, ".json")
	out.parent.mkdir(parents=True, exist_ok=True)
	out.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
	return out


def write_json_report(path: Path, summary: ScanSummary, iter_findings: Callable[[], Iterable[Finding]]) -> Path:
	by_category: dict[str, int] = {}
	total_errors = 0
	for finding in iter_findings():
		by_category[finding.category] = by_category.get(finding.category, 0) + 1
		total_errors += 1

	out = unique_report_path(path, ".json")
	out.parent.mkdir(parents=True, exist_ok=True)
	with out.open("w", encoding="utf-8") as handle:
		handle.write("{\n")
		handle.write(f'  "source_file": {json.dumps(summary.file)},\n')
		handle.write(f'  "total_lines": {summary.total_lines},\n')
		handle.write(f'  "total_errors": {total_errors},\n')
		handle.write(f'  "errors_by_category": {json.dumps(by_category)},\n')
		handle.write(f'  "errors_by_severity": {json.dumps(summary.severity_breakdown)},\n')
		handle.write(f'  "summary": {json.dumps(_summary_payload(summary))},\n')
		handle.write('  "errors": [\n')
		first = True
		for finding in iter_findings():
			if not first:
				handle.write(",\n")
			handle.write(f"    {json.dumps(_finding_to_dict(finding))}")
			first = False
		handle.write("\n  ]\n}\n")
	return out


def write_csv_report(path: Path, iter_findings: Callable[[], Iterable[Finding]]) -> Path:
	out = unique_report_path(path, ".csv")
	out.parent.mkdir(parents=True, exist_ok=True)
	with out.open("w", encoding="utf-8", newline="") as handle:
		writer = csv.writer(handle)
		writer.writerow(["line_number", "category", "severity", "score", "timestamp", "ip_address", "matched_phrases", "message"])
		for finding in iter_findings():
			writer.writerow([
				finding.line_number,
				finding.category,
				finding.severity,
				finding.score,
				finding.timestamp or "",
				finding.ip_address or "",
				";".join(finding.matched_phrases),
				finding.message,
			])
	return out


def write_html_report(
	path: Path,
	summary: ScanSummary,
	iter_findings: Callable[[], Iterable[Finding]],
	report_username: str | None = None,
	report_password: str | None = None,
) -> Path:
	out = unique_report_path(path, ".html")
	out.parent.mkdir(parents=True, exist_ok=True)

	requires_auth = bool(report_username and report_password)
	user_js = json.dumps(report_username) if report_username else "null"
	pass_js = json.dumps(report_password) if report_password else "null"
	auth_block = ""
	auth_script = ""
	content_style = ""
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
		content_style = "style=\"display:none;\""
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

	total_findings = int(sum(summary.severity_breakdown.values()))
	with out.open("w", encoding="utf-8") as handle:
		handle.write(f"""<!doctype html>
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
		<div class=\"meta\">Source: {escape(summary.file)}<br/>Total lines: {summary.total_lines}<br/>Total findings: {total_findings}</div>
		<table>
			<thead>
				<tr>
					<th>Line</th><th>Category</th><th>Severity</th><th>Score</th><th>Timestamp</th><th>IP Address</th><th>Phrases</th><th>Message</th>
				</tr>
			</thead>
			<tbody>
""")
		for finding in iter_findings():
			handle.write(
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
		handle.write(f"""			</tbody>
		</table>
	</div>
	{auth_script}
</body>
</html>
""")
	return out


def write_timestamps_db(
	path: Path,
	summary: ScanSummary,
	iter_findings: Callable[[], Iterable[Finding]],
	dashboard_metrics: dict[str, Any],
) -> Path:
	out = unique_report_path(path, ".db")
	out.parent.mkdir(parents=True, exist_ok=True)
	conn = sqlite3.connect(out)
	try:
		conn.execute("PRAGMA journal_mode=WAL")
		conn.execute("PRAGMA synchronous=NORMAL")
		conn.execute("PRAGMA temp_store=MEMORY")
		cur = conn.cursor()
		cur.execute(
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
		cur.execute(
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
		cur.execute(
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
		cur.execute(
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
		cur.execute(
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
		cur.execute(
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
		cur.execute(
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
		cur.execute("CREATE INDEX IF NOT EXISTS idx_ip_malicious_requests ON ip_request_metrics (scan_id, malicious_request_count DESC)")

		first_ts: datetime | None = None
		last_ts: datetime | None = None
		for finding in iter_findings():
			parsed = parse_timestamp_text(finding.timestamp)
			if parsed is None:
				continue
			if first_ts is None or parsed < first_ts:
				first_ts = parsed
			if last_ts is None or parsed > last_ts:
				last_ts = parsed
		duration = (last_ts - first_ts).total_seconds() if first_ts and last_ts and last_ts > first_ts else None

		cur.execute(
			"INSERT INTO scan_meta (source_file, total_lines, first_timestamp, last_timestamp, duration_seconds) VALUES (?, ?, ?, ?, ?)",
			(summary.file, summary.total_lines, first_ts.isoformat() if first_ts else None, last_ts.isoformat() if last_ts else None, duration),
		)
		scan_id = int(cur.lastrowid)

		for finding in iter_findings():
			if finding.timestamp is not None:
				cur.execute(
					"INSERT INTO timestamp_events (scan_id, line_number, timestamp, category, severity, message) VALUES (?, ?, ?, ?, ?, ?)",
					(scan_id, finding.line_number, finding.timestamp, finding.category, finding.severity, finding.message),
				)
			if finding.timestamp is not None and finding.category == "time_gap":
				cur.execute(
					"INSERT INTO time_gap_events (scan_id, line_number, timestamp, gap_seconds, severity, message) VALUES (?, ?, ?, ?, ?, ?)",
					(scan_id, finding.line_number, finding.timestamp, _extract_gap_seconds(finding), finding.severity, finding.message),
				)

		for row in dashboard_metrics.get("ip_request_metrics", []):
			cur.execute(
				"""
				INSERT INTO ip_request_metrics
				(scan_id, ip_address, total_requests, malicious_request_count, critical_findings, high_findings, first_seen, last_seen)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)
				""",
				(
					scan_id,
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
			cur.execute(
				"INSERT INTO error_phrase_metrics (scan_id, phrase, occurrences) VALUES (?, ?, ?)",
				(scan_id, row.get("phrase"), row.get("occurrences", 0)),
			)

		for row in dashboard_metrics.get("ip_error_correlation", []):
			cur.execute(
				"INSERT INTO ip_category_metrics (scan_id, ip_address, category, occurrences) VALUES (?, ?, ?, ?)",
				(scan_id, row.get("ip_address"), row.get("category"), row.get("occurrences", 0)),
			)

		for row in dashboard_metrics.get("time_series", []):
			cur.execute(
				"""
				INSERT INTO uptime_intervals
				(scan_id, interval_index, interval_start, interval_end, total_events, malicious_events, downtime_seconds, uptime_percent)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)
				""",
				(
					scan_id,
					row.get("index", 0),
					row.get("interval_start"),
					row.get("interval_end"),
					row.get("total_events", 0),
					row.get("malicious_events", 0),
					row.get("downtime_seconds", 0),
					row.get("uptime_percent", 100.0),
				),
			)
		conn.commit()
	finally:
		conn.close()

	return out


def normalize_requested_formats(requested_formats: list[str] | None) -> list[str]:
	if not requested_formats:
		return list(SUPPORTED_FORMATS)

	normalized = [fmt.strip().lower() for fmt in requested_formats if fmt.strip()]
	valid = [fmt for fmt in normalized if fmt in SUPPORTED_FORMATS]
	return valid if valid else list(SUPPORTED_FORMATS)


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

	def iter_findings() -> Iterable[Finding]:
		if findings_jsonl is not None:
			return _iter_findings_from_jsonl(findings_jsonl)
		return iter(findings or [])

	base = resolve_report_base(log_path, output_dir=output_dir, explicit_path=explicit_path)
	formats = normalize_requested_formats(requested_formats)

	outputs: dict[str, Path] = {}
	dashboard_metrics: dict[str, Any] | None = None
	script_runtime_seconds = None
	if script_start_time is not None:
		script_runtime_seconds = max(0.0, time.perf_counter() - script_start_time)
	if include_dashboard_metrics or "db" in formats:
		dashboard_metrics = build_dashboard_metrics(summary, iter_findings, script_runtime_seconds=script_runtime_seconds)
	if include_dashboard_metrics and dashboard_metrics is not None:
		outputs["dashboard_metrics"] = write_dashboard_metrics_json(
			base.parent / f"{base.name}_dashboard_metrics.json",
			dashboard_metrics,
		)
	if "json" in formats:
		outputs["json"] = write_json_report(base.with_suffix(".json"), summary, iter_findings)
	if "csv" in formats:
		outputs["csv"] = write_csv_report(base.with_suffix(".csv"), iter_findings)
	if "html" in formats:
		outputs["html"] = write_html_report(
			base.with_suffix(".html"),
			summary,
			iter_findings,
			report_username=report_username,
			report_password=report_password,
		)
	if "db" in formats:
		if dashboard_metrics is None:
			dashboard_metrics = build_dashboard_metrics(summary, iter_findings, script_runtime_seconds=script_runtime_seconds)
		outputs["db"] = write_timestamps_db(base.with_suffix(".db"), summary, iter_findings, dashboard_metrics)
	return outputs

from __future__ import annotations

import json
import os
import re
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from itertools import islice
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Iterable

#pattern detection block
MALICIOUS_PATTERNS: list[tuple[str, re.Pattern[str], str, int]] = [
	(
		"sql_injection",
		re.compile(r"(?i)(union\s+select|or\s+1=1|drop\s+table|information_schema)"),
		"Possible SQL injection payload",
		4,
	),
	(
		"command_injection",
		re.compile(r"(?i)(\b(?:wget|curl|nc|netcat|bash\s+-c|powershell)\b)"),
		"Suspicious command execution token",
		4,
	),
	(
		"path_traversal",
		re.compile(r"(\.\./|%2e%2e%2f|%252e%252e%252f)", re.IGNORECASE),
		"Potential path traversal pattern",
		3,
	),
	(
		"xss_payload",
		re.compile(r"(?i)(<script\b|javascript:|onerror\s*=|onload\s*=)"),
		"Potential XSS payload",
		3,
	),
]

#timestamp recognition
TIMESTAMP_PATTERNS: list[re.Pattern[str]] = [
	re.compile(r"^\s*\[([A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}\s\d{4})\]"),
	re.compile(r"^\s*([A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}\s\d{4})"),
	re.compile(r"^\s*(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"),
	re.compile(r"^\s*(\d{4}/\d{2}/\d{2}\s\d{2}:\d{2}:\d{2})"),
	re.compile(r"^\s*([A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})"),
]

TIMESTAMP_FORMATS: list[str] = [
	"%a %b %d %H:%M:%S %Y",
	"%Y-%m-%d %H:%M:%S",
	"%Y-%m-%dT%H:%M:%S",
	"%Y-%m-%dT%H:%M:%S.%f",
	"%Y-%m-%d %H:%M:%S.%f",
	"%Y/%m/%d %H:%M:%S",
	"%b %d %H:%M:%S",
]

CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F]")
KEY_VALUE_RE = re.compile(r"(?:^|\s)([A-Za-z0-9_.:-]+)=")
ERROR_KEYPHRASES = [
	"authentication failure",
	"access denied",
	"permission denied",
	"connection refused",
	"service unavailable",
	"permission denied",
	"timed out",
	"fatal",
	"panic",
	"denied",
	"refused",
	"unavailable",
	"corrupt",
	"invalid",
	"invalid user",
	"timeout",
	"segfault",
	"not found",
	"unable to",
	"failed password",
	"connection refused",
]

ERROR_KEYWORDS = {
	# "error",
	# "errors",
	# "failed",
	# "failure",
	"fatal",
	"critical",
	"alert",
	"emergency",
	"panic",
	"denied",
	"refused",
	"invalid",
	"timeout",
	"corrupt",
	"unavailable",
	"retry",
	"unreachable",
	"forbidden",
	"unauthorized",
	"segfault",
	"blocked",
	"unauthorized",
}

WORD_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{1,}")
IP_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
LOCAL_IP_EXCEPTIONS = {"127.0.0.1", "0.0.0.0"}
ENABLE_OUT_OF_ORDER_TIMESTAMP = False
TIME_GAP_THRESHOLD_HIGH = timedelta(seconds=300)
TIME_GAP_THRESHOLD_CRITICAL = timedelta(seconds=500)
COMMON_KEY_MIN_LINES = 5
LINE_BATCH_SIZE = 4096

HIGH_SEVERITY_ERROR_TERMS = {
	"error",
	"failed",
	"failure",
	"fatal",
	"critical",
	"panic",
	"denied",
	"unauthorized",
	"forbidden",
	"authentication failure",
	"access denied",
	"permission denied",
	"connection refused",
}

ERROR_PHRASE_PATTERNS: list[tuple[str, re.Pattern[str]]] = []
for _phrase in ERROR_KEYPHRASES:
	_phrase_re = re.escape(_phrase).replace(r"\ ", r"\s+")
	ERROR_PHRASE_PATTERNS.append((_phrase, re.compile(rf"\b{_phrase_re}\b")))


@dataclass
class Finding:
	line_number: int
	timestamp: str | None
	severity: str
	score: int
	category: str
	matched_phrases: list[str]
	message: str
	ip_address: str | None = None


@dataclass
class LineScanResult:
	line_number: int
	line_snippet: str
	timestamp_text: str | None
	parsed_timestamp: datetime | None
	ip_address: str | None
	line_keys: list[str]
	findings: list[Finding]


@dataclass
class ScanBatch:
	rows: list[tuple[int, str]]
	bytes_read: int


@dataclass
class ScanSummary:
	file: str
	total_lines: int
	malicious_findings: int
	timestamp_findings: int
	time_gap_findings: int
	time_gap_count_gt500: int
	time_gap_count_300_to_500: int
	time_gap_count_gt300: int
	corruption_findings: int
	missing_key_findings: int
	error_log_findings: int
	attack_pattern_findings: int
	timestamp_mode: str
	severity_breakdown: dict[str, int]


def parse_timestamp_text(raw: str | None) -> datetime | None:
	if raw is None:
		return None

	iso_candidate = raw.replace("Z", "+00:00")
	try:
		return datetime.fromisoformat(iso_candidate)
	except ValueError:
		pass

	for fmt in TIMESTAMP_FORMATS:
		try:
			dt = datetime.strptime(raw, fmt)
			if fmt == "%b %d %H:%M:%S":
				dt = dt.replace(year=datetime.now().year)
			return dt
		except ValueError:
			continue
	return None


def extract_timestamp_text(line: str) -> str | None:
	for pattern in TIMESTAMP_PATTERNS:
		match = pattern.search(line)
		if match:
			return match.group(1)
	return None


def extract_keys(line: str) -> set[str]:
	keys: set[str] = set()
	text = line.strip()
	if not text:
		return keys

	if text.startswith("{") and text.endswith("}"):
		try:
			parsed = json.loads(text)
			if isinstance(parsed, dict):
				return {str(key) for key in parsed.keys()}
		except json.JSONDecodeError:
			pass

	for match in KEY_VALUE_RE.finditer(text):
		keys.add(match.group(1))
	return keys


def extract_words(line: str) -> set[str]:
	return {word.lower() for word in WORD_RE.findall(line)}


def extract_all_ips(line: str) -> str | None:
	"""Extract all non-exception IPv4 addresses from the line, as a comma-separated string."""
	matches = [ip for ip in IP_RE.findall(line) if ip not in LOCAL_IP_EXCEPTIONS]
	if matches:
		return ",".join(sorted(set(matches)))  # unique IPs in stable order
	return None


def score_to_severity(score: int) -> str:
	if score >= 8:
		return "critical"
	if score >= 5:
		return "high"
	if score >= 3:
		return "medium"
	return "low"


def _detect_malicious_context(line_number: int, timestamp_text: str | None, ip_addr: str | None, line_snippet: str, line: str) -> list[Finding]:
	findings: list[Finding] = []
	for _, pattern, reason, score in MALICIOUS_PATTERNS:
		if pattern.search(line):
			findings.append(
				Finding(
					line_number=line_number,
					category="malicious",
					severity=score_to_severity(score),
					score=score,
					timestamp=timestamp_text,
					matched_phrases=[reason],
					message=line_snippet,
					ip_address=ip_addr,
				)
			)
	return findings


def _extract_error_matches(line: str) -> list[str]:
	text_lower = line.lower()
	matches: list[str] = []
	covered_ranges: list[tuple[int, int]] = []

	for phrase, pattern in ERROR_PHRASE_PATTERNS:
		for match in pattern.finditer(text_lower):
			matches.append(phrase)
			covered_ranges.append(match.span())

	def word_is_covered(word: str) -> bool:
		for word_match in re.finditer(rf"\b{re.escape(word)}\b", text_lower):
			for start, end in covered_ranges:
				if word_match.start() >= start and word_match.end() <= end:
					return True
		return False

	for word in extract_words(text_lower):
		if word in ERROR_KEYWORDS and not word_is_covered(word):
			matches.append(word)

	return sorted(set(matches))[:6]


def _detect_error_keywords_context(line_number: int, timestamp_text: str | None, ip_addr: str | None, line_snippet: str, line: str) -> list[Finding]:
	matches = _extract_error_matches(line)
	if not matches:
		return []

	severity = "high" if any(word in HIGH_SEVERITY_ERROR_TERMS for word in matches) else "medium"
	return [
		Finding(
			line_number=line_number,
			category="error_log",
			severity=severity,
			score=6 if severity == "high" else 4,
			timestamp=timestamp_text,
			matched_phrases=matches,
			message=line_snippet,
			ip_address=ip_addr,
		)
	]


def _detect_missing_keys_context(line_number: int, timestamp_text: str | None, ip_addr: str | None, line_snippet: str, line_keys: list[str], expected_keys: list[str]) -> list[Finding]:
	if not expected_keys or not line_keys:
		return []

	line_key_set = set(line_keys)
	missing = [key for key in expected_keys if key not in line_key_set]
	if not missing:
		return []

	return [
		Finding(
			line_number=line_number,
			category="schema",
			severity="medium",
			score=3,
			timestamp=timestamp_text,
			matched_phrases=missing[:8],
			message=line_snippet,
			ip_address=ip_addr,
		)
	]


def _detect_corruption_context(line_number: int, timestamp_text: str | None, ip_addr: str | None, line_snippet: str, line: str) -> list[Finding]:
	findings: list[Finding] = []
	replacement_count = line.count("\ufffd")
	if replacement_count >= 2:
		score = min(8, 2 + replacement_count)
		findings.append(
			Finding(
				line_number=line_number,
				category="corruption",
				severity=score_to_severity(score),
				score=score,
				timestamp=timestamp_text,
				matched_phrases=[f"decode_replacement:{replacement_count}"],
				message=line_snippet,
				ip_address=ip_addr,
			)
		)

	control_chars = CONTROL_CHAR_RE.findall(line)
	if len(control_chars) >= 2:
		score = min(7, 2 + len(control_chars))
		findings.append(
			Finding(
				line_number=line_number,
				category="corruption",
				severity=score_to_severity(score),
				score=score,
				timestamp=timestamp_text,
				matched_phrases=[f"control_chars:{len(control_chars)}"],
				message=line_snippet,
				ip_address=ip_addr,
			)
		)

	if len(line) > 20000:
		findings.append(
			Finding(
				line_number=line_number,
				category="corruption",
				severity="medium",
				score=4,
				timestamp=timestamp_text,
				matched_phrases=["very_long_line"],
				message=line_snippet,
				ip_address=ip_addr,
			)
		)

	return findings


def _scan_line_batch(batch: list[tuple[int, str]]) -> list[LineScanResult]:
	results: list[LineScanResult] = []
	for line_number, line in batch:
		timestamp_text = extract_timestamp_text(line)
		parsed_timestamp = parse_timestamp_text(timestamp_text)
		ip_addr = extract_all_ips(line)
		line_snippet = line.strip()[:240]
		line_keys = sorted(extract_keys(line))
		findings: list[Finding] = []
		findings.extend(_detect_malicious_context(line_number, timestamp_text, ip_addr, line_snippet, line))
		findings.extend(_detect_error_keywords_context(line_number, timestamp_text, ip_addr, line_snippet, line))
		findings.extend(_detect_corruption_context(line_number, timestamp_text, ip_addr, line_snippet, line))
		results.append(
			LineScanResult(
				line_number=line_number,
				line_snippet=line_snippet,
				timestamp_text=timestamp_text,
				parsed_timestamp=parsed_timestamp,
				ip_address=ip_addr,
				line_keys=line_keys,
				findings=findings,
			)
		)
	return results




def detect_time_gap(
	previous_timestamp: datetime,
	current_timestamp: datetime,
	line_number: int,
	timestamp_text: str | None,
	ip_addr: str | None,
) -> Iterable[Finding]:
	delta = current_timestamp - previous_timestamp
	if delta <= TIME_GAP_THRESHOLD_HIGH:
		return []

	seconds = int(delta.total_seconds())

	if delta >= TIME_GAP_THRESHOLD_CRITICAL:
		return [
			Finding(
				line_number=line_number,
				category="time_gap",
				severity="critical",
				score=9,
				timestamp=timestamp_text,
				matched_phrases=[f"gap>{int(delta.total_seconds())}sec"],
				message=f"CRITICAL time gap: {seconds} second(s) - potential malicious activity detected",
				ip_address=ip_addr,
			)
		]
	else:
		return [
			Finding(
				line_number=line_number,
				category="time_gap",
				severity="high",
				score=7,
				timestamp=timestamp_text,
				matched_phrases=[f"gap>{int(delta.total_seconds())}sec"],
				message=f"Suspicious time gap: {seconds} second(s) since previous log entry",
				ip_address=ip_addr,
			)
		]


def detect_attack_pattern(error_phrase: str, line_number: int, timestamp_text: str | None, line_snippet: str, phrase_count: int, ip_addr: str | None) -> Finding | None:
	"""Detect if an error phrase appears frequently (10+ times), flagging as potential attack."""
	if phrase_count < 10:
		return None

	return Finding(
		line_number=line_number,
		category="attack_pattern",
		severity="high",
		score=8,
		timestamp=timestamp_text,
		matched_phrases=[f"repeated_error:{error_phrase}:{phrase_count}x"],
		message=f"Potential attack detected: '{error_phrase}' repeated {phrase_count} times | {line_snippet}",
		ip_address=ip_addr,
	)


def _iter_line_batches(log_path: Path, chunk_size: int = LINE_BATCH_SIZE) -> Iterable[ScanBatch]:
	with log_path.open("r", encoding="utf-8", errors="replace") as handle:
		line_number = 1
		bytes_read = 0
		while True:
			raw_lines = list(islice(handle, chunk_size))
			if not raw_lines:
				break
			# TextIO.tell() is unreliable during iterator-based reads on some runtimes.
			# Track approximate progress using encoded size of consumed lines instead.
			bytes_read += sum(len(line.encode("utf-8", errors="replace")) for line in raw_lines)
			batch = [(line_number + offset, line.rstrip("\n")) for offset, line in enumerate(raw_lines)]
			line_number += len(batch)
			yield ScanBatch(rows=batch, bytes_read=bytes_read)


def _scan_batch(payload: ScanBatch) -> tuple[list[LineScanResult], int]:
	return _scan_line_batch(payload.rows), payload.bytes_read


def scan_log_file(
	log_path: Path,
	collect_findings: bool = True,
	finding_sink: Callable[[Finding], None] | None = None,
	workers: int | None = None,
	progress_callback: Callable[[int, int, int], None] | None = None,
) -> tuple[list[Finding], ScanSummary]:
	findings: list[Finding] = []
	severity_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
	category_counts: dict[str, int] = {"malicious": 0, "timestamp": 0, "corruption": 0, "time_gap": 0, "schema": 0, "error_log": 0, "attack_pattern": 0}
	previous_timestamp: datetime | None = None
	timestamp_seen = False
	total_lines = 0
	common_key_counts: dict[str, int] = {}
	structured_lines_seen = 0
	common_keys: list[str] = []
	common_keys_ready = False
	error_phrase_counts: dict[str, int] = {}
	error_phrase_last: dict[str, tuple[int, str | None, str | None, str]] = {}
	time_gap_critical = 0
	time_gap_high = 0
	total_bytes = log_path.stat().st_size
	worker_count = max(1, workers if workers is not None else (os.cpu_count() or 1))

	def process_result(result: LineScanResult) -> None:
		nonlocal previous_timestamp, timestamp_seen, total_lines, structured_lines_seen, common_keys_ready
		nonlocal common_keys, time_gap_critical, time_gap_high
		total_lines += 1
		line_findings: list[Finding] = list(result.findings)
		current_ts = result.parsed_timestamp
		if current_ts is None:
			if timestamp_seen:
				line_findings.append(
					Finding(
						line_number=result.line_number,
						category="timestamp",
						severity="medium",
						score=3,
						timestamp=None,
						matched_phrases=["missing_timestamp"],
						message=result.line_snippet,
						ip_address=result.ip_address,
					)
				)
		else:
			timestamp_seen = True
			if previous_timestamp is not None:
				line_findings.extend(detect_time_gap(previous_timestamp, current_ts, result.line_number, result.timestamp_text, result.ip_address))
			if ENABLE_OUT_OF_ORDER_TIMESTAMP and previous_timestamp and current_ts < previous_timestamp:
				line_findings.append(
					Finding(
						line_number=result.line_number,
						category="timestamp",
						severity="high",
						score=6,
						timestamp=result.timestamp_text,
						matched_phrases=["out_of_order_timestamp"],
						message=result.line_snippet,
						ip_address=result.ip_address,
					)
				)
			previous_timestamp = current_ts

		if result.line_keys:
			structured_lines_seen += 1
			for key in result.line_keys:
				common_key_counts[key] = common_key_counts.get(key, 0) + 1
			if not common_keys_ready and structured_lines_seen >= COMMON_KEY_MIN_LINES:
				common_keys = [
					key
					for key, count in sorted(common_key_counts.items(), key=lambda item: (-item[1], item[0]))
					if count / structured_lines_seen >= 0.6
				]
				common_keys_ready = True

		if common_keys_ready and result.line_keys:
			line_findings.extend(_detect_missing_keys_context(result.line_number, result.timestamp_text, result.ip_address, result.line_snippet, result.line_keys, common_keys))

		for finding in line_findings:
			if collect_findings:
				findings.append(finding)
			if finding_sink is not None:
				finding_sink(finding)
			severity_breakdown[finding.severity] += 1
			category_counts[finding.category] = category_counts.get(finding.category, 0) + 1
			if finding.category == "time_gap":
				if finding.severity == "critical":
					time_gap_critical += 1
				elif finding.severity == "high":
					time_gap_high += 1
			if finding.category == "error_log":
				for phrase in finding.matched_phrases:
					error_phrase_counts[phrase] = error_phrase_counts.get(phrase, 0) + 1
					error_phrase_last[phrase] = (result.line_number, result.timestamp_text, result.ip_address, result.line_snippet)

	batch_iter = _iter_line_batches(log_path)
	if worker_count > 1:
		with ProcessPoolExecutor(max_workers=worker_count) as executor:
			for batch_results, bytes_read in executor.map(_scan_batch, batch_iter, chunksize=1):
				for result in batch_results:
					process_result(result)
				if progress_callback is not None:
					progress_callback(total_lines, bytes_read, total_bytes)
	else:
		for batch in batch_iter:
			for result in _scan_line_batch(batch.rows):
				process_result(result)
			if progress_callback is not None:
				progress_callback(total_lines, batch.bytes_read, total_bytes)

	for phrase, count in error_phrase_counts.items():
		if count >= 3:
			line_number, timestamp_text, ip_addr, line_snippet = error_phrase_last[phrase]
			attack_finding = detect_attack_pattern(phrase, line_number, timestamp_text, line_snippet, count, ip_addr)
			if attack_finding:
				if collect_findings:
					findings.append(attack_finding)
				if finding_sink is not None:
					finding_sink(attack_finding)
				severity_breakdown[attack_finding.severity] += 1
				category_counts[attack_finding.category] = category_counts.get(attack_finding.category, 0) + 1

	summary = ScanSummary(
		file=str(log_path),
		total_lines=total_lines,
		malicious_findings=category_counts.get("malicious", 0),
		timestamp_findings=category_counts.get("timestamp", 0),
		corruption_findings=category_counts.get("corruption", 0),
		time_gap_findings=category_counts.get("time_gap", 0),
		time_gap_count_gt500=time_gap_critical,
		time_gap_count_300_to_500=time_gap_high,
		time_gap_count_gt300=time_gap_high + time_gap_critical,
		missing_key_findings=category_counts.get("schema", 0),
		error_log_findings=category_counts.get("error_log", 0),
		attack_pattern_findings=category_counts.get("attack_pattern", 0),
		timestamp_mode="strict" if timestamp_seen else "not_applicable",
		severity_breakdown=severity_breakdown,
	)
	return findings, summary

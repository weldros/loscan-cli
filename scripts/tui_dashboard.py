#!/usr/bin/env python3

from __future__ import annotations

import json
import locale
import math
import os
import platform
import sys
import textwrap
from dataclasses import asdict
from pathlib import Path
from typing import Any

try:
	import curses
except Exception:  # pragma: no cover - runtime fallback
	curses = None

from scanner_core import ScanSummary

try:
	locale.setlocale(locale.LC_ALL, "")
except locale.Error:
	pass

SPARK_CHARS = "▁▂▃▄▅▆▇█"
SYSTEM_LABEL = f"{platform.system()} {platform.release()} | {platform.machine()} | CPU {os.cpu_count() or '?'}"


def _load_json(path: Path) -> dict[str, Any]:
	return json.loads(path.read_text(encoding="utf-8"))


def _resolve_metrics_path(path: Path) -> Path:
	if path.name.endswith("_dashboard_metrics.json"):
		return path
	if path.suffix.lower() == ".json":
		candidate = path.with_name(f"{path.stem}_dashboard_metrics.json")
		if candidate.exists():
			return candidate
	return path


def _infer_report_path(metrics_path: Path) -> Path | None:
	if metrics_path.name.endswith("_dashboard_metrics.json"):
		base_name = metrics_path.name[: -len("_dashboard_metrics.json")]
		candidate = metrics_path.with_name(f"{base_name}.json")
		if candidate.exists():
			return candidate
	return None


def _summary_from_scan(summary: ScanSummary | None) -> dict[str, Any]:
	if summary is None:
		return {}
	data = asdict(summary)
	data["severity_breakdown"] = dict(summary.severity_breakdown)
	return data


def _summary_from_report(report: dict[str, Any] | None) -> dict[str, Any]:
	if not report:
		return {}
	report_summary = report.get("summary", {})
	return {
		"file": report.get("source_file"),
		"total_lines": report.get("total_lines", 0),
		"malicious_findings": report_summary.get("malicious_findings", 0),
		"timestamp_findings": report_summary.get("timestamp_findings", 0),
		"time_gap_findings": report_summary.get("time_gap_findings", 0),
		"time_gap_count_gt500": report_summary.get("time_gap_count_gt500", 0),
		"time_gap_count_300_to_500": report_summary.get("time_gap_count_300_to_500", 0),
		"time_gap_count_gt300": report_summary.get("time_gap_count_gt300", 0),
		"corruption_findings": report_summary.get("corruption_findings", 0),
		"missing_key_findings": report_summary.get("missing_key_findings", 0),
		"error_log_findings": report_summary.get("error_log_findings", 0),
		"attack_pattern_findings": report_summary.get("attack_pattern_findings", 0),
		"timestamp_mode": report_summary.get("timestamp_mode", "not_applicable"),
		"severity_breakdown": dict(report.get("errors_by_severity", {})),
	}


def _safe_addstr(win, y: int, x: int, text: str, attr: int = 0) -> None:
	if y < 0 or x < 0:
		return
	try:
		max_y, max_x = win.getmaxyx()
		if y >= max_y or x >= max_x:
			return
		win.addstr(y, x, text[: max(0, max_x - x - 1)], attr)
	except curses.error:
		pass


def _draw_box(win, y: int, x: int, h: int, w: int, title: str | None = None, color: int = 0) -> None:
	if h < 2 or w < 2:
		return
	for col in range(x + 1, x + w - 1):
		_safe_addstr(win, y, col, "─", color)
		_safe_addstr(win, y + h - 1, col, "─", color)
	for row in range(y + 1, y + h - 1):
		_safe_addstr(win, row, x, "│", color)
		_safe_addstr(win, row, x + w - 1, "│", color)
	_safe_addstr(win, y, x, "┌", color)
	_safe_addstr(win, y, x + w - 1, "┐", color)
	_safe_addstr(win, y + h - 1, x, "└", color)
	_safe_addstr(win, y + h - 1, x + w - 1, "┘", color)
	if title:
		_safe_addstr(win, y, x + 2, f" {title} ", color | curses.A_BOLD)


def _format_count(value: int | float) -> str:
	return f"{int(value):,}"


def _format_duration(seconds: float | int | None) -> str:
	seconds_value = max(0.0, float(seconds or 0.0))
	total_ms = int(round(seconds_value * 1000))
	whole_seconds, millis = divmod(total_ms, 1000)
	days, remainder = divmod(whole_seconds, 86400)
	hours, remainder = divmod(remainder, 3600)
	minutes, secs = divmod(remainder, 60)
	parts: list[str] = []
	if days:
		parts.append(f"{days}d")
	if hours:
		parts.append(f"{hours}h")
	if minutes:
		parts.append(f"{minutes}m")
	if secs or millis or not parts:
		parts.append(f"{secs}.{millis:03d}s")
	return " ".join(parts)


def _sparkline(values: list[float]) -> str:
	if not values:
		return ""
	minimum = min(values)
	maximum = max(values)
	if math.isclose(minimum, maximum):
		return SPARK_CHARS[-1] * len(values)
	levels = len(SPARK_CHARS) - 1
	result = []
	for value in values:
		index = int(round((value - minimum) / (maximum - minimum) * levels))
		result.append(SPARK_CHARS[max(0, min(levels, index))])
	return "".join(result)


def _draw_meter(win, y: int, x: int, width: int, ratio: float, color: int) -> None:
	width = max(1, width)
	filled = max(0, min(width, int(round(width * ratio))))
	_safe_addstr(win, y, x, "[", curses.A_DIM)
	for idx in range(width):
		char = "█" if idx < filled else "░"
		attr = color if idx < filled else curses.A_DIM
		_safe_addstr(win, y, x + 1 + idx, char, attr)
	_safe_addstr(win, y, x + width + 1, "]", curses.A_DIM)


def _render_metric_cards(
	win,
	start_y: int,
	width: int,
	summary: dict[str, Any],
	metrics: dict[str, Any],
	color_map: dict[str, int],
	cards: list[tuple[str, str, str]] | None = None,
) -> int:
	if cards is None:
		cards = [
		("Lines", _format_count(summary.get("total_lines", 0)), "scanned"),
		("Findings", _format_count(sum(summary.get("severity_breakdown", {}).values())), "all severities"),
		("Log Runtime", _format_duration(metrics.get("trend_metadata", {}).get("log_span_seconds", 0)), "log span"),
		("Availability", f"{metrics.get('trend_metadata', {}).get('availability_percent', 100.0):.2f}%", "from timeline"),
		]
	cards_per_row = max(1, len(cards))
	card_width = max(18, (width - (cards_per_row + 1)) // cards_per_row)
	height = 5
	for idx, (label, value, note) in enumerate(cards):
		row = idx // cards_per_row
		col = idx % cards_per_row
		x = 1 + col * (card_width + 1)
		y = start_y + row * (height + 1)
		if x + card_width >= width:
			break
		_draw_box(win, y, x, height, card_width, label, color_map["panel"])
		_safe_addstr(win, y + 1, x + 2, value, color_map["accent"] | curses.A_BOLD)
		_safe_addstr(win, y + 2, x + 2, note, color_map["dim"])
	row_count = (len(cards) + cards_per_row - 1) // cards_per_row
	return start_y + (row_count * (height + 1))


def _render_severity_panel(win, y: int, x: int, h: int, w: int, summary: dict[str, Any], color_map: dict[str, int]) -> None:
	_draw_box(win, y, x, h, w, "Severity Breakdown", color_map["panel"])
	breakdown = summary.get("severity_breakdown", {}) or {}
	ordered = ["critical", "high", "medium", "low"]
	counts = {severity: max(0, int(breakdown.get(severity, 0))) for severity in ordered}
	total_findings = max(1, sum(counts.values()))
	total_lines = max(1, int(summary.get("total_lines", 0)))
	for row, severity in enumerate(ordered):
		count = counts[severity]
		label = severity.upper()
		bar_width = max(8, w - 24)
		line_ratio = min(1.0, count / total_lines)
		finding_ratio = count / total_findings
		_safe_addstr(win, y + 1 + row * 2, x + 2, f"{label:<8}", color_map.get(severity, color_map["text"]))
		_draw_meter(win, y + 1 + row * 2, x + 11, bar_width, line_ratio, color_map.get(severity, color_map["text"]))
		_safe_addstr(win, y + 2 + row * 2, x + 11, f"{count} | {finding_ratio * 100.0:.1f}% findings | {line_ratio * 100.0:.2f}% lines", color_map["dim"])


def _render_gap_panel(win, y: int, x: int, h: int, w: int, summary: dict[str, Any], metrics: dict[str, Any], color_map: dict[str, int]) -> None:
	_draw_box(win, y, x, h, w, "Time-Gap Bar Graph", color_map["panel"])
	trend = metrics.get("trend_metadata", {})
	critical = int(trend.get("time_gap_count_gt500", 0))
	high = max(0, int(trend.get("time_gap_count_gt300", 0)) - critical)
	total_gaps = max(1, critical + high)
	total_lines = max(1, int(summary.get("total_lines", 0)))
	bar_width = max(10, w - 26)
	_safe_addstr(win, y + 1, x + 2, "Bar scale: % of time-gap findings", color_map["dim"])
	rows = [
		("CRITICAL >500s", critical, color_map["critical"]),
		("HIGH 300-500s", high, color_map["high"]),
	]
	for idx, (label, count, color) in enumerate(rows):
		line_y = y + 3 + idx * 3
		gap_ratio = count / total_gaps
		line_ratio = count / total_lines
		rate_per_10k = (count * 10000.0) / total_lines
		_safe_addstr(win, line_y, x + 2, f"{label:<15}", color | curses.A_BOLD)
		_draw_meter(win, line_y, x + 18, bar_width, gap_ratio, color)
		_safe_addstr(
			win,
			line_y + 1,
			x + 18,
			f"{count} findings | {gap_ratio * 100.0:.1f}% of gaps | {line_ratio * 100.0:.2f}% of lines | {rate_per_10k:.2f}/10k",
			color_map["dim"],
		)
	_safe_addstr(win, y + h - 2, x + 2, f"Total time-gap findings: {critical + high} / {total_lines} lines", color_map["accent"])


def _render_trend_panel(win, y: int, x: int, h: int, w: int, metrics: dict[str, Any], color_map: dict[str, int]) -> None:
	_draw_box(win, y, x, h, w, "Uptime Trend", color_map["panel"])
	series = metrics.get("uptime_trend", []) or []
	values = [float(point.get("uptime_percent", 0.0)) for point in series]
	if values:
		spark = _sparkline(values)
		_safe_addstr(win, y + 1, x + 2, spark, color_map["accent"] | curses.A_BOLD)
		_safe_addstr(win, y + 2, x + 2, f"min {min(values):.1f}%  max {max(values):.1f}%  last {values[-1]:.1f}%", color_map["dim"])
	else:
		_safe_addstr(win, y + 1, x + 2, "No trend data", color_map["dim"])


def _render_table_panel(win, y: int, x: int, h: int, w: int, title: str, rows: list[tuple[str, str, str]], color_map: dict[str, int]) -> None:
	_draw_box(win, y, x, h, w, title, color_map["panel"])
	if not rows:
		_safe_addstr(win, y + 1, x + 2, "No data", color_map["dim"])
		return
	for index, (left, middle, right) in enumerate(rows[: max(1, h - 2)]):
		row_y = y + 1 + index
		if row_y >= y + h - 1:
			break
		_safe_addstr(win, row_y, x + 2, textwrap.shorten(left, width=max(8, w // 3), placeholder="…"), color_map["text"] | curses.A_BOLD)
		_safe_addstr(win, row_y, x + max(12, w // 2), textwrap.shorten(middle, width=max(8, w // 3), placeholder="…"), color_map["accent"])
		if right:
			_safe_addstr(win, row_y, x + w - max(12, len(right) + 3), textwrap.shorten(right, width=max(10, w // 4), placeholder="…"), color_map["dim"])


def _get_top_malicious_ips(metrics: dict[str, Any], limit: int = 5) -> tuple[int, list[dict[str, Any]]]:
	ip_metrics = metrics.get("ip_request_metrics", []) or []
	rows = sorted(
		ip_metrics,
		key=lambda row: (
			int(row.get("malicious_request_count", 0)),
			int(row.get("total_requests", 0)),
			str(row.get("ip_address", "")),
		),
		reverse=True,
	)
	top_rows = [row for row in rows if int(row.get("malicious_request_count", 0)) > 0][:limit]
	total_hits = sum(int(row.get("malicious_request_count", 0)) for row in rows)
	return total_hits, top_rows


def _render_malicious_ip_panel(win, y: int, x: int, h: int, w: int, metrics: dict[str, Any], color_map: dict[str, int]) -> None:
	_draw_box(win, y, x, h, w, "Malicious IP Hits", color_map["panel"])
	total_hits, top_rows = _get_top_malicious_ips(metrics, limit=5)
	_safe_addstr(win, y + 1, x + 2, f"Total malicious IP hits: {_format_count(total_hits)}", color_map["accent"] | curses.A_BOLD)

	if not top_rows:
		_safe_addstr(win, y + 3, x + 2, "No malicious IP hits", color_map["dim"])
		return

	max_hits = max(1, max(int(row.get("malicious_request_count", 0)) for row in top_rows))
	hits_col_w = max(2, max(len(str(int(row.get("malicious_request_count", 0)))) for row in top_rows))
	label_w = max(12, min(24, w // 2))
	bar_x = x + 2 + label_w
	bar_w = max(6, w - label_w - hits_col_w - 8)

	for idx, row in enumerate(top_rows):
		line_y = y + 3 + idx * 2
		if line_y >= y + h - 1:
			break
		ip = str(row.get("ip_address", "unknown"))
		hits = int(row.get("malicious_request_count", 0))
		hits_text = str(hits)
		ratio = hits / max_hits
		_safe_addstr(win, line_y, x + 2, textwrap.shorten(f"{idx + 1}. {ip}", width=label_w, placeholder="..."), color_map["text"] | curses.A_BOLD)
		_draw_meter(win, line_y, bar_x, bar_w, ratio, color_map["high"])
		hits_x = min(x + w - 2 - len(hits_text), bar_x + bar_w + 3)
		_safe_addstr(win, line_y, max(bar_x + 2, hits_x), hits_text, color_map["dim"])


def _build_model(metrics_path: Path, report_path: Path | None, summary: ScanSummary | None, footer_message: str) -> dict[str, Any]:
	metrics = _load_json(metrics_path)
	report = _load_json(report_path) if report_path and report_path.exists() else None
	if summary is not None:
		summary_data = _summary_from_scan(summary)
	elif report is not None:
		summary_data = _summary_from_report(report)
	else:
		summary_data = {
			"file": metrics.get("trend_metadata", {}).get("source_file", str(metrics_path)),
			"total_lines": 0,
			"severity_breakdown": {},
		}
	if report is not None and not summary_data.get("severity_breakdown"):
		summary_data["severity_breakdown"] = dict(report.get("errors_by_severity", {}))
	return {
		"metrics": metrics,
		"summary": summary_data,
		"report": report,
		"metrics_path": metrics_path,
		"report_path": report_path,
		"footer_message": footer_message,
	}


def _render_screen(stdscr, model: dict[str, Any]) -> None:
	metrics = model["metrics"]
	summary = model["summary"]
	footer_message = model.get("footer_message", 'Report has been generated at the website. Please visit "our site url".')
	stdscr.erase()
	max_y, max_x = stdscr.getmaxyx()
	color_map = {
		"text": curses.color_pair(1),
		"dim": curses.color_pair(2),
		"critical": curses.color_pair(3),
		"high": curses.color_pair(4),
		"medium": curses.color_pair(5),
		"low": curses.color_pair(6),
		"accent": curses.color_pair(7),
		"panel": curses.color_pair(1),
	}
	_safe_addstr(stdscr, 0, 2, "Log Scanner Dashboard", color_map["accent"] | curses.A_BOLD)
	_safe_addstr(stdscr, 0, max(24, max_x // 3), f"{summary.get('file') or metrics.get('trend_metadata', {}).get('source_file', 'unknown')}", color_map["text"])
	_safe_addstr(stdscr, 0, max(2, max_x - 30), "q quit • r reload", color_map["dim"])
	_safe_addstr(
		stdscr,
		1,
		2,
		f"Lines {summary.get('total_lines', 0)} • Findings {sum(summary.get('severity_breakdown', {}).values())} • Log Runtime {_format_duration(metrics.get('trend_metadata', {}).get('log_span_seconds', 0))}",
		color_map["dim"],
	)
	_safe_addstr(
		stdscr,
		2,
		2,
		f"System {SYSTEM_LABEL} • Time Taken {_format_duration(metrics.get('trend_metadata', {}).get('runtime_seconds', 0))}",
		color_map["dim"],
	)
	if max_y < 24 or max_x < 80:
		_safe_addstr(stdscr, 5, 2, "Enlarge the terminal for the full dashboard.", color_map["dim"])
		stdscr.refresh()
		return

	current_y = 5
	left_w = max(40, (max_x - 3) // 2)
	right_w = max_x - left_w - 3
	left_x = 1
	right_x = left_x + left_w + 1
	series = metrics.get("uptime_trend", []) or []
	trend_values = [float(point.get("uptime_percent", 0.0)) for point in series]
	trend_value = _sparkline(trend_values) if trend_values else "No trend data"
	trend_note = "time trend"
	if trend_values:
		trend_note = f"min {min(trend_values):.1f}%  max {max(trend_values):.1f}%"
	top_cards = [
		("Lines", _format_count(summary.get("total_lines", 0)), "scanned"),
		("Findings", _format_count(sum(summary.get("severity_breakdown", {}).values())), "all severities"),
		("Log Runtime", _format_duration(metrics.get("trend_metadata", {}).get("log_span_seconds", 0)), "log span"),
		("Availability", f"{metrics.get('trend_metadata', {}).get('availability_percent', 100.0):.2f}%", "from timeline"),
		("Uptime Trend", trend_value, trend_note),
	]
	current_y = _render_metric_cards(stdscr, current_y, max_x - 2, summary, metrics, color_map, cards=top_cards)
	content_h = max_y - current_y - 2
	if content_h >= 12:
		left_top_h = max(8, min(12, content_h // 2 + 1))
		_render_severity_panel(stdscr, current_y, left_x, left_top_h, left_w, summary, color_map)
		_render_gap_panel(stdscr, current_y, right_x, left_top_h, right_w, summary, metrics, color_map)
		lower_y = current_y + left_top_h + 1
		lower_h = max_y - lower_y - 2
		if lower_h >= 7:
			_, top_rows = _get_top_malicious_ips(metrics, limit=5)
			malicious_h = 5 if not top_rows else (2 * len(top_rows) + 3)
			malicious_h = min(lower_h, max(5, malicious_h))
			_render_malicious_ip_panel(stdscr, lower_y, left_x, malicious_h, left_w, metrics, color_map)
	else:
		_safe_addstr(stdscr, current_y, 2, "Terminal too small for dashboard sections.", color_map["dim"])

	_safe_addstr(stdscr, max_y - 1, 2, textwrap.shorten(footer_message, width=max(10, max_x - 4), placeholder="..."), color_map["accent"] | curses.A_BOLD)

	stdscr.refresh()


def _init_colors() -> None:
	curses.start_color()
	if hasattr(curses, "use_default_colors"):
		try:
			curses.use_default_colors()
		except curses.error:
			pass
	curses.init_pair(1, curses.COLOR_WHITE, -1)
	curses.init_pair(2, curses.COLOR_CYAN, -1)
	curses.init_pair(3, curses.COLOR_RED, -1)
	curses.init_pair(4, curses.COLOR_YELLOW, -1)
	curses.init_pair(5, curses.COLOR_BLUE, -1)
	curses.init_pair(6, curses.COLOR_GREEN, -1)
	curses.init_pair(7, curses.COLOR_MAGENTA, -1)


def launch_dashboard(
	metrics_path: Path,
	report_path: Path | None = None,
	summary: ScanSummary | None = None,
	footer_message: str = 'Report has been generated at the website. Please visit "our site url".',
) -> bool:
	if curses is None:
		raise RuntimeError("curses is not available in this Python environment")
	metrics_path = _resolve_metrics_path(metrics_path)
	if report_path is None:
		report_path = _infer_report_path(metrics_path)
	model = _build_model(metrics_path, report_path, summary, footer_message)
	if not sys.stdin.isatty() or not sys.stdout.isatty():
		print("Terminal dashboard requires an interactive terminal.")
		print(f"Metrics: {metrics_path}")
		return False

	def _run(stdscr) -> None:
		try:
			curses.curs_set(0)
		except curses.error:
			pass
		stdscr.keypad(True)
		_init_colors()
		while True:
			_render_screen(stdscr, model)
			key = stdscr.getch()
			if key in (ord("q"), ord("Q")):
				break
			if key in (ord("r"), ord("R")):
				model.update(_build_model(metrics_path, report_path, summary, footer_message))
				continue

	curses.wrapper(_run)
	return True


def main() -> int:
	if len(sys.argv) < 2:
		print("Usage: python scripts/tui_dashboard.py <dashboard_metrics.json>")
		return 1
	launch_dashboard(Path(sys.argv[1]))
	return 0


if __name__ == "__main__":
	raise SystemExit(main())

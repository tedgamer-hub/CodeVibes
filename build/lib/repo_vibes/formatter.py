from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass
import json
from pathlib import Path

from .config import RepoVibesConfig, default_repo_config
from .models import FileInfo, RiskFinding, ScanReport
from .scoring import RepoScorecard, SEVERITY_ORDER

RULE_TITLES = {
    "hardcoded_secret": "Hardcoded Secrets",
    "dangerous_execution": "Dangerous Execution",
    "debug_marker": "Debug Markers",
    "large_file": "Large Files",
    "naming_chaos": "Naming Chaos",
    "generic_folder_overuse": "Generic Folder Overuse",
    "deep_nesting": "Deep Nesting",
    "oversized_code_file": "Oversized Code File",
    "root_clutter": "Root Clutter",
    "legacy_filename_pattern": "Legacy Filename Pattern",
}
SECURITY_RULE_IDS = {
    "hardcoded_secret",
    "dangerous_execution",
    "debug_marker",
    "large_file",
}
VIBE_RULE_IDS = {
    "naming_chaos",
    "generic_folder_overuse",
    "deep_nesting",
    "oversized_code_file",
    "root_clutter",
    "legacy_filename_pattern",
}
RISKY_PATTERN_RULE_IDS = {"hardcoded_secret", "dangerous_execution", "debug_marker"}


@dataclass(slots=True)
class SuspiciousBucket:
    reasons: set[str]
    score: int


def format_report(
    scan_report: ScanReport,
    scorecard: RepoScorecard,
    *,
    max_findings: int = 50,
    config: RepoVibesConfig | None = None,
    roast_mode: bool = False,
) -> str:
    runtime_config = config if config is not None else default_repo_config()
    findings = scorecard.all_findings
    extension_counts = _extension_counts(scan_report.files)
    total_size_bytes = sum(file.size_bytes for file in scan_report.files)

    lines: list[str] = []
    lines.append("=== Project Overview ===")
    lines.append(f"Project: {scan_report.project_name}")
    lines.append(f"Path: {scan_report.root_path}")
    lines.append(f"Duration: {scan_report.duration_ms} ms")
    lines.append(f"Scanned files: {scan_report.file_count}")
    lines.append(f"Total lines: {scan_report.total_lines}")
    lines.append(f"Max depth: {scan_report.max_depth}")
    lines.append(f"Total size: {_format_bytes(total_size_bytes)}")
    lines.append("")

    lines.append("=== Core Scores ===")
    lines.append(f"Complexity Score: {scorecard.complexity_score}/100")
    lines.append(f"Structure Score: {scorecard.structure_score}/100")
    lines.append(f"Naming Chaos Index: {scorecard.naming_chaos_index}/100")
    lines.append(f"Risk Score: {scorecard.risk_score}/100 ({scorecard.risk_level})")
    lines.append(f"Vibe Score: {scorecard.vibe_score}/100")
    lines.append(f"Total findings: {scorecard.total_findings}")
    for severity in SEVERITY_ORDER:
        lines.append(f"{severity.title()} findings: {scorecard.severity_counts.get(severity, 0)}")
    lines.append("")

    lines.append("=== Overall Verdict ===")
    lines.append(_render_verdict(scorecard, roast_mode))
    lines.append("")

    lines.append("=== Top Suspicious Files ===")
    suspicious = _top_suspicious_files(
        scan_report,
        findings,
        config=runtime_config,
        top_n=5,
    )
    if suspicious:
        for path, reasons in suspicious:
            reason_text = ", ".join(reasons)
            lines.append(f"- {path} | {reason_text}")
    else:
        lines.append("No strongly suspicious files detected.")
    lines.append("")

    lines.append("=== Naming / Structure Notes ===")
    lines.append(
        f"Naming chaos signals: {scorecard.naming_stats.suspicious_name_count} suspicious paths, "
        f"{scorecard.naming_stats.filename_keyword_hits} filename keyword hits, "
        f"{scorecard.naming_stats.generic_file_name_hits} generic file names, "
        f"{scorecard.naming_stats.numeric_suffix_hits} numeric suffix names."
    )
    lines.append(
        f"Structure pressure: {scorecard.structure_stats.deep_path_count} deep paths (>=4), "
        f"{scorecard.structure_stats.generic_folder_hits} generic-folder hits, "
        f"{scorecard.structure_stats.root_file_count} root-level files."
    )
    if scan_report.suspicious_names:
        lines.append("Examples:")
        for item in scan_report.suspicious_names[:5]:
            lines.append(f"- {item}")
        if len(scan_report.suspicious_names) > 5:
            lines.append(f"... and {len(scan_report.suspicious_names) - 5} more paths with naming concerns.")
    else:
        lines.append("No suspicious naming paths were detected in this scan.")
    lines.append("")

    lines.append("=== Top File Types ===")
    if extension_counts:
        for ext, count in extension_counts:
            lines.append(f"{ext}: {count}")
    else:
        lines.append("No files found.")
    lines.append("")

    lines.append("=== Top Long Files ===")
    if scan_report.largest_files:
        for item in scan_report.largest_files:
            lines.append(f"{item.line_count:>6} lines  {_format_bytes(item.size_bytes):>10}  {item.path}")
    else:
        lines.append("No files found.")
    lines.append("")

    lines.append("=== Complexity Offenders ===")
    if scorecard.complexity_stats.top_offenders:
        for item in scorecard.complexity_stats.top_offenders:
            lines.append(f"- {item.line_count} lines | {item.path}")
    else:
        lines.append("No files above 300 lines.")
    lines.append("")

    lines.append("=== Security Findings ===")
    if not findings:
        lines.append("No risk signals detected.")
        return "\n".join(lines)

    shown_findings = findings[:max_findings]
    security_findings = [f for f in shown_findings if f.rule_id in SECURITY_RULE_IDS]
    vibe_findings = [f for f in shown_findings if f.rule_id in VIBE_RULE_IDS]

    _append_grouped_findings(lines, security_findings)
    lines.append("")
    lines.append("=== CodeVibes Findings ===")
    _append_grouped_findings(lines, vibe_findings)

    if len(findings) > max_findings:
        lines.append(
            f"... Truncated details: showing first {max_findings} of {len(findings)} findings."
        )

    return "\n".join(lines).rstrip()


def format_markdown_report(
    scan_report: ScanReport,
    scorecard: RepoScorecard,
    *,
    max_findings: int = 50,
    config: RepoVibesConfig | None = None,
    roast_mode: bool = False,
) -> str:
    runtime_config = config if config is not None else default_repo_config()
    findings = scorecard.all_findings[:max_findings]
    extension_counts = _extension_counts(scan_report.files)
    total_size_bytes = sum(file.size_bytes for file in scan_report.files)
    suspicious = _top_suspicious_files(
        scan_report,
        scorecard.all_findings,
        config=runtime_config,
        top_n=5,
    )
    security_findings = [f for f in findings if f.rule_id in SECURITY_RULE_IDS]
    vibe_findings = [f for f in findings if f.rule_id in VIBE_RULE_IDS]

    lines: list[str] = []
    lines.append("# CodeVibes Report")
    lines.append("")
    lines.append("## Project Overview")
    lines.append(f"- Project: `{scan_report.project_name}`")
    lines.append(f"- Path: `{scan_report.root_path}`")
    lines.append(f"- Duration: `{scan_report.duration_ms} ms`")
    lines.append(f"- Scanned files: `{scan_report.file_count}`")
    lines.append(f"- Total lines: `{scan_report.total_lines}`")
    lines.append(f"- Max depth: `{scan_report.max_depth}`")
    lines.append(f"- Total size: `{_format_bytes(total_size_bytes)}`")
    lines.append("")
    lines.append("## Core Scores")
    lines.append(f"- Complexity Score: `{scorecard.complexity_score}/100`")
    lines.append(f"- Structure Score: `{scorecard.structure_score}/100`")
    lines.append(f"- Naming Chaos Index: `{scorecard.naming_chaos_index}/100`")
    lines.append(f"- Risk Score: `{scorecard.risk_score}/100 ({scorecard.risk_level})`")
    lines.append(f"- Vibe Score: `{scorecard.vibe_score}/100`")
    lines.append("")
    lines.append("## Overall Verdict")
    lines.append(_render_verdict(scorecard, roast_mode))
    lines.append("")
    lines.append("## Top Suspicious Files")
    if suspicious:
        for path, reasons in suspicious:
            lines.append(f"- `{path}` - {', '.join(reasons)}")
    else:
        lines.append("- No strongly suspicious files detected.")
    lines.append("")
    lines.append("## Naming / Structure Notes")
    lines.append(
        f"- Naming chaos signals: {scorecard.naming_stats.suspicious_name_count} suspicious paths, "
        f"{scorecard.naming_stats.filename_keyword_hits} filename keyword hits, "
        f"{scorecard.naming_stats.generic_file_name_hits} generic file names, "
        f"{scorecard.naming_stats.numeric_suffix_hits} numeric suffix names."
    )
    lines.append(
        f"- Structure pressure: {scorecard.structure_stats.deep_path_count} deep paths (>=4), "
        f"{scorecard.structure_stats.generic_folder_hits} generic-folder hits, "
        f"{scorecard.structure_stats.root_file_count} root-level files."
    )
    lines.append("")
    lines.append("## Top File Types")
    if extension_counts:
        for ext, count in extension_counts:
            lines.append(f"- `{ext}`: {count}")
    else:
        lines.append("- No files found.")
    lines.append("")
    lines.append("## Top Long Files")
    if scan_report.largest_files:
        for item in scan_report.largest_files:
            lines.append(
                f"- `{item.path}` - {item.line_count} lines, {_format_bytes(item.size_bytes)}"
            )
    else:
        lines.append("- No files found.")
    lines.append("")
    lines.append("## Risk Details")
    lines.append("### Security Findings")
    _append_grouped_findings_md(lines, security_findings)
    lines.append("")
    lines.append("### CodeVibes Findings")
    _append_grouped_findings_md(lines, vibe_findings)
    if len(scorecard.all_findings) > max_findings:
        lines.append("")
        lines.append(
            f"> Truncated details: showing first {max_findings} of {len(scorecard.all_findings)} findings."
        )
    return "\n".join(lines).rstrip()


def format_json_report(
    scan_report: ScanReport,
    scorecard: RepoScorecard,
    *,
    max_findings: int = 50,
    config: RepoVibesConfig | None = None,
    roast_mode: bool = False,
) -> str:
    runtime_config = config if config is not None else default_repo_config()
    findings = scorecard.all_findings[:max_findings]
    payload = {
        "scan_report": asdict(scan_report),
        "scorecard": asdict(scorecard),
        "top_suspicious_files": _top_suspicious_files(
            scan_report,
            scorecard.all_findings,
            config=runtime_config,
            top_n=5,
        ),
        "security_findings": [asdict(f) for f in findings if f.rule_id in SECURITY_RULE_IDS],
        "vibe_findings": [asdict(f) for f in findings if f.rule_id in VIBE_RULE_IDS],
        "verdict": _render_verdict(scorecard, roast_mode),
        "roast_mode": roast_mode,
        "max_findings": max_findings,
        "truncated": len(scorecard.all_findings) > max_findings,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _render_verdict(scorecard: RepoScorecard, roast_mode: bool) -> str:
    if not roast_mode:
        return scorecard.overall_verdict
    return _roast_verdict(scorecard)


def _roast_verdict(scorecard: RepoScorecard) -> str:
    if scorecard.vibe_score >= 80 and scorecard.risk_score < 30:
        return "This repo is annoyingly healthy. Someone here still believes in standards."
    if scorecard.risk_score >= 70:
        return "Security vibes are chaotic. This repo is one bad deploy away from a postmortem."
    if scorecard.naming_chaos_index >= 60 and scorecard.structure_score >= 70:
        return "The folders look disciplined, but the filenames are pure emotional damage."
    if scorecard.complexity_score < 45:
        return "A few giant files are carrying this repo like unpaid overtime."
    if scorecard.structure_score < 50:
        return "The code might work, but navigating this structure feels like side quests."
    return "Still manageable, but entropy has moved in and started rearranging furniture."


def _group_by_rule(findings: list[RiskFinding]) -> dict[str, list[RiskFinding]]:
    grouped: dict[str, list[RiskFinding]] = defaultdict(list)
    for finding in findings:
        grouped[finding.rule_id].append(finding)
    return dict(grouped)


def _append_grouped_findings(lines: list[str], findings: list[RiskFinding]) -> None:
    if not findings:
        lines.append("No findings.")
        return
    grouped = _group_by_rule(findings)
    for rule_id, group in grouped.items():
        title = RULE_TITLES.get(rule_id, rule_id)
        lines.append(f"[{title}] ({len(group)} shown)")
        for finding in group:
            if finding.line_no is None:
                location = finding.file_path
            else:
                location = f"{finding.file_path}:{finding.line_no}"
            lines.append(f"- ({finding.severity}) {location} | {finding.snippet}")
        lines.append("")


def _append_grouped_findings_md(lines: list[str], findings: list[RiskFinding]) -> None:
    if not findings:
        lines.append("- No findings.")
        return
    grouped = _group_by_rule(findings)
    for rule_id, group in grouped.items():
        title = RULE_TITLES.get(rule_id, rule_id)
        lines.append(f"- **{title}** ({len(group)} shown)")
        for finding in group:
            if finding.line_no is None:
                location = finding.file_path
            else:
                location = f"{finding.file_path}:{finding.line_no}"
            lines.append(f"  - ({finding.severity}) `{location}` | {finding.snippet}")


def _top_suspicious_files(
    scan_report: ScanReport,
    findings: list[RiskFinding],
    *,
    config: RepoVibesConfig,
    top_n: int,
) -> list[tuple[str, list[str]]]:
    by_path: dict[str, SuspiciousBucket] = {}
    file_map = {file.path: file for file in scan_report.files}

    for file in scan_report.files:
        reasons = _heuristic_reasons(file, scan_report.root_path, config)
        score = len(reasons) * 2
        by_path[file.path] = SuspiciousBucket(reasons=set(reasons), score=score)

    for finding in findings:
        if finding.file_path not in by_path:
            continue
        reason = _reason_from_rule(finding.rule_id)
        if reason:
            by_path[finding.file_path].reasons.add(reason)
            by_path[finding.file_path].score += _severity_weight(finding.severity)
        if finding.rule_id == "oversized_code_file":
            file = file_map.get(finding.file_path)
            if file:
                by_path[finding.file_path].score += max(1, file.line_count // 200)

    ranked = sorted(
        (
            (path, data)
            for path, data in by_path.items()
            if data.reasons
        ),
        key=lambda item: item[1].score,
        reverse=True,
    )[:top_n]

    result: list[tuple[str, list[str]]] = []
    for path, data in ranked:
        reasons = sorted(data.reasons)
        result.append((path, reasons))
    return result


def _heuristic_reasons(
    file: FileInfo,
    root_path: str,
    config: RepoVibesConfig,
) -> list[str]:
    reasons: list[str] = []
    stem = Path(file.name).stem.lower()
    segments = _relative_segments(file.path, root_path)

    if file.line_count >= config.oversized_file_line_thresholds["medium"]:
        reasons.append("too large")
    if file.depth >= 4:
        reasons.append("too deeply nested")
    if any(keyword in stem for keyword in config.suspicious_name_keywords):
        reasons.append("vague naming")
    if any(folder in config.generic_folder_names for folder in segments[:-1]):
        reasons.append("generic directory")
    return reasons


def _reason_from_rule(rule_id: str) -> str | None:
    if rule_id in RISKY_PATTERN_RULE_IDS:
        return "contains risky patterns"
    if rule_id == "oversized_code_file":
        return "too large"
    if rule_id == "deep_nesting":
        return "too deeply nested"
    if rule_id in {"naming_chaos", "legacy_filename_pattern"}:
        return "vague naming"
    if rule_id in {"generic_folder_overuse", "root_clutter"}:
        return "generic directory"
    return None


def _severity_weight(severity: str) -> int:
    if severity == "critical":
        return 6
    if severity == "high":
        return 4
    if severity == "medium":
        return 3
    return 1


def _relative_segments(file_path: str, root_path: str) -> list[str]:
    try:
        rel = Path(file_path).resolve().relative_to(Path(root_path).resolve())
    except (ValueError, OSError):
        rel = Path(file_path)
    return [segment.lower() for segment in rel.parts]


def _extension_counts(files: list[FileInfo], top_n: int = 8) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for file in files:
        counts[file.extension] = counts.get(file.extension, 0) + 1
    return sorted(counts.items(), key=lambda item: item[1], reverse=True)[:top_n]


def _format_bytes(num_bytes: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(num_bytes)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{num_bytes} B"

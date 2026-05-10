from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

from .models import FileInfo, RiskFinding, ScanReport
from .rules import OVERSIZED_FILE_LINE_THRESHOLDS

SEVERITY_ORDER = ["critical", "high", "medium", "low"]
SEVERITY_WEIGHTS = {
    "critical": 40,
    "high": 20,
    "medium": 8,
    "low": 2,
}

NAMING_RISK_KEYWORDS = {
    "final",
    "temp",
    "copy",
    "backup",
    "new",
    "old",
}
GENERIC_FILE_BASE_NAMES = {"utils", "helpers", "common"}
HISTORY_WORDS = {"final", "copy", "backup", "old", "new", "test2", "temp", "draft"}
HISTORY_SUFFIX_PATTERN = re.compile(r"(?:[_-]?v?\d+$|\d+$)")
NUMERIC_SUFFIX_PATTERN = re.compile(r"\d+$")

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


@dataclass(slots=True)
class RiskScorecard:
    findings: list[RiskFinding]
    severity_counts: dict[str, int]
    total_findings: int
    risk_score: int
    risk_level: str


@dataclass(slots=True)
class NamingChaosStats:
    suspicious_name_count: int
    filename_keyword_hits: int
    generic_file_name_hits: int
    numeric_suffix_hits: int


@dataclass(slots=True)
class StructureStats:
    max_depth: int
    deep_path_count: int
    generic_folder_hits: int
    root_file_count: int


@dataclass(slots=True)
class ComplexityStats:
    over_300_count: int
    over_500_count: int
    over_800_count: int
    top_offenders: list[FileInfo]
    large_file_pressure: int


@dataclass(slots=True)
class RepoScorecard:
    risk_score: int
    risk_level: str
    naming_chaos_index: int
    structure_score: int
    complexity_score: int
    vibe_score: int
    overall_verdict: str
    security_findings: list[RiskFinding]
    vibe_findings: list[RiskFinding]
    all_findings: list[RiskFinding]
    severity_counts: dict[str, int]
    total_findings: int
    naming_stats: NamingChaosStats
    structure_stats: StructureStats
    complexity_stats: ComplexityStats


def score_findings(findings: list[RiskFinding]) -> RiskScorecard:
    adjusted = [
        RiskFinding(
            rule_id=f.rule_id,
            severity=f.severity,
            file_path=f.file_path,
            line_no=f.line_no,
            snippet=f.snippet,
        )
        for f in findings
    ]
    _promote_debug_severity(adjusted)
    return _risk_scorecard_from_findings(adjusted)


def score_repo_vibes(
    scan_report: ScanReport,
    *,
    line_thresholds: dict[str, int] | None = None,
) -> RepoScorecard:
    thresholds = line_thresholds if line_thresholds is not None else OVERSIZED_FILE_LINE_THRESHOLDS
    security_findings = [f for f in scan_report.findings if f.rule_id in SECURITY_RULE_IDS]
    risk_card = score_findings(security_findings)

    naming_stats = _naming_chaos_stats(scan_report)
    naming_chaos_index = _naming_chaos_index(naming_stats, scan_report.file_count)
    structure_stats = _structure_stats(scan_report)
    structure_score = _structure_score(structure_stats)
    complexity_stats = _complexity_stats(scan_report, thresholds)
    complexity_score = max(0, 100 - complexity_stats.large_file_pressure)
    vibe_score = _vibe_score(naming_chaos_index, structure_score, complexity_score)

    vibe_findings = _build_vibe_findings(
        scan_report=scan_report,
        naming_chaos_index=naming_chaos_index,
        structure_stats=structure_stats,
        complexity_stats=complexity_stats,
        line_thresholds=thresholds,
    )
    all_findings = risk_card.findings + vibe_findings
    merged_risk = _risk_scorecard_from_findings(all_findings)
    overall_verdict = _stylized_verdict(
        naming_chaos_index=naming_chaos_index,
        structure_score=structure_score,
        complexity_score=complexity_score,
        risk_score=risk_card.risk_score,
        vibe_score=vibe_score,
    )

    return RepoScorecard(
        risk_score=risk_card.risk_score,
        risk_level=risk_card.risk_level,
        naming_chaos_index=naming_chaos_index,
        structure_score=structure_score,
        complexity_score=complexity_score,
        vibe_score=vibe_score,
        overall_verdict=overall_verdict,
        security_findings=risk_card.findings,
        vibe_findings=vibe_findings,
        all_findings=all_findings,
        severity_counts=merged_risk.severity_counts,
        total_findings=merged_risk.total_findings,
        naming_stats=naming_stats,
        structure_stats=structure_stats,
        complexity_stats=complexity_stats,
    )


def _risk_scorecard_from_findings(findings: list[RiskFinding]) -> RiskScorecard:
    severity_counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        if finding.severity in severity_counts:
            severity_counts[finding.severity] += 1

    total = sum(severity_counts.values())
    weighted_score = sum(
        severity_counts[severity] * SEVERITY_WEIGHTS[severity] for severity in SEVERITY_ORDER
    )
    risk_score = min(100, weighted_score)
    risk_level = _risk_level_from_score(risk_score)

    return RiskScorecard(
        findings=findings,
        severity_counts=severity_counts,
        total_findings=total,
        risk_score=risk_score,
        risk_level=risk_level,
    )


def _promote_debug_severity(findings: list[RiskFinding]) -> None:
    debug_indexes: list[int] = []
    debug_hits_per_file: dict[str, int] = {}
    for idx, finding in enumerate(findings):
        if finding.rule_id != "debug_marker":
            continue
        debug_indexes.append(idx)
        debug_hits_per_file[finding.file_path] = debug_hits_per_file.get(finding.file_path, 0) + 1

    global_debug_count = sum(debug_hits_per_file.values())
    should_promote_globally = global_debug_count >= 20
    files_reaching_threshold = {path for path, count in debug_hits_per_file.items() if count >= 5}

    for idx in debug_indexes:
        finding = findings[idx]
        if should_promote_globally or finding.file_path in files_reaching_threshold:
            finding.severity = "medium"


def _risk_level_from_score(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def _relative_segments(file_path: str, root_path: str) -> list[str]:
    try:
        rel = Path(file_path).resolve().relative_to(Path(root_path).resolve())
    except (ValueError, OSError):
        rel = Path(file_path)
    return [segment.lower() for segment in rel.parts]


def _naming_chaos_stats(scan_report: ScanReport) -> NamingChaosStats:
    suspicious_name_count = len(scan_report.suspicious_names)
    filename_keyword_hits = 0
    generic_file_name_hits = 0
    numeric_suffix_hits = 0

    for file in scan_report.files:
        stem = Path(file.name).stem.lower()

        if any(keyword in stem for keyword in NAMING_RISK_KEYWORDS):
            filename_keyword_hits += 1

        if stem in GENERIC_FILE_BASE_NAMES:
            generic_file_name_hits += 1

        if NUMERIC_SUFFIX_PATTERN.search(stem):
            numeric_suffix_hits += 1

    return NamingChaosStats(
        suspicious_name_count=suspicious_name_count,
        filename_keyword_hits=filename_keyword_hits,
        generic_file_name_hits=generic_file_name_hits,
        numeric_suffix_hits=numeric_suffix_hits,
    )


def _naming_chaos_index(stats: NamingChaosStats, file_count: int) -> int:
    base = max(1, file_count)
    suspicious_ratio = min(1.0, stats.suspicious_name_count / max(1, base * 0.4))
    keyword_ratio = min(1.0, stats.filename_keyword_hits / max(1, base * 0.35))
    generic_ratio = min(1.0, stats.generic_file_name_hits / max(1, base * 0.2))
    numeric_ratio = min(1.0, stats.numeric_suffix_hits / max(1, base * 0.25))
    score = (
        suspicious_ratio * 0.35
        + keyword_ratio * 0.30
        + generic_ratio * 0.20
        + numeric_ratio * 0.15
    ) * 100
    return int(round(score))


def _structure_stats(scan_report: ScanReport) -> StructureStats:
    max_depth = scan_report.max_depth
    deep_path_count = scan_report.deep_path_count
    root_file_count = scan_report.root_file_count
    generic_folder_hits = sum(scan_report.generic_folder_counts.values())

    return StructureStats(
        max_depth=max_depth,
        deep_path_count=deep_path_count,
        generic_folder_hits=generic_folder_hits,
        root_file_count=root_file_count,
    )


def _structure_score(stats: StructureStats) -> int:
    # Higher is better. Start at 100 and subtract structure penalties.
    score = 100

    max_depth_penalty = max(0, stats.max_depth - 3) * 5
    deep_path_penalty = min(35, stats.deep_path_count * 4)
    generic_folder_penalty = min(30, stats.generic_folder_hits * 3)
    root_clutter_penalty = max(0, stats.root_file_count - 12) * 2

    score -= max_depth_penalty
    score -= deep_path_penalty
    score -= generic_folder_penalty
    score -= root_clutter_penalty
    return max(0, score)


def _complexity_stats(scan_report: ScanReport, line_thresholds: dict[str, int]) -> ComplexityStats:
    over_300 = list(scan_report.oversized_files)
    over_500 = [
        file
        for file in scan_report.files
        if file.line_count >= line_thresholds["high"]
    ]
    over_800 = [
        file
        for file in scan_report.files
        if file.line_count >= line_thresholds["critical"]
    ]
    top_offenders = sorted(over_300, key=lambda item: item.line_count, reverse=True)[:5]
    pressure = min(100, len(over_300) * 8 + len(over_500) * 12 + len(over_800) * 18)

    return ComplexityStats(
        over_300_count=len(over_300),
        over_500_count=len(over_500),
        over_800_count=len(over_800),
        top_offenders=top_offenders,
        large_file_pressure=pressure,
    )


def _vibe_score(naming_chaos_index: int, structure_score: int, complexity_score: int) -> int:
    return int(round(0.35 * (100 - naming_chaos_index) + 0.35 * structure_score + 0.30 * complexity_score))


def _build_vibe_findings(
    *,
    scan_report: ScanReport,
    naming_chaos_index: int,
    structure_stats: StructureStats,
    complexity_stats: ComplexityStats,
    line_thresholds: dict[str, int],
) -> list[RiskFinding]:
    findings: list[RiskFinding] = []

    if naming_chaos_index >= 25:
        findings.append(
            RiskFinding(
                rule_id="naming_chaos",
                severity="medium" if naming_chaos_index >= 60 else "low",
                file_path=".",
                line_no=None,
                snippet=f"Naming Chaos Index reached {naming_chaos_index}/100.",
            )
        )

    if structure_stats.generic_folder_hits > 0:
        findings.append(
            RiskFinding(
                rule_id="generic_folder_overuse",
                severity="medium" if structure_stats.generic_folder_hits >= 4 else "low",
                file_path=".",
                line_no=None,
                snippet=f"Detected {structure_stats.generic_folder_hits} generic folder hits.",
            )
        )

    if structure_stats.deep_path_count > 0:
        findings.append(
            RiskFinding(
                rule_id="deep_nesting",
                severity="medium" if structure_stats.deep_path_count >= 5 else "low",
                file_path=".",
                line_no=None,
                snippet=f"{structure_stats.deep_path_count} files are nested at depth >= 4.",
            )
        )

    for offender in complexity_stats.top_offenders:
        findings.append(
            RiskFinding(
                rule_id="oversized_code_file",
                severity="high" if offender.line_count >= line_thresholds["critical"] else "medium",
                file_path=offender.path,
                line_no=None,
                snippet=f"{offender.line_count} lines in a single file.",
            )
        )

    if structure_stats.root_file_count > 12:
        findings.append(
            RiskFinding(
                rule_id="root_clutter",
                severity="medium",
                file_path=".",
                line_no=None,
                snippet=f"Root contains {structure_stats.root_file_count} files.",
            )
        )

    legacy_count = sum(
        1
        for file in scan_report.files
        if _is_legacy_filename_pattern(Path(file.name).stem.lower())
    )
    if legacy_count > 0:
        findings.append(
            RiskFinding(
                rule_id="legacy_filename_pattern",
                severity="medium" if legacy_count >= 5 else "low",
                file_path=".",
                line_no=None,
                snippet=f"{legacy_count} files show legacy filename patterns.",
            )
        )

    return findings


def _is_legacy_filename_pattern(stem: str) -> bool:
    has_history_word = any(word in stem for word in HISTORY_WORDS)
    has_numeric_suffix = bool(HISTORY_SUFFIX_PATTERN.search(stem))
    return has_history_word or has_numeric_suffix


def _stylized_verdict(
    *,
    naming_chaos_index: int,
    structure_score: int,
    complexity_score: int,
    risk_score: int,
    vibe_score: int,
) -> str:
    # Convert multiple scores into one intuitive repo-health impression.
    health_score = int(
        round(
            0.30 * structure_score
            + 0.30 * complexity_score
            + 0.20 * (100 - naming_chaos_index)
            + 0.20 * (100 - risk_score)
        )
    )

    if health_score >= 80:
        headline = "Overall healthy and maintainable."
    elif health_score >= 60:
        headline = "Overall workable, but drift has started."
    elif health_score >= 40:
        headline = "Overall fragile, maintenance cost is rising."
    else:
        headline = "Overall unstable, this repo needs active cleanup."

    notes: list[str] = []
    if naming_chaos_index >= 60:
        notes.append("Naming is chaotic.")
    elif naming_chaos_index >= 40:
        notes.append("Naming discipline is slipping.")

    if structure_score < 45:
        notes.append("Structure is hard to navigate.")
    elif structure_score < 65:
        notes.append("Structure needs tightening.")

    if complexity_score < 45:
        notes.append("Too many oversized files are carrying core logic.")
    elif complexity_score < 65:
        notes.append("Complexity is accumulating in large files.")

    if risk_score >= 60:
        notes.append("Security risk signals need urgent attention.")
    elif risk_score >= 35:
        notes.append("Security risk signals should be reviewed soon.")

    if not notes:
        notes.append("No major hotspot dominates yet; small cleanup now prevents big pain later.")

    return f"{headline} {' '.join(notes)}"

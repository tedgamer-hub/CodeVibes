from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any


def snapshot_from_scorecard(*, label: str, report: Any, scorecard: Any) -> dict[str, Any]:
    return {
        "label": label,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_report": asdict(report),
        "scorecard": asdict(scorecard),
    }


def build_diff_payload(
    *,
    base: dict[str, Any],
    head: dict[str, Any],
    changed_files: list[str],
    max_findings: int = 50,
) -> dict[str, Any]:
    base_score = _as_dict(base.get("scorecard"))
    head_score = _as_dict(head.get("scorecard"))
    base_report = _as_dict(base.get("scan_report"))
    head_report = _as_dict(head.get("scan_report"))

    base_findings = _coerce_findings(base_score.get("all_findings"))
    head_findings = _coerce_findings(head_score.get("all_findings"))

    base_set = {_finding_key(item) for item in base_findings}
    head_set = {_finding_key(item) for item in head_findings}

    new_findings = [item for item in head_findings if _finding_key(item) not in base_set]
    removed_findings = [item for item in base_findings if _finding_key(item) not in head_set]

    base_risk = _as_int(base_score.get("risk_score"))
    head_risk = _as_int(head_score.get("risk_score"))
    base_total = _as_int(base_score.get("total_findings"))
    head_total = _as_int(head_score.get("total_findings"))

    risk_regression = max(0, head_risk - base_risk)
    findings_regression = max(0, head_total - base_total)
    new_high_findings = sum(
        1 for item in new_findings if str(item.get("severity", "")).lower() in {"high", "critical"}
    )

    degradation_sources: list[str] = []
    if risk_regression > 0:
        degradation_sources.append(f"Risk score increased by {risk_regression}.")
    if findings_regression > 0:
        degradation_sources.append(f"Total findings increased by {findings_regression}.")
    if new_high_findings > 0:
        degradation_sources.append(f"{new_high_findings} new high/critical findings detected.")

    base_suspicious = set(_as_list(base_report.get("suspicious_names")))
    head_suspicious = set(_as_list(head_report.get("suspicious_names")))
    added_suspicious = sorted(head_suspicious - base_suspicious)
    if added_suspicious:
        degradation_sources.append(
            "New suspicious filenames: " + ", ".join(added_suspicious[:3]) + ("..." if len(added_suspicious) > 3 else "")
        )

    fix_suggestions = _build_fix_suggestions(new_findings)
    if not fix_suggestions and degradation_sources:
        fix_suggestions.append("Address regression drivers first, then re-run scan.")

    return {
        "changed_files": changed_files,
        "changed_file_count": len(changed_files),
        "base_label": str(base.get("label", "base")),
        "head_label": str(head.get("label", "head")),
        "base_risk_score": base_risk,
        "head_risk_score": head_risk,
        "new_findings_total": len(new_findings),
        "removed_findings_total": len(removed_findings),
        "new_findings": new_findings[:max_findings],
        "removed_findings": removed_findings[:max_findings],
        "ci_signals": {
            "risk_regression": risk_regression,
            "new_high_findings": new_high_findings,
            "finding_regression": findings_regression,
        },
        "degradation_sources": degradation_sources,
        "fix_suggestions": fix_suggestions,
    }


def format_diff_report(payload: dict[str, Any]) -> str:
    ci = _as_dict(payload.get("ci_signals"))
    lines: list[str] = []
    lines.append("=== Diff Overview ===")
    lines.append(f"Changed files: {payload.get('changed_file_count', 0)}")
    lines.append(f"New findings: {payload.get('new_findings_total', 0)}")
    lines.append(f"Removed findings: {payload.get('removed_findings_total', 0)}")
    lines.append("")
    lines.append("=== CI Signals ===")
    lines.append(f"Risk regression: {ci.get('risk_regression', 0)}")
    lines.append(f"New high findings: {ci.get('new_high_findings', 0)}")
    lines.append(f"Finding regression: {ci.get('finding_regression', 0)}")

    degradation = _as_list(payload.get("degradation_sources"))
    if degradation:
        lines.append("")
        lines.append("=== Degradation Sources ===")
        for item in degradation:
            lines.append(f"- {item}")

    suggestions = _as_list(payload.get("fix_suggestions"))
    lines.append("")
    lines.append("=== Suggested Fix Order ===")
    if suggestions:
        for idx, item in enumerate(suggestions, start=1):
            lines.append(f"{idx}. {item}")
    else:
        lines.append("1. No urgent fixes suggested.")
    return "\n".join(lines)


def _build_fix_suggestions(findings: list[dict[str, Any]]) -> list[str]:
    if not findings:
        return []

    ordered = sorted(
        findings,
        key=lambda item: (_severity_rank(str(item.get("severity", ""))), str(item.get("file_path", ""))),
    )
    suggestions: list[str] = []
    for item in ordered[:5]:
        severity = str(item.get("severity", "low")).lower()
        path = str(item.get("file_path", "."))
        rule = str(item.get("rule_id", "finding"))
        if severity in {"critical", "high"}:
            suggestions.append(f"Fix {severity} issue `{rule}` in `{path}` first.")
        else:
            suggestions.append(f"Triage `{rule}` in `{path}`.")
    return suggestions


def _severity_rank(severity: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return order.get(severity.lower(), 4)


def _finding_key(item: dict[str, Any]) -> tuple[str, str, str, int | None, str]:
    line_no_value = item.get("line_no")
    line_no = line_no_value if isinstance(line_no_value, int) else None
    return (
        str(item.get("rule_id", "")),
        str(item.get("severity", "")),
        str(item.get("file_path", "")),
        line_no,
        str(item.get("snippet", "")),
    )


def _coerce_findings(value: Any) -> list[dict[str, Any]]:
    items = _as_list(value)
    normalized: list[dict[str, Any]] = []
    for item in items:
        if isinstance(item, dict):
            normalized.append(item)
    return normalized


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

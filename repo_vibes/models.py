from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class FileInfo:
    path: str
    name: str
    extension: str
    line_count: int
    depth: int
    size_bytes: int
    is_binary: bool = False


@dataclass(slots=True)
class RiskFinding:
    rule_id: str
    severity: str
    file_path: str
    line_no: int | None
    snippet: str


@dataclass(slots=True)
class ScanReport:
    project_name: str
    root_path: str
    file_count: int
    total_lines: int
    max_depth: int
    generic_folder_counts: dict[str, int]
    deep_path_count: int
    root_file_count: int
    files: list[FileInfo]
    largest_files: list[FileInfo]
    oversized_files: list[FileInfo]
    suspicious_names: list[str]
    findings: list[RiskFinding]
    duration_ms: int

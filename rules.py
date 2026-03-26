from __future__ import annotations

from pathlib import Path
import re
from typing import Iterable

EXCLUDED_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    ".release_check_venv",
    ".release_check_venv2",
    ".release_install_check",
    ".release_install_target",
    "dist",
    "build",
    "__pycache__",
    "reports",
    ".codevibes_tmp",
    ".repo_vibes_tmp",
}

INCLUDED_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".json",
    ".md",
    ".yaml",
    ".yml",
    ".toml",
}

GENERIC_FOLDER_NAMES = {
    "utils",
    "helper",
    "helpers",
    "common",
    "misc",
    "shared",
    "temp",
}

OVERSIZED_FILE_LINE_THRESHOLDS = {
    "medium": 300,
    "high": 500,
    "critical": 800,
}

SUSPICIOUS_NAME_KEYWORDS = {
    "temp",
    "final",
    "test",
    "test2",
    "new",
    "old",
    "backup",
    "copy",
    "misc",
    "helper",
    "utils",
    "common",
    "draft",
    "secret",
    "password",
    "passwd",
    "token",
    "key",
    "private",
    "bak",
    "tmp",
}

LARGE_FILE_THRESHOLD_BYTES = 5 * 1024 * 1024

SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"xoxb-[A-Za-z0-9-]+"),
    re.compile(r"password\s*=", re.IGNORECASE),
    re.compile(r"secret\s*=", re.IGNORECASE),
    re.compile(r"api[_-]?key", re.IGNORECASE),
]
DEBUG_PATTERN = re.compile(r"\b(TODO|FIXME|HACK|XXX)\b")
DANGEROUS_PATTERNS = [
    re.compile(r"\beval\s*\("),
    re.compile(r"\bexec\s*\("),
    re.compile(r"subprocess\.[A-Za-z_][A-Za-z0-9_]*\s*\(.*shell\s*=\s*True"),
]


def matches_any(line: str, patterns: Iterable[re.Pattern[str]]) -> bool:
    return any(pattern.search(line) for pattern in patterns)


def path_has_suspicious_name(
    relative_path: Path,
    keywords: set[str] | None = None,
) -> bool:
    active_keywords = keywords if keywords is not None else SUSPICIOUS_NAME_KEYWORDS
    segments = [segment.lower() for segment in relative_path.parts]
    return any(
        keyword in segment
        for segment in segments
        for keyword in active_keywords
    )


from __future__ import annotations

from dataclasses import dataclass
import fnmatch
from pathlib import Path
import os
import time

from .config import RepoVibesConfig, default_repo_config
from .models import FileInfo, RiskFinding, ScanReport
from .rules import (
    DANGEROUS_PATTERNS,
    DEBUG_PATTERN,
    LARGE_FILE_THRESHOLD_BYTES,
    SECRET_PATTERNS,
    matches_any,
    path_has_suspicious_name,
)

DEEP_PATH_THRESHOLD = 4


def scan_project(
    project_path: str | Path,
    *,
    top_largest_files: int = 5,
    config: RepoVibesConfig | None = None,
) -> ScanReport:
    start = time.perf_counter()
    root = Path(project_path).resolve()
    root_display_path = _display_path(root)
    runtime_config = config if config is not None else default_repo_config()
    active_extensions = runtime_config.effective_included_extensions
    gitignore_rules = _load_gitignore_rules(root, runtime_config)
    files: list[FileInfo] = []
    findings: list[RiskFinding] = []
    suspicious_name_paths: set[str] = set()
    generic_folder_counts: dict[str, int] = {}
    total_lines = 0
    max_depth = 0
    deep_path_count = 0
    root_file_count = 0
    oversized_files: list[FileInfo] = []

    for current_root, dirnames, filenames in os.walk(root, topdown=True):
        current_root_path = Path(current_root)
        next_dirnames: list[str] = []
        for dirname in dirnames:
            if dirname.lower() in runtime_config.excluded_dirs:
                continue
            relative_dir = (current_root_path / dirname).relative_to(root)
            if runtime_config.exclude_globs and _matches_any_glob(
                relative_dir.as_posix(),
                dirname,
                runtime_config.exclude_globs,
            ):
                continue
            if _is_ignored_by_gitignore(relative_dir, gitignore_rules, is_dir=True):
                continue
            next_dirnames.append(dirname)
        dirnames[:] = next_dirnames

        for filename in filenames:
            file_path = current_root_path / filename
            extension = file_path.suffix.lower()
            if extension not in active_extensions:
                continue

            try:
                file_size = file_path.stat().st_size
            except OSError:
                continue

            relative_path = file_path.relative_to(root)
            relative_path_str = str(relative_path)
            if not _should_include_path(relative_path, runtime_config, gitignore_rules):
                continue
            depth = len(relative_path.parts) - 1
            max_depth = max(max_depth, depth)
            if depth == 0:
                root_file_count += 1
            if depth >= DEEP_PATH_THRESHOLD:
                deep_path_count += 1
            for part in relative_path.parts[:-1]:
                key = part.lower()
                if key in runtime_config.generic_folder_names:
                    generic_folder_counts[key] = generic_folder_counts.get(key, 0) + 1

            if file_size > LARGE_FILE_THRESHOLD_BYTES:
                findings.append(
                    RiskFinding(
                        rule_id="large_file",
                        severity="low",
                        file_path=relative_path_str,
                        line_no=None,
                        snippet=f"File size {file_size} bytes exceeds 5 MB threshold.",
                    )
                )

            is_binary = False
            line_count = 0
            content = _read_text_content(file_path)
            if content is None:
                is_binary = True
                content = ""

            if content:
                line_count = _count_lines(content)
                total_lines += line_count
                _scan_text_findings(
                    file_path_display=relative_path_str,
                    content=content,
                    findings=findings,
                )

            file_info = FileInfo(
                path=relative_path_str,
                name=file_path.name,
                extension=extension,
                line_count=line_count,
                depth=depth,
                size_bytes=file_size,
                is_binary=is_binary,
            )
            files.append(file_info)
            if line_count >= runtime_config.oversized_file_line_thresholds["medium"]:
                oversized_files.append(file_info)

            if _path_has_suspicious_name(relative_path, runtime_config.suspicious_name_keywords):
                suspicious_name_paths.add(relative_path_str)

    largest_files = _top_n_largest_files(files, top_largest_files)
    oversized_files.sort(key=lambda info: info.line_count, reverse=True)
    duration_ms = int((time.perf_counter() - start) * 1000)

    return ScanReport(
        project_name=root.name,
        root_path=root_display_path,
        file_count=len(files),
        total_lines=total_lines,
        max_depth=max_depth,
        generic_folder_counts=generic_folder_counts,
        deep_path_count=deep_path_count,
        root_file_count=root_file_count,
        files=files,
        largest_files=largest_files,
        oversized_files=oversized_files,
        suspicious_names=sorted(suspicious_name_paths),
        findings=findings,
        duration_ms=duration_ms,
    )


def _scan_text_findings(
    *,
    file_path_display: str,
    content: str,
    findings: list[RiskFinding],
) -> None:
    for line_no, line in enumerate(content.splitlines(), start=1):
        snippet = _clip_snippet(line.strip())
        if not snippet:
            continue

        if matches_any(line, SECRET_PATTERNS):
            findings.append(
                RiskFinding(
                    rule_id="hardcoded_secret",
                    severity="critical",
                    file_path=file_path_display,
                    line_no=line_no,
                    snippet=snippet,
                )
            )

        if matches_any(line, DANGEROUS_PATTERNS):
            findings.append(
                RiskFinding(
                    rule_id="dangerous_execution",
                    severity="high",
                    file_path=file_path_display,
                    line_no=line_no,
                    snippet=snippet,
                )
            )

        if DEBUG_PATTERN.search(line):
            findings.append(
                RiskFinding(
                    rule_id="debug_marker",
                    severity="low",
                    file_path=file_path_display,
                    line_no=line_no,
                    snippet=snippet,
                )
            )


def _top_n_largest_files(files: list[FileInfo], top_n: int) -> list[FileInfo]:
    return sorted(
        files,
        key=lambda info: (info.line_count, info.size_bytes),
        reverse=True,
    )[:top_n]


def _read_text_content(file_path: Path) -> str | None:
    try:
        sample = _read_sample(file_path)
    except OSError:
        try:
            return file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return ""

    if _looks_binary(sample):
        return None

    try:
        return file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        try:
            return file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return ""
    except OSError:
        return ""


def _count_lines(content: str) -> int:
    line_count = content.count("\n")
    if content and not content.endswith("\n"):
        line_count += 1
    return line_count


def _read_sample(file_path: Path, size: int = 4096) -> bytes:
    with file_path.open("rb") as f:
        return f.read(size)


def _looks_binary(sample: bytes) -> bool:
    if not sample:
        return False
    if b"\x00" in sample:
        return True

    # UTF-8 text (including CJK content) should be treated as textual source.
    try:
        sample.decode("utf-8")
        return False
    except UnicodeDecodeError:
        pass

    # Fallback heuristic: many control bytes usually indicate binary payloads.
    control_count = 0
    for byte in sample:
        if byte in (9, 10, 13):  # tab/newline/carriage return
            continue
        if byte < 32 or byte == 127:
            control_count += 1
    return (control_count / len(sample)) > 0.10


def _clip_snippet(text: str, max_len: int = 120) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _display_path(path: Path) -> str:
    cwd = Path.cwd().resolve()
    try:
        rel = path.relative_to(cwd)
        return "." if not rel.parts else str(rel)
    except ValueError:
        pass

    try:
        rel_text = os.path.relpath(path, cwd)
        return rel_text
    except ValueError:
        return str(path)


def _should_include_path(
    relative_path: Path,
    config: RepoVibesConfig,
    gitignore_rules: list["_GitignoreRule"],
) -> bool:
    normalized = relative_path.as_posix()
    filename = relative_path.name

    if config.include_globs and not _matches_any_glob(normalized, filename, config.include_globs):
        return False
    if config.exclude_globs and _matches_any_glob(normalized, filename, config.exclude_globs):
        return False
    if _is_ignored_by_gitignore(relative_path, gitignore_rules, is_dir=False):
        return False
    return True


def _matches_any_glob(path_text: str, file_name: str, patterns: list[str]) -> bool:
    for pattern in patterns:
        if pattern.endswith("/"):
            prefix = pattern.rstrip("/")
            if path_text == prefix or path_text.startswith(f"{prefix}/"):
                return True
            continue

        if fnmatch.fnmatch(path_text, pattern):
            return True
        if "/" not in pattern and fnmatch.fnmatch(file_name, pattern):
            return True
    return False


@dataclass(slots=True)
class _GitignoreRule:
    pattern: str
    negate: bool
    directory_only: bool
    anchored: bool
    has_slash: bool


def _load_gitignore_rules(root: Path, config: RepoVibesConfig) -> list[_GitignoreRule]:
    if not config.respect_gitignore:
        return []

    gitignore_path = root / ".gitignore"
    try:
        if not gitignore_path.exists():
            return []
        raw_lines = gitignore_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []

    rules: list[_GitignoreRule] = []
    for raw_line in raw_lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("\\#") or line.startswith("\\!"):
            line = line[1:]

        negate = line.startswith("!")
        if negate:
            line = line[1:].strip()
            if not line:
                continue

        anchored = line.startswith("/")
        if anchored:
            line = line[1:]

        directory_only = line.endswith("/")
        if directory_only:
            line = line[:-1]

        normalized = line.replace("\\", "/").strip()
        if not normalized:
            continue

        rules.append(
            _GitignoreRule(
                pattern=normalized,
                negate=negate,
                directory_only=directory_only,
                anchored=anchored,
                has_slash="/" in normalized,
            )
        )
    return rules


def _is_ignored_by_gitignore(
    relative_path: Path,
    rules: list[_GitignoreRule],
    *,
    is_dir: bool,
) -> bool:
    if not rules:
        return False

    path_text = relative_path.as_posix()
    path_parts = relative_path.parts
    ignored = False
    for rule in rules:
        if _matches_gitignore_rule(path_text, path_parts, rule, is_dir=is_dir):
            ignored = not rule.negate
    return ignored


def _matches_gitignore_rule(
    path_text: str,
    path_parts: tuple[str, ...],
    rule: _GitignoreRule,
    *,
    is_dir: bool,
) -> bool:
    if rule.directory_only:
        if rule.anchored:
            return path_text == rule.pattern or path_text.startswith(f"{rule.pattern}/")
        if rule.has_slash:
            return path_text == rule.pattern or path_text.startswith(f"{rule.pattern}/")
        return rule.pattern in path_parts

    if rule.anchored:
        return fnmatch.fnmatch(path_text, rule.pattern)

    if rule.has_slash:
        if fnmatch.fnmatch(path_text, rule.pattern):
            return True
        return fnmatch.fnmatch(path_text, f"**/{rule.pattern}")

    file_name = path_parts[-1] if path_parts else path_text
    if fnmatch.fnmatch(file_name, rule.pattern):
        return True
    if is_dir and fnmatch.fnmatch(path_text, rule.pattern):
        return True
    return False


def _path_has_suspicious_name(relative_path: Path, keywords: set[str]) -> bool:
    try:
        return path_has_suspicious_name(relative_path, keywords)
    except TypeError as exc:
        # Backward compatibility for older rules.py where the helper
        # accepted only `relative_path`.
        message = str(exc)
        if "positional argument" in message and "2 were given" in message:
            return path_has_suspicious_name(relative_path)
        raise

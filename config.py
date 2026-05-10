from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

from .rules import (
    EXCLUDED_DIRS,
    GENERIC_FOLDER_NAMES,
    INCLUDED_EXTENSIONS,
    OVERSIZED_FILE_LINE_THRESHOLDS,
    SUSPICIOUS_NAME_KEYWORDS,
)

CONFIG_FILENAME = ".codevibes.json"
LEGACY_CONFIG_FILENAME = ".repo-vibes.json"


@dataclass(slots=True)
class RepoVibesConfig:
    included_extensions: set[str]
    excluded_extensions: set[str]
    excluded_dirs: set[str]
    include_globs: list[str]
    exclude_globs: list[str]
    respect_gitignore: bool
    generic_folder_names: set[str]
    suspicious_name_keywords: set[str]
    oversized_file_line_thresholds: dict[str, int]
    max_findings_default: int

    @property
    def effective_included_extensions(self) -> set[str]:
        return self.included_extensions - self.excluded_extensions


def default_repo_config() -> RepoVibesConfig:
    return RepoVibesConfig(
        included_extensions=set(INCLUDED_EXTENSIONS),
        excluded_extensions=set(),
        excluded_dirs=set(EXCLUDED_DIRS),
        include_globs=[],
        exclude_globs=[],
        respect_gitignore=True,
        generic_folder_names=set(GENERIC_FOLDER_NAMES),
        suspicious_name_keywords=set(SUSPICIOUS_NAME_KEYWORDS),
        oversized_file_line_thresholds=dict(OVERSIZED_FILE_LINE_THRESHOLDS),
        max_findings_default=50,
    )


def load_repo_config(project_root: str | Path) -> tuple[RepoVibesConfig, list[str]]:
    config = default_repo_config()
    warnings: list[str] = []
    root = Path(project_root).resolve()
    config_path = root / CONFIG_FILENAME
    legacy_config_path = root / LEGACY_CONFIG_FILENAME
    if not config_path.exists() and legacy_config_path.exists():
        config_path = legacy_config_path
        warnings.append(f"using legacy config filename {LEGACY_CONFIG_FILENAME}; prefer {CONFIG_FILENAME}.")

    if not config_path.exists():
        return config, warnings

    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except OSError as exc:
        warnings.append(f"failed to read {CONFIG_FILENAME}: {exc}")
        return config, warnings
    except json.JSONDecodeError as exc:
        warnings.append(f"failed to parse {CONFIG_FILENAME}: {exc}")
        return config, warnings

    if not isinstance(raw, dict):
        warnings.append(f"{CONFIG_FILENAME} must be a JSON object.")
        return config, warnings

    included_extensions = _read_extension_set(raw, "included_extensions", warnings)
    if included_extensions is not None:
        config.included_extensions = included_extensions

    excluded_extensions = _read_extension_set(raw, "excluded_extensions", warnings)
    if excluded_extensions is not None:
        config.excluded_extensions = excluded_extensions

    excluded_dirs = _read_lower_set(raw, "excluded_dirs", warnings)
    if excluded_dirs is not None:
        config.excluded_dirs = excluded_dirs

    include_globs = _read_pattern_list(raw, "include_globs", warnings)
    if include_globs is not None:
        config.include_globs = include_globs

    exclude_globs = _read_pattern_list(raw, "exclude_globs", warnings)
    if exclude_globs is not None:
        config.exclude_globs = exclude_globs

    respect_gitignore = _read_bool(raw, "respect_gitignore", warnings)
    if respect_gitignore is not None:
        config.respect_gitignore = respect_gitignore

    generic_folder_names = _read_lower_set(raw, "generic_folder_names", warnings)
    if generic_folder_names is not None:
        config.generic_folder_names = generic_folder_names

    suspicious_name_keywords = _read_lower_set(raw, "suspicious_name_keywords", warnings)
    if suspicious_name_keywords is not None:
        config.suspicious_name_keywords = suspicious_name_keywords

    thresholds = _read_line_thresholds(raw, warnings)
    if thresholds is not None:
        config.oversized_file_line_thresholds = thresholds

    max_findings_default = raw.get("max_findings_default")
    if max_findings_default is not None:
        if isinstance(max_findings_default, int) and max_findings_default > 0:
            config.max_findings_default = max_findings_default
        else:
            warnings.append("max_findings_default must be a positive integer.")

    return config, warnings


def _read_extension_set(
    payload: dict[str, object],
    key: str,
    warnings: list[str],
) -> set[str] | None:
    raw = payload.get(key)
    if raw is None:
        return None
    if not isinstance(raw, list):
        warnings.append(f"{key} must be a list of extensions.")
        return None

    result: set[str] = set()
    for item in raw:
        if not isinstance(item, str):
            warnings.append(f"{key} contains a non-string value; it was ignored.")
            continue
        ext = item.strip().lower()
        if not ext:
            continue
        if not ext.startswith("."):
            ext = f".{ext}"
        result.add(ext)
    return result


def _read_lower_set(
    payload: dict[str, object],
    key: str,
    warnings: list[str],
) -> set[str] | None:
    raw = payload.get(key)
    if raw is None:
        return None
    if not isinstance(raw, list):
        warnings.append(f"{key} must be a list of strings.")
        return None

    result: set[str] = set()
    for item in raw:
        if not isinstance(item, str):
            warnings.append(f"{key} contains a non-string value; it was ignored.")
            continue
        value = item.strip().lower()
        if value:
            result.add(value)
    return result


def _read_line_thresholds(
    payload: dict[str, object],
    warnings: list[str],
) -> dict[str, int] | None:
    raw = payload.get("line_thresholds")
    if raw is None:
        raw = payload.get("oversized_file_line_thresholds")
    if raw is None:
        return None
    if not isinstance(raw, dict):
        warnings.append("line_thresholds must be an object with medium/high/critical integers.")
        return None

    result: dict[str, int] = dict(OVERSIZED_FILE_LINE_THRESHOLDS)
    for key in ("medium", "high", "critical"):
        value = raw.get(key)
        if value is None:
            continue
        if isinstance(value, int) and value > 0:
            result[key] = value
        else:
            warnings.append(f"line_thresholds.{key} must be a positive integer.")

    if not (result["medium"] <= result["high"] <= result["critical"]):
        warnings.append("line_thresholds must satisfy medium <= high <= critical.")
        return None

    return result


def _read_pattern_list(
    payload: dict[str, object],
    key: str,
    warnings: list[str],
) -> list[str] | None:
    raw = payload.get(key)
    if raw is None:
        return None
    if not isinstance(raw, list):
        warnings.append(f"{key} must be a list of glob patterns.")
        return None

    result: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            warnings.append(f"{key} contains a non-string value; it was ignored.")
            continue
        value = item.strip().replace("\\", "/")
        if value:
            result.append(value)
    return result


def _read_bool(
    payload: dict[str, object],
    key: str,
    warnings: list[str],
) -> bool | None:
    raw = payload.get(key)
    if raw is None:
        return None
    if isinstance(raw, bool):
        return raw
    warnings.append(f"{key} must be true or false.")
    return None

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from urllib.parse import urlparse
import uuid
import webbrowser

from . import __version__
from .config import RepoVibesConfig, load_repo_config
from .diffing import build_diff_payload, format_diff_report, snapshot_from_scorecard
from .formatter import format_json_report, format_markdown_report, format_report
from .scoring import score_repo_vibes
from .scanner import scan_project


def main(argv: list[str] | None = None) -> int:
    raw_args = argv if argv is not None else sys.argv[1:]
    commands = {"scan", "diff", "ui"}
    if raw_args and raw_args[0] not in commands and not raw_args[0].startswith("-"):
        # Backward-compatible shortcut: `python main.py <path>`
        raw_args = ["scan", raw_args[0], *raw_args[1:]]

    parser = _build_parser()
    try:
        ns = parser.parse_args(raw_args)
    except SystemExit as exc:
        return _normalize_system_exit_code(exc.code)

    if ns.command == "scan":
        return _run_scan_command(ns)
    if ns.command == "diff":
        return _run_diff_command(ns)
    if ns.command == "ui":
        return _run_ui_command(ns)

    parser.print_help()
    return 1


def _normalize_system_exit_code(code: object) -> int:
    if code is None:
        return 0
    if isinstance(code, int):
        return code
    if isinstance(code, str):
        try:
            return int(code)
        except ValueError:
            return 1
    return 1


def _run_scan_command(ns: argparse.Namespace) -> int:
    if ns.fail_on_risk is not None and not (0 <= ns.fail_on_risk <= 100):
        print("Error: --fail-on-risk must be between 0 and 100.")
        return 1
    if ns.fail_on_findings is not None and ns.fail_on_findings < 0:
        print("Error: --fail-on-findings must be >= 0.")
        return 1
    if ns.submit_timeout <= 0:
        print("Error: --submit-timeout must be > 0.")
        return 1
    if ns.clone_timeout <= 0:
        print("Error: --clone-timeout must be > 0.")
        return 1

    with _prepare_scan_path(ns.path, clone_timeout=ns.clone_timeout) as project_path:
        if project_path is None:
            return 1

        try:
            config, warnings = load_repo_config(project_path)
            for warning in warnings:
                print(f"Warning: {warning}")

            report = scan_project(
                project_path,
                top_largest_files=ns.top_files,
                config=config,
            )
            scorecard = score_repo_vibes(
                report,
                line_thresholds=config.oversized_file_line_thresholds,
            )
            max_findings = ns.max_findings
            if max_findings is None:
                max_findings = config.max_findings_default
        except PermissionError as exc:
            print(f"Error: permission denied while scanning: {exc}")
            return 1
        except OSError as exc:
            print(f"Error: failed to scan project: {exc}")
            return 1

        output = _render_output(
            report,
            scorecard,
            output_format=ns.format,
            max_findings=max_findings,
            config=config,
            roast_mode=ns.roast,
        )

        submit_failed = False
        if ns.submit_webhook:
            submit_payload = _call_formatter(
                format_json_report,
                report,
                scorecard,
                max_findings=max_findings,
                config=config,
                roast_mode=ns.roast,
            )
            submit_payload = _with_submission_metadata(
                submit_payload,
                project_path=project_path,
            )
            submit_failed = not _submit_report(
                ns.submit_webhook,
                submit_payload,
                timeout_seconds=ns.submit_timeout,
            )

        if ns.output:
            output_path = Path(ns.output).expanduser()
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(output, encoding="utf-8")
            print(f"Saved report to: {output_path}")
        else:
            print(output)

        if submit_failed:
            return 3

        policy_errors: list[str] = []
        if ns.fail_on_risk is not None and scorecard.risk_score >= ns.fail_on_risk:
            policy_errors.append(
                f"risk score {scorecard.risk_score} >= fail-on-risk {ns.fail_on_risk}"
            )
        if ns.fail_on_findings is not None and scorecard.total_findings >= ns.fail_on_findings:
            policy_errors.append(
                f"findings {scorecard.total_findings} >= fail-on-findings {ns.fail_on_findings}"
            )
        if policy_errors:
            print(f"Policy failed: {'; '.join(policy_errors)}.", file=sys.stderr)
            return 2
        return 0


def _run_diff_command(ns: argparse.Namespace) -> int:
    if ns.clone_timeout <= 0:
        print("Error: --clone-timeout must be > 0.")
        return 1
    if ns.fail_on_new_high is not None and ns.fail_on_new_high < 0:
        print("Error: --fail-on-new-high must be >= 0.")
        return 1

    with _prepare_scan_path(ns.path, clone_timeout=ns.clone_timeout) as project_path:
        if project_path is None:
            return 1
        try:
            config, _warnings = load_repo_config(project_path)
            max_findings = ns.max_findings
            if max_findings is None:
                max_findings = config.max_findings_default

            if ns.baseline:
                baseline_snapshot = _load_baseline_snapshot(ns.baseline)
                head_snapshot = _scan_snapshot(
                    project_path=project_path,
                    top_files=ns.top_files,
                    config=config,
                    label="head",
                )
                changed_files = _changed_files_from_snapshots(
                    baseline_snapshot.get("scan_report", {}),
                    head_snapshot.get("scan_report", {}),
                )
            else:
                baseline_snapshot, head_snapshot, changed_files = _load_ref_snapshots(
                    project_path=project_path,
                    base_ref=ns.base,
                    head_ref=ns.head,
                    top_files=ns.top_files,
                    config=config,
                )

            payload = build_diff_payload(
                base=baseline_snapshot,
                head=head_snapshot,
                changed_files=changed_files,
                max_findings=max_findings,
            )
        except OSError as exc:
            print(f"Error: failed to build diff: {exc}")
            return 1
        except ValueError as exc:
            print(f"Error: {exc}")
            return 1

    output = _render_diff_output(payload, output_format=ns.format)
    if ns.output:
        output_path = Path(ns.output).expanduser()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output, encoding="utf-8")
        print(f"Saved report to: {output_path}")
    else:
        print(output)

    policy_errors: list[str] = []
    ci_signals = payload.get("ci_signals", {})
    new_high = int(ci_signals.get("new_high_findings", 0))
    if ns.fail_on_new_high is not None and new_high > ns.fail_on_new_high:
        policy_errors.append(
            f"new high findings {new_high} > fail-on-new-high {ns.fail_on_new_high}"
        )
    if policy_errors:
        print(f"Policy failed: {'; '.join(policy_errors)}.", file=sys.stderr)
        return 2
    return 0


def _run_ui_command(ns: argparse.Namespace) -> int:
    next_ui_dir = _locate_next_ui_dir()
    if next_ui_dir is None:
        print("Error: Next.js UI directory not found. Expected: ./ui with package.json")
        return 1

    try:
        return _run_next_ui(
            ui_dir=next_ui_dir,
            host=ns.host,
            port=ns.port,
            no_browser=ns.no_browser,
            skip_install=ns.skip_install,
        )
    except OSError as exc:
        print(f"Error: failed to launch Next.js UI: {exc}")
        return 1


def _render_output(
    report,
    scorecard,
    *,
    output_format: str,
    max_findings: int,
    config: RepoVibesConfig,
    roast_mode: bool,
) -> str:
    if output_format == "text":
        return _call_formatter(
            format_report,
            report,
            scorecard,
            max_findings=max_findings,
            config=config,
            roast_mode=roast_mode,
        )
    if output_format == "markdown":
        return _call_formatter(
            format_markdown_report,
            report,
            scorecard,
            max_findings=max_findings,
            config=config,
            roast_mode=roast_mode,
        )
    if output_format == "json":
        return _call_formatter(
            format_json_report,
            report,
            scorecard,
            max_findings=max_findings,
            config=config,
            roast_mode=roast_mode,
        )
    raise ValueError(f"Unsupported format: {output_format}")


def _render_diff_output(payload: dict[str, object], *, output_format: str) -> str:
    if output_format == "json":
        return json.dumps(payload, ensure_ascii=False, indent=2)
    if output_format == "text":
        return format_diff_report(payload)
    raise ValueError(f"Unsupported format: {output_format}")


def _call_formatter(
    formatter,
    report,
    scorecard,
    *,
    max_findings: int,
    config: RepoVibesConfig,
    roast_mode: bool,
) -> str:
    try:
        return formatter(
            report,
            scorecard,
            max_findings=max_findings,
            config=config,
            roast_mode=roast_mode,
        )
    except TypeError as exc:
        # Backward compatibility for older formatter versions without `config`.
        message = str(exc)
        if "unexpected keyword argument 'config'" in message:
            try:
                return formatter(
                    report,
                    scorecard,
                    max_findings=max_findings,
                    roast_mode=roast_mode,
                )
            except TypeError as nested_exc:
                nested_message = str(nested_exc)
                if "unexpected keyword argument 'roast_mode'" in nested_message:
                    return formatter(report, scorecard, max_findings=max_findings)
                raise
        if "unexpected keyword argument 'roast_mode'" in message:
            return formatter(
                report,
                scorecard,
                max_findings=max_findings,
                config=config,
            )
        raise


def _scan_snapshot(
    *,
    project_path: Path,
    top_files: int,
    config: RepoVibesConfig,
    label: str,
) -> dict[str, object]:
    report = scan_project(
        project_path,
        top_largest_files=top_files,
        config=config,
    )
    scorecard = score_repo_vibes(
        report,
        line_thresholds=config.oversized_file_line_thresholds,
    )
    return snapshot_from_scorecard(
        label=label,
        report=report,
        scorecard=scorecard,
    )


def _load_ref_snapshots(
    *,
    project_path: Path,
    base_ref: str,
    head_ref: str,
    top_files: int,
    config: RepoVibesConfig,
) -> tuple[dict[str, object], dict[str, object], list[str]]:
    _verify_git_ref_exists(project_path, base_ref)
    _verify_git_ref_exists(project_path, head_ref)
    changed_files = _list_changed_files_between_refs(
        project_path=project_path,
        base_ref=base_ref,
        head_ref=head_ref,
    )
    changed_set = set(changed_files)
    base_snapshot = _snapshot_from_ref_files(
        project_path=project_path,
        ref=base_ref,
        changed_files=changed_set,
        top_files=top_files,
        config=config,
        label=base_ref,
    )
    head_snapshot = _snapshot_from_ref_files(
        project_path=project_path,
        ref=head_ref,
        changed_files=changed_set,
        top_files=top_files,
        config=config,
        label=head_ref,
    )
    return base_snapshot, head_snapshot, changed_files


def _verify_git_ref_exists(project_path: Path, ref: str) -> None:
    result = subprocess.run(
        ["git", "-C", str(project_path), "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ValueError(f"git ref does not exist or is not a commit: {ref}")


def _list_changed_files_between_refs(
    *,
    project_path: Path,
    base_ref: str,
    head_ref: str,
) -> list[str]:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(project_path),
            "diff",
            "--name-only",
            "--diff-filter=ACMRD",
            base_ref,
            head_ref,
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown git diff error"
        raise ValueError(f"failed to compute git diff for refs `{base_ref}` -> `{head_ref}`: {detail}")
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _snapshot_from_ref_files(
    *,
    project_path: Path,
    ref: str,
    changed_files: set[str],
    top_files: int,
    config: RepoVibesConfig,
    label: str,
) -> dict[str, object]:
    workspace_temp = Path.cwd() / ".codevibes_tmp"
    workspace_temp.mkdir(parents=True, exist_ok=True)
    temp_dir = _create_workspace_temp_dir(
        base_dir=workspace_temp,
        prefix="codevibes-ref-",
    )
    try:
        for raw_path in sorted(changed_files):
            normalized = raw_path.replace("\\", "/")
            rel_path = Path(normalized)
            if rel_path.is_absolute() or any(part in {"", ".", ".."} for part in rel_path.parts):
                raise ValueError(f"unexpected changed path from git diff: {raw_path}")
            file_bytes = _load_file_from_ref(
                project_path=project_path,
                ref=ref,
                relative_path=normalized,
            )
            if file_bytes is None:
                continue
            target_path = temp_dir / rel_path
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_bytes(file_bytes)

        return _scan_snapshot(
            project_path=temp_dir,
            top_files=top_files,
            config=config,
            label=label,
        )
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def _load_file_from_ref(
    *,
    project_path: Path,
    ref: str,
    relative_path: str,
) -> bytes | None:
    result = subprocess.run(
        ["git", "-C", str(project_path), "show", f"{ref}:{relative_path}"],
        capture_output=True,
    )
    if result.returncode == 0:
        return result.stdout

    stderr_text = result.stderr.decode("utf-8", errors="replace").lower()
    if "does not exist in" in stderr_text or "exists on disk, but not in" in stderr_text:
        return None
    detail = result.stderr.decode("utf-8", errors="replace").strip() or "unknown git show error"
    raise ValueError(f"failed to load `{relative_path}` at ref `{ref}`: {detail}")


def _load_baseline_snapshot(baseline_path: str) -> dict[str, object]:
    path = Path(baseline_path).expanduser()
    if not path.exists():
        raise ValueError(f"baseline file does not exist: {path}")
    raw = path.read_text(encoding="utf-8")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid baseline JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise ValueError("baseline JSON must be an object.")
    scan_report = payload.get("scan_report")
    scorecard = payload.get("scorecard")
    if not isinstance(scan_report, dict) or not isinstance(scorecard, dict):
        raise ValueError("baseline JSON must include `scan_report` and `scorecard`.")
    return {
        "label": "baseline",
        "scan_report": scan_report,
        "scorecard": scorecard,
    }


def _changed_files_from_snapshots(base_report: object, head_report: object) -> list[str]:
    base_paths = _extract_file_paths(base_report)
    head_paths = _extract_file_paths(head_report)
    changed = sorted(base_paths.symmetric_difference(head_paths))
    if changed:
        return changed
    # If the set is unchanged, provide all current files to keep the summary useful.
    return sorted(head_paths)


def _extract_file_paths(report: object) -> set[str]:
    if not isinstance(report, dict):
        return set()
    files = report.get("files")
    if not isinstance(files, list):
        return set()
    paths: set[str] = set()
    for item in files:
        if isinstance(item, dict):
            path_value = item.get("path")
            if isinstance(path_value, str) and path_value:
                paths.add(path_value)
    return paths


def _locate_next_ui_dir() -> Path | None:
    candidate = Path(__file__).resolve().parents[1] / "ui"
    if not candidate.exists():
        return None
    if not (candidate / "package.json").exists():
        return None
    return candidate


def _run_next_ui(
    *,
    ui_dir: Path,
    host: str,
    port: int,
    no_browser: bool,
    skip_install: bool,
) -> int:
    npm_bin = _resolve_npm_executable()
    node_modules_dir = ui_dir / "node_modules"
    if not node_modules_dir.exists():
        if skip_install:
            raise OSError("ui/node_modules is missing. Run `npm install` or remove `--skip-install`.")
        print("ui/node_modules is missing; running `npm install`...")
        install_result = subprocess.run([npm_bin, "install"], cwd=ui_dir)
        if install_result.returncode != 0:
            raise OSError(f"`npm install` failed with exit code {install_result.returncode}.")

    url = f"http://{host}:{port}"
    print(f"CodeVibes Next UI listening on {url}")
    print("Press Ctrl+C to stop.")
    if not no_browser:
        webbrowser.open(url)

    try:
        return int(
            subprocess.run(
                [
                    npm_bin,
                    "run",
                    "dev",
                    "--",
                    "--hostname",
                    host,
                    "--port",
                    str(port),
                ],
                cwd=ui_dir,
            ).returncode
        )
    except KeyboardInterrupt:
        print("\nShutting down CodeVibes Next UI...")
        return 0


def _resolve_npm_executable() -> str:
    candidates = ["npm.cmd", "npm"] if os.name == "nt" else ["npm"]
    for candidate in candidates:
        if shutil.which(candidate):
            return candidate
    raise OSError("npm is not installed or not available in PATH.")


def _create_workspace_temp_dir(*, base_dir: Path, prefix: str) -> Path:
    for _ in range(50):
        candidate = base_dir / f"{prefix}{uuid.uuid4().hex}"
        try:
            candidate.mkdir(parents=True, exist_ok=False)
            return candidate
        except FileExistsError:
            continue
    raise OSError(f"failed to allocate temporary directory under {base_dir}")


@contextmanager
def _prepare_scan_path(raw_path: str, *, clone_timeout: float = 30.0):
    if _is_github_url(raw_path):
        workspace_temp = Path.cwd() / ".codevibes_tmp"
        workspace_temp.mkdir(parents=True, exist_ok=True)
        temp_dir = _create_workspace_temp_dir(base_dir=workspace_temp, prefix="codevibes-")
        try:
            clone_path = temp_dir / "repo"
            env = os.environ.copy()
            env["GIT_TERMINAL_PROMPT"] = "0"
            try:
                clone_result = subprocess.run(
                    ["git", "clone", "--depth", "1", raw_path, str(clone_path)],
                    capture_output=True,
                    text=True,
                    timeout=clone_timeout,
                    env=env,
                )
            except FileNotFoundError:
                print("Error: git is not installed or not available in PATH.")
                yield None
                return
            except subprocess.TimeoutExpired:
                print(f"Error: git clone timed out after {clone_timeout:.0f} seconds.")
                yield None
                return
            if clone_result.returncode != 0:
                stderr = clone_result.stderr.strip()
                stdout = clone_result.stdout.strip()
                detail = stderr or stdout or "unknown git clone error"
                print(f"Error: failed to clone GitHub repo: {detail}")
                yield None
                return
            yield clone_path
            return
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    if _looks_like_url(raw_path):
        print("Error: only GitHub URLs are supported in this version.")
        yield None
        return

    project_path = Path(raw_path).expanduser()
    if not project_path.exists():
        print(f"Error: path does not exist: {project_path}")
        yield None
        return
    if not project_path.is_dir():
        print(f"Error: path is not a directory: {project_path}")
        yield None
        return
    yield project_path


def _is_github_url(value: str) -> bool:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        return False
    if parsed.netloc.lower() != "github.com":
        return False
    path_parts = [part for part in parsed.path.split("/") if part]
    return len(path_parts) >= 2


def _looks_like_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="codevibes",
        description="Brutally honest repository analysis.",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan a local repository path.")
    scan_parser.add_argument("path", help="Local project path or GitHub URL to scan.")
    scan_parser.add_argument(
        "--format",
        choices=("text", "markdown", "json"),
        default="text",
        help="Output format.",
    )
    scan_parser.add_argument(
        "--top-files",
        type=int,
        default=5,
        help="How many top long files to include.",
    )
    scan_parser.add_argument(
        "--max-findings",
        type=int,
        default=None,
        help="Maximum findings shown in detail sections (default comes from .codevibes.json or 50).",
    )
    scan_parser.add_argument(
        "--output",
        help="Optional output file path. If omitted, print to stdout.",
    )
    scan_parser.add_argument(
        "--roast",
        action="store_true",
        help="Use a more sarcastic, personality-heavy verdict style.",
    )
    scan_parser.add_argument(
        "--fail-on-risk",
        type=int,
        help="Return non-zero when risk score is >= this threshold (0-100).",
    )
    scan_parser.add_argument(
        "--fail-on-findings",
        type=int,
        help="Return non-zero when total findings is >= this threshold.",
    )
    scan_parser.add_argument(
        "--submit-webhook",
        help="POST the JSON report to a webhook URL.",
    )
    scan_parser.add_argument(
        "--submit-timeout",
        type=float,
        default=10.0,
        help="Webhook submit timeout in seconds (default: 10).",
    )
    scan_parser.add_argument(
        "--clone-timeout",
        type=float,
        default=30.0,
        help="Git clone timeout in seconds for GitHub URL scans (default: 30).",
    )

    diff_parser = subparsers.add_parser(
        "diff",
        help="Compare refs (`--base/--head`) or compare against a baseline JSON (`--baseline`).",
    )
    diff_parser.add_argument("path", help="Local project path or GitHub URL to scan.")
    diff_parser.add_argument(
        "--baseline",
        help="Path to baseline scan JSON generated by `scan --format json`.",
    )
    diff_parser.add_argument(
        "--base",
        default="main",
        help="Base git ref when `--baseline` is not provided (default: main).",
    )
    diff_parser.add_argument(
        "--head",
        default="HEAD",
        help="Head git ref when `--baseline` is not provided (default: HEAD).",
    )
    diff_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Diff output format.",
    )
    diff_parser.add_argument(
        "--top-files",
        type=int,
        default=5,
        help="How many top long files to include while scanning current state.",
    )
    diff_parser.add_argument(
        "--max-findings",
        type=int,
        default=None,
        help="Maximum findings included in diff details.",
    )
    diff_parser.add_argument(
        "--output",
        help="Optional output file path. If omitted, print to stdout.",
    )
    diff_parser.add_argument(
        "--fail-on-new-high",
        type=int,
        help="Return non-zero when new high/critical findings are greater than this threshold.",
    )
    diff_parser.add_argument(
        "--clone-timeout",
        type=float,
        default=30.0,
        help="Git clone timeout in seconds for GitHub URL scans (default: 30).",
    )

    ui_parser = subparsers.add_parser("ui", help="Run the local Next.js web UI.")
    ui_parser.add_argument("--host", default="127.0.0.1", help="Host to bind.")
    ui_parser.add_argument("--port", type=int, default=8765, help="Port to bind.")
    ui_parser.add_argument("--no-browser", action="store_true", help="Do not auto-open browser.")
    ui_parser.add_argument(
        "--skip-install",
        action="store_true",
        help="Do not auto-run npm install when ui/node_modules is missing.",
    )

    return parser


def _submit_report(webhook_url: str, payload_json: str, *, timeout_seconds: float) -> bool:
    try:
        req = urllib.request.Request(
            webhook_url,
            data=payload_json.encode("utf-8"),
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": f"codevibes/{__version__}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            status = getattr(resp, "status", 200)
            if 200 <= status < 300:
                return True
            print(f"Error: webhook submission failed with HTTP {status}.", file=sys.stderr)
            return False
    except urllib.error.HTTPError as exc:
        print(f"Error: webhook submission failed with HTTP {exc.code}.", file=sys.stderr)
        return False
    except urllib.error.URLError as exc:
        print(f"Error: webhook submission failed: {exc.reason}", file=sys.stderr)
        return False
    except OSError as exc:
        print(f"Error: webhook submission failed: {exc}", file=sys.stderr)
        return False


def _with_submission_metadata(payload_json: str, *, project_path: Path) -> str:
    try:
        payload_obj = json.loads(payload_json)
    except json.JSONDecodeError:
        return payload_json
    if not isinstance(payload_obj, dict):
        return payload_json

    payload_obj["submission_metadata"] = {
        "project_path": str(project_path),
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "tool_version": __version__,
    }
    return json.dumps(payload_obj, ensure_ascii=False, indent=2)

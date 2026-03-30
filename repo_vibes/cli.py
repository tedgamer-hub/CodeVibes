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
import tempfile
import urllib.error
import urllib.request
from urllib.parse import urlparse

from . import __version__
from .config import RepoVibesConfig, load_repo_config
from .formatter import format_json_report, format_markdown_report, format_report
from .scoring import score_repo_vibes
from .scanner import scan_project


def main(argv: list[str] | None = None) -> int:
    raw_args = argv if argv is not None else sys.argv[1:]
    if raw_args and raw_args[0] not in {"scan", "ui"}:
        # Backward-compatible shortcut: `python main.py <path>`
        raw_args = ["scan", raw_args[0], *raw_args[1:]]

    parser = _build_parser()
    ns = parser.parse_args(raw_args)
    if ns.command == "ui":
        return _run_ui_command(ns)
    if ns.command != "scan":
        parser.print_help()
        return 1
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

    return _run_scan_command(ns)


def _run_scan_command(ns) -> int:
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
        if (
            ns.fail_on_findings is not None
            and scorecard.total_findings >= ns.fail_on_findings
        ):
            policy_errors.append(
                f"findings {scorecard.total_findings} >= fail-on-findings {ns.fail_on_findings}"
            )
        if policy_errors:
            print(f"Policy failed: {'; '.join(policy_errors)}.", file=sys.stderr)
            return 2
        return 0


def _run_ui_command(ns) -> int:
    if ns.port <= 0 or ns.port > 65535:
        print("Error: --port must be in range 1..65535.")
        return 1
    if ns.clone_timeout <= 0:
        print("Error: --clone-timeout must be > 0.")
        return 1
    from .web_ui import run_ui_server

    return run_ui_server(
        host=ns.host,
        port=ns.port,
        no_browser=ns.no_browser,
        clone_timeout=ns.clone_timeout,
    )


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
                return formatter(report, scorecard, max_findings=max_findings, roast_mode=roast_mode)
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


@contextmanager
def _prepare_scan_path(raw_path: str, *, clone_timeout: float = 30.0):
    if _is_github_url(raw_path):
        workspace_temp = Path.cwd() / ".codevibes_tmp"
        workspace_temp.mkdir(parents=True, exist_ok=True)
        temp_dir = tempfile.mkdtemp(prefix="codevibes-", dir=str(workspace_temp))
        try:
            clone_path = Path(temp_dir) / "repo"
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

    ui_parser = subparsers.add_parser("ui", help="Launch local web UI dashboard.")
    ui_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind the UI server (default: 127.0.0.1).",
    )
    ui_parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="Port to bind the UI server (default: 8765).",
    )
    ui_parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not auto-open browser when the UI starts.",
    )
    ui_parser.add_argument(
        "--clone-timeout",
        type=float,
        default=30.0,
        help="Git clone timeout in seconds for GitHub URL scans (default: 30).",
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

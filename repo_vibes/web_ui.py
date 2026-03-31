from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import shutil
import subprocess
import tempfile
import webbrowser
from urllib.parse import urlparse

from .config import load_repo_config
from .formatter import format_json_report, format_markdown_report, format_report
from .scoring import score_repo_vibes
from .scanner import scan_project

HTML_PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>CodeVibes UI</title>
  <style>
    body { font-family: Consolas, "Courier New", monospace; margin: 24px; }
    input, button { font: inherit; padding: 8px; margin: 4px 0; }
    pre { background: #111; color: #ddd; padding: 12px; overflow: auto; border-radius: 8px; }
  </style>
</head>
<body>
  <h1>CodeVibes UI</h1>
  <form id="scan-form">
    <div><input id="path" type="text" value="." style="width: 520px;" /></div>
    <div><label>Top Files: <input id="top-files" type="number" min="1" value="5" /></label></div>
    <div><label>Max Findings: <input id="max-findings" type="number" min="1" /></label></div>
    <div><label><input id="roast-mode" type="checkbox" /> Roast mode</label></div>
    <button type="submit">Run Scan</button>
  </form>
  <pre id="output">No scan yet.</pre>
  <script>
    const form = document.getElementById("scan-form");
    const output = document.getElementById("output");
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const payload = {
        path: document.getElementById("path").value.trim(),
        top_files: Number(document.getElementById("top-files").value || "5"),
        max_findings: document.getElementById("max-findings").value
          ? Number(document.getElementById("max-findings").value)
          : null,
        roast_mode: !!document.getElementById("roast-mode").checked,
      };
      try {
        const resp = await fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        const body = await resp.json();
        output.textContent = JSON.stringify(body, null, 2);
      } catch (err) {
        output.textContent = String(err);
      }
    });
  </script>
</body>
</html>
"""


def scan_to_payload(
    raw_path: str,
    *,
    top_files: int | None = 5,
    max_findings: int | None = None,
    roast_mode: bool = False,
    clone_timeout: float = 30.0,
) -> dict[str, object]:
    path_value = raw_path.strip()
    if not path_value:
        raise ValueError("path is required.")
    resolved_top_files = 5 if top_files is None else top_files
    if resolved_top_files <= 0:
        raise ValueError("top_files must be >= 1.")
    if max_findings is not None and max_findings <= 0:
        raise ValueError("max_findings must be >= 1 when provided.")
    if clone_timeout <= 0:
        raise ValueError("clone_timeout must be > 0.")

    with _prepare_scan_path(path_value, clone_timeout=clone_timeout) as project_path:
        config, warnings = load_repo_config(project_path)
        report = scan_project(project_path, top_largest_files=resolved_top_files, config=config)
        scorecard = score_repo_vibes(report, line_thresholds=config.oversized_file_line_thresholds)
        resolved_max_findings = (
            max_findings if max_findings is not None else config.max_findings_default
        )
        payload = json.loads(
            format_json_report(
                report,
                scorecard,
                max_findings=resolved_max_findings,
                config=config,
                roast_mode=roast_mode,
            )
        )
        text_report = format_report(
            report,
            scorecard,
            max_findings=resolved_max_findings,
            config=config,
            roast_mode=roast_mode,
        )
        markdown_report = format_markdown_report(
            report,
            scorecard,
            max_findings=resolved_max_findings,
            config=config,
            roast_mode=roast_mode,
        )
    return {
        "warnings": warnings,
        "payload": payload,
        "text_report": text_report,
        "markdown_report": markdown_report,
    }


def run_ui_server(
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    no_browser: bool = False,
    clone_timeout: float = 30.0,
) -> int:
    handler_cls = _build_handler(clone_timeout=clone_timeout)
    server = ThreadingHTTPServer((host, port), handler_cls)
    url = f"http://{host}:{port}"
    print(f"CodeVibes UI listening on {url}")
    print("Press Ctrl+C to stop.")
    if not no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down CodeVibes UI...")
        return 0
    finally:
        server.server_close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="codevibes-ui", description="Run CodeVibes web UI.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--clone-timeout", type=float, default=30.0)
    ns = parser.parse_args(argv)
    if ns.clone_timeout <= 0:
        print("Error: --clone-timeout must be > 0.")
        return 1
    return run_ui_server(
        host=ns.host,
        port=ns.port,
        no_browser=ns.no_browser,
        clone_timeout=ns.clone_timeout,
    )


def _build_handler(*, clone_timeout: float):
    class CodeVibesHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path != "/":
                self._send_json(404, {"ok": False, "error": "Not found."})
                return
            body = HTML_PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/api/scan":
                self._send_json(404, {"ok": False, "error": "Not found."})
                return
            try:
                body_length = int(self.headers.get("Content-Length", "0"))
                raw_body = self.rfile.read(body_length).decode("utf-8")
                data = json.loads(raw_body) if raw_body else {}
                if not isinstance(data, dict):
                    raise ValueError("Request body must be a JSON object.")

                top_files = int(_required_int_value(data.get("top_files"), default=5))
                max_findings: int | None = _optional_int_value(data.get("max_findings"))
                roast_mode = bool(data.get("roast_mode", False))
                timeout_value = _float_value(data.get("clone_timeout"), default=clone_timeout)
                result = scan_to_payload(
                    str(data.get("path", "")),
                    top_files=top_files,
                    max_findings=max_findings,
                    roast_mode=roast_mode,
                    clone_timeout=timeout_value,
                )
                self._send_json(200, {"ok": True, "result": result})
            except ValueError as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
            except OSError as exc:
                self._send_json(500, {"ok": False, "error": f"scan failed: {exc}"})
            except Exception as exc:  # pragma: no cover
                self._send_json(500, {"ok": False, "error": f"unexpected error: {exc}"})

        def log_message(self, format: str, *args: object) -> None:
            return

        def _send_json(self, status: int, payload: dict[str, object]) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return CodeVibesHandler


def _required_int_value(value: object, *, default: int) -> int:
    if value in (None, ""):
        return default
    if isinstance(value, bool):
        raise ValueError("Integer value cannot be boolean.")
    if not isinstance(value, (int, float, str)):
        raise ValueError(f"Invalid integer value: {value}")
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid integer value: {value}") from exc


def _optional_int_value(value: object) -> int | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        raise ValueError("Integer value cannot be boolean.")
    if not isinstance(value, (int, float, str)):
        raise ValueError(f"Invalid integer value: {value}")
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid integer value: {value}") from exc


def _float_value(value: object, *, default: float) -> float:
    if value in (None, ""):
        return default
    if isinstance(value, bool):
        raise ValueError("Float value cannot be boolean.")
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid float value: {value}") from exc


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
            clone_result = subprocess.run(
                ["git", "clone", "--depth", "1", raw_path, str(clone_path)],
                capture_output=True,
                text=True,
                timeout=clone_timeout,
                env=env,
            )
            if clone_result.returncode != 0:
                stderr = clone_result.stderr.strip()
                stdout = clone_result.stdout.strip()
                detail = stderr or stdout or "unknown git clone error"
                raise OSError(f"failed to clone GitHub repo: {detail}")
            yield clone_path
            return
        except FileNotFoundError as exc:
            raise OSError("git is not installed or not available in PATH.") from exc
        except subprocess.TimeoutExpired as exc:
            raise OSError(f"git clone timed out after {clone_timeout:.0f} seconds.") from exc
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    if _looks_like_url(raw_path):
        raise ValueError("only GitHub URLs are supported in this version.")

    project_path = Path(raw_path).expanduser()
    if not project_path.exists():
        raise ValueError(f"path does not exist: {project_path}")
    if not project_path.is_dir():
        raise ValueError(f"path is not a directory: {project_path}")
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

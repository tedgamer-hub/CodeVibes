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
  <title>CodeVibes Control Room</title>
  <style>
    :root {
      --bg-a: #041a22;
      --bg-b: #0f3f44;
      --ink: #f6f9ef;
      --muted: #c4d3ce;
      --card: rgba(4, 18, 26, 0.68);
      --line: rgba(160, 202, 191, 0.24);
      --ok: #42d9a1;
      --warn: #f7b548;
      --danger: #ff6f61;
      --accent: #7ef0cf;
      --accent-2: #ffd184;
      --shadow: 0 18px 40px rgba(0, 7, 10, 0.34);
      --rad-lg: 20px;
      --rad-md: 14px;
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      min-height: 100vh;
      font-family: "Trebuchet MS", "Gill Sans", "Noto Sans SC", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(1200px 420px at -10% 0%, rgba(126, 240, 207, 0.13), transparent 62%),
        radial-gradient(900px 300px at 110% 12%, rgba(255, 209, 132, 0.12), transparent 54%),
        linear-gradient(155deg, var(--bg-a) 0%, var(--bg-b) 64%, #0a2833 100%);
    }

    .grain {
      position: fixed;
      inset: 0;
      pointer-events: none;
      opacity: 0.22;
      background-image: radial-gradient(rgba(255, 255, 255, 0.15) 0.75px, transparent 0.75px);
      background-size: 3px 3px;
      mix-blend-mode: soft-light;
    }

    .shell {
      width: min(1180px, 94vw);
      margin: 40px auto 52px;
      position: relative;
      z-index: 1;
      animation: rise 500ms ease-out both;
    }

    .hero {
      border: 1px solid var(--line);
      border-radius: var(--rad-lg);
      padding: 28px 24px;
      background: linear-gradient(
        140deg,
        rgba(11, 37, 46, 0.9) 0%,
        rgba(8, 30, 38, 0.82) 44%,
        rgba(13, 45, 46, 0.74) 100%
      );
      box-shadow: var(--shadow);
      backdrop-filter: blur(4px);
    }

    .hero h1 {
      margin: 0;
      letter-spacing: 0.06em;
      font-family: "Franklin Gothic Medium", "Arial Narrow", sans-serif;
      text-transform: uppercase;
      font-size: clamp(1.5rem, 3.5vw, 2.35rem);
    }

    .hero p {
      margin: 10px 0 0;
      color: var(--muted);
      max-width: 760px;
      line-height: 1.5;
    }

    .panel {
      margin-top: 18px;
      border: 1px solid var(--line);
      border-radius: var(--rad-lg);
      background: var(--card);
      box-shadow: var(--shadow);
      backdrop-filter: blur(5px);
      overflow: hidden;
    }

    .controls {
      padding: 18px;
      display: grid;
      grid-template-columns: 2.3fr 1fr 1fr;
      gap: 12px;
      align-items: end;
      border-bottom: 1px solid var(--line);
    }

    .ctrl {
      display: flex;
      flex-direction: column;
      gap: 6px;
      min-width: 0;
    }

    .ctrl label {
      font-size: 0.83rem;
      color: var(--muted);
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }

    input[type="text"],
    input[type="number"] {
      width: 100%;
      border: 1px solid rgba(167, 221, 209, 0.3);
      border-radius: 12px;
      background: rgba(3, 17, 25, 0.8);
      color: var(--ink);
      padding: 11px 12px;
      font-size: 0.96rem;
      outline: none;
      transition: border-color 120ms ease, box-shadow 120ms ease;
    }

    input[type="text"]:focus,
    input[type="number"]:focus {
      border-color: rgba(126, 240, 207, 0.92);
      box-shadow: 0 0 0 2px rgba(126, 240, 207, 0.14);
    }

    .control-row {
      padding: 16px 18px;
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      align-items: center;
    }

    button {
      border: 1px solid rgba(191, 255, 233, 0.5);
      border-radius: 999px;
      background: linear-gradient(120deg, #91ffe0, #d2ff8f);
      color: #03211f;
      font-weight: 700;
      letter-spacing: 0.03em;
      text-transform: uppercase;
      padding: 11px 18px;
      cursor: pointer;
      transition: transform 120ms ease, box-shadow 120ms ease;
    }

    button:hover {
      transform: translateY(-1px);
      box-shadow: 0 8px 20px rgba(104, 224, 180, 0.35);
    }

    button:disabled {
      cursor: not-allowed;
      transform: none;
      opacity: 0.75;
    }

    .checkbox {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      color: var(--muted);
      font-size: 0.94rem;
      margin-right: 12px;
    }

    .status {
      margin-left: auto;
      font-size: 0.84rem;
      color: #0a3d2f;
      background: rgba(126, 240, 207, 0.9);
      padding: 6px 10px;
      border-radius: 999px;
      white-space: nowrap;
    }

    .status[data-level="busy"] {
      color: #4a3000;
      background: rgba(247, 181, 72, 0.9);
    }

    .status[data-level="error"] {
      color: #4f0d07;
      background: rgba(255, 111, 97, 0.9);
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(12, minmax(0, 1fr));
      gap: 12px;
      padding: 14px;
    }

    .card {
      border: 1px solid var(--line);
      border-radius: var(--rad-md);
      background: rgba(3, 15, 24, 0.8);
      padding: 14px;
      animation: rise 420ms ease-out both;
    }

    .card h2 {
      margin: 0 0 8px;
      font-size: 0.98rem;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      color: #dbefe7;
    }

    .span-4 { grid-column: span 4; }
    .span-6 { grid-column: span 6; }
    .span-8 { grid-column: span 8; }
    .span-12 { grid-column: span 12; }

    .metric {
      margin-bottom: 12px;
    }

    .metric-head {
      display: flex;
      justify-content: space-between;
      font-size: 0.91rem;
      color: var(--muted);
      margin-bottom: 4px;
    }

    .meter {
      position: relative;
      height: 8px;
      border-radius: 999px;
      background: rgba(157, 211, 205, 0.17);
      overflow: hidden;
    }

    .meter > span {
      position: absolute;
      inset: 0 auto 0 0;
      width: 0;
      border-radius: 999px;
      background: linear-gradient(90deg, #7ef0cf 0%, #d2ff8f 100%);
      transition: width 420ms ease;
    }

    .meter.risk > span {
      background: linear-gradient(90deg, #f8da84 0%, #ff6f61 100%);
    }

    .kv {
      display: grid;
      grid-template-columns: auto 1fr;
      gap: 7px 10px;
      margin: 0;
    }

    .kv dt {
      color: var(--muted);
      font-size: 0.87rem;
    }

    .kv dd {
      margin: 0;
      font-family: Consolas, "Courier New", monospace;
      font-size: 0.9rem;
      color: #eaf7f2;
      word-break: break-word;
    }

    .tag-row {
      display: flex;
      flex-wrap: wrap;
      gap: 7px;
    }

    .tag {
      border: 1px solid rgba(150, 212, 195, 0.28);
      border-radius: 999px;
      padding: 4px 10px;
      font-size: 0.79rem;
      color: #d8ebe4;
      background: rgba(12, 48, 51, 0.65);
      white-space: nowrap;
    }

    .finding-list {
      list-style: none;
      margin: 0;
      padding: 0;
      display: flex;
      flex-direction: column;
      gap: 9px;
    }

    .finding {
      border: 1px solid rgba(148, 201, 188, 0.23);
      border-radius: 10px;
      padding: 9px 10px;
      background: rgba(5, 21, 29, 0.72);
    }

    .finding small {
      color: var(--muted);
    }

    .sev {
      display: inline-block;
      margin-right: 6px;
      border-radius: 999px;
      padding: 1px 8px;
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      font-weight: 700;
    }

    .sev.low { background: rgba(66, 217, 161, 0.2); color: #86ffd5; }
    .sev.medium { background: rgba(247, 181, 72, 0.22); color: #ffd18a; }
    .sev.high,
    .sev.critical { background: rgba(255, 111, 97, 0.24); color: #ffbaae; }

    pre {
      margin: 0;
      max-height: 300px;
      overflow: auto;
      padding: 12px;
      border: 1px solid rgba(148, 201, 188, 0.25);
      border-radius: 10px;
      background: rgba(3, 16, 22, 0.9);
      color: #dbf2eb;
      font-size: 0.83rem;
      font-family: Consolas, "Courier New", monospace;
      line-height: 1.4;
      white-space: pre-wrap;
      word-break: break-word;
    }

    .empty {
      color: var(--muted);
      margin: 0;
    }

    @keyframes rise {
      from {
        opacity: 0;
        transform: translateY(7px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    @media (max-width: 980px) {
      .controls {
        grid-template-columns: 1fr;
      }
      .status {
        margin-left: 0;
      }
      .span-4,
      .span-6,
      .span-8 {
        grid-column: span 12;
      }
    }
  </style>
</head>
<body>
  <div class="grain"></div>
  <main class="shell">
    <section class="hero">
      <h1>CodeVibes Control Room</h1>
      <p>Scan local projects or GitHub repos, inspect risk and vibe signals, and review findings in one live dashboard.</p>
    </section>

    <section class="panel">
      <form id="scan-form">
        <div class="controls">
          <div class="ctrl">
            <label for="path">Project Path Or GitHub URL</label>
            <input id="path" type="text" value="." placeholder="C:\\projects\\my-repo or https://github.com/org/repo" required />
          </div>
          <div class="ctrl">
            <label for="top-files">Top Long Files</label>
            <input id="top-files" type="number" min="1" max="50" value="5" />
          </div>
          <div class="ctrl">
            <label for="max-findings">Max Findings (Optional)</label>
            <input id="max-findings" type="number" min="1" max="500" placeholder="use config default" />
          </div>
        </div>
        <div class="control-row">
          <label class="checkbox"><input id="roast-mode" type="checkbox" /> Roast mode verdict</label>
          <button id="scan-button" type="submit">Run Scan</button>
          <span id="status" class="status" data-level="ok">Idle</span>
        </div>
      </form>

      <div class="grid">
        <article class="card span-4">
          <h2>Overview</h2>
          <dl id="overview" class="kv"></dl>
        </article>

        <article class="card span-8">
          <h2>Core Scores</h2>
          <div id="scores"></div>
          <div id="verdict" class="tag" style="margin-top:10px;"></div>
        </article>

        <article class="card span-6">
          <h2>Suspicious Files</h2>
          <div id="suspicious" class="tag-row"></div>
        </article>

        <article class="card span-6">
          <h2>Warnings</h2>
          <ul id="warnings" class="finding-list"></ul>
        </article>

        <article class="card span-6">
          <h2>Security Findings</h2>
          <ul id="security-findings" class="finding-list"></ul>
        </article>

        <article class="card span-6">
          <h2>CodeVibes Findings</h2>
          <ul id="vibe-findings" class="finding-list"></ul>
        </article>

        <article class="card span-12">
          <h2>Raw JSON</h2>
          <pre id="json-output">No scan yet.</pre>
        </article>
      </div>
    </section>
  </main>

  <script>
    const els = {
      form: document.getElementById("scan-form"),
      path: document.getElementById("path"),
      topFiles: document.getElementById("top-files"),
      maxFindings: document.getElementById("max-findings"),
      roastMode: document.getElementById("roast-mode"),
      status: document.getElementById("status"),
      button: document.getElementById("scan-button"),
      overview: document.getElementById("overview"),
      scores: document.getElementById("scores"),
      verdict: document.getElementById("verdict"),
      suspicious: document.getElementById("suspicious"),
      warnings: document.getElementById("warnings"),
      securityFindings: document.getElementById("security-findings"),
      vibeFindings: document.getElementById("vibe-findings"),
      jsonOutput: document.getElementById("json-output"),
    };

    function escapeHtml(value) {
      return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
    }

    function setStatus(level, text) {
      els.status.dataset.level = level;
      els.status.textContent = text;
    }

    function meter(name, value, riskMode = false) {
      const clz = riskMode ? "meter risk" : "meter";
      const width = Math.max(0, Math.min(100, Number(value)));
      return `
        <div class="metric">
          <div class="metric-head"><span>${escapeHtml(name)}</span><strong>${width}/100</strong></div>
          <div class="${clz}"><span style="width:${width}%"></span></div>
        </div>
      `;
    }

    function renderFindings(target, findings) {
      if (!Array.isArray(findings) || findings.length === 0) {
        target.innerHTML = '<p class="empty">No findings.</p>';
        return;
      }
      target.innerHTML = findings
        .map((f) => {
          const sev = escapeHtml(f.severity || "low");
          const path = escapeHtml(f.file_path || ".");
          const line = f.line_no ? `:${f.line_no}` : "";
          const snippet = escapeHtml(f.snippet || "");
          return `
            <li class="finding">
              <span class="sev ${sev}">${sev}</span>
              <small>${path}${line}</small>
              <div>${snippet}</div>
            </li>
          `;
        })
        .join("");
    }

    function renderWarnings(warnings) {
      if (!Array.isArray(warnings) || warnings.length === 0) {
        els.warnings.innerHTML = '<p class="empty">No config warnings.</p>';
        return;
      }
      els.warnings.innerHTML = warnings
        .map((item) => `<li class="finding"><small>${escapeHtml(item)}</small></li>`)
        .join("");
    }

    function renderSuspicious(items) {
      if (!Array.isArray(items) || items.length === 0) {
        els.suspicious.innerHTML = '<p class="empty">No strongly suspicious files detected.</p>';
        return;
      }
      els.suspicious.innerHTML = items
        .map((entry) => {
          const path = escapeHtml(entry[0] || "");
          const reasons = Array.isArray(entry[1]) ? entry[1].map((v) => escapeHtml(v)).join(", ") : "";
          return `<span class="tag">${path}${reasons ? " | " + reasons : ""}</span>`;
        })
        .join("");
    }

    function renderOverview(report, scorecard) {
      const items = [
        ["Project", report.project_name],
        ["Path", report.root_path],
        ["Duration", `${report.duration_ms} ms`],
        ["Scanned Files", report.file_count],
        ["Total Lines", report.total_lines],
        ["Risk Level", scorecard.risk_level],
        ["Total Findings", scorecard.total_findings],
      ];
      els.overview.innerHTML = items
        .map(([k, v]) => `<dt>${escapeHtml(k)}</dt><dd>${escapeHtml(v)}</dd>`)
        .join("");
    }

    function renderScores(scorecard) {
      els.scores.innerHTML = [
        meter("Risk Score", scorecard.risk_score, true),
        meter("Vibe Score", scorecard.vibe_score),
        meter("Structure Score", scorecard.structure_score),
        meter("Complexity Score", scorecard.complexity_score),
        meter("Naming Chaos Index", scorecard.naming_chaos_index, true),
      ].join("");
    }

    function parseInteger(value) {
      if (value === undefined || value === null || value === "") {
        return null;
      }
      const parsed = Number(value);
      if (!Number.isInteger(parsed)) {
        throw new Error("Numeric fields must be integers.");
      }
      return parsed;
    }

    async function runScan() {
      const payload = {
        path: els.path.value.trim(),
        top_files: parseInteger(els.topFiles.value),
        max_findings: parseInteger(els.maxFindings.value),
        roast_mode: !!els.roastMode.checked,
      };

      if (!payload.path) {
        throw new Error("Please provide a path or GitHub URL.");
      }
      if (!payload.top_files || payload.top_files < 1) {
        throw new Error("Top files must be at least 1.");
      }

      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      let body = {};
      try {
        body = await response.json();
      } catch (err) {
        throw new Error("Server returned invalid JSON.");
      }

      if (!response.ok || !body.ok) {
        throw new Error(body.error || "Scan failed.");
      }

      const result = body.result;
      const payloadObj = result.payload;
      renderOverview(payloadObj.scan_report, payloadObj.scorecard);
      renderScores(payloadObj.scorecard);
      renderWarnings(result.warnings);
      renderSuspicious(payloadObj.top_suspicious_files);
      renderFindings(els.securityFindings, payloadObj.security_findings);
      renderFindings(els.vibeFindings, payloadObj.vibe_findings);
      els.verdict.textContent = payloadObj.verdict || "No verdict.";
      els.jsonOutput.textContent = JSON.stringify(payloadObj, null, 2);
      return payloadObj.scan_report.project_name;
    }

    els.form.addEventListener("submit", async (event) => {
      event.preventDefault();
      els.button.disabled = true;
      setStatus("busy", "Scanning...");
      try {
        const project = await runScan();
        setStatus("ok", `Done: ${project}`);
      } catch (error) {
        setStatus("error", error.message || "Scan failed");
      } finally {
        els.button.disabled = false;
      }
    });
  </script>
</body>
</html>
"""


def scan_to_payload(
    raw_path: str,
    *,
    top_files: int = 5,
    max_findings: int | None = None,
    roast_mode: bool = False,
    clone_timeout: float = 30.0,
) -> dict[str, object]:
    path_value = raw_path.strip()
    if not path_value:
        raise ValueError("path is required.")
    if top_files <= 0:
        raise ValueError("top_files must be >= 1.")
    if max_findings is not None and max_findings <= 0:
        raise ValueError("max_findings must be >= 1 when provided.")
    if clone_timeout <= 0:
        raise ValueError("clone_timeout must be > 0.")

    with _prepare_scan_path(path_value, clone_timeout=clone_timeout) as project_path:
        config, warnings = load_repo_config(project_path)
        report = scan_project(
            project_path,
            top_largest_files=top_files,
            config=config,
        )
        scorecard = score_repo_vibes(
            report,
            line_thresholds=config.oversized_file_line_thresholds,
        )
        resolved_max_findings = (
            max_findings if max_findings is not None else config.max_findings_default
        )

        payload_json = format_json_report(
            report,
            scorecard,
            max_findings=resolved_max_findings,
            config=config,
            roast_mode=roast_mode,
        )
        payload = json.loads(payload_json)
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

                top_files = _required_int_value(data.get("top_files"), default=5)
                max_findings = _optional_int_value(data.get("max_findings"))
                roast_mode = bool(data.get("roast_mode", False))
                timeout_value = _float_value(
                    data.get("clone_timeout"),
                    default=clone_timeout,
                )
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
            except Exception as exc:  # pragma: no cover - defensive fallback
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
            try:
                clone_result = subprocess.run(
                    ["git", "clone", "--depth", "1", raw_path, str(clone_path)],
                    capture_output=True,
                    text=True,
                    timeout=clone_timeout,
                    env=env,
                )
            except FileNotFoundError as exc:
                raise ValueError("git is not installed or not available in PATH.") from exc
            except subprocess.TimeoutExpired as exc:
                raise ValueError(
                    f"git clone timed out after {clone_timeout:.0f} seconds."
                ) from exc
            if clone_result.returncode != 0:
                stderr = clone_result.stderr.strip()
                stdout = clone_result.stdout.strip()
                detail = stderr or stdout or "unknown git clone error"
                raise ValueError(f"failed to clone GitHub repo: {detail}")
            yield clone_path
            return
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    if _looks_like_url(raw_path):
        raise ValueError("Only GitHub URLs are supported in this version.")

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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="codevibes-ui",
        description="Run CodeVibes local web UI.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind.")
    parser.add_argument("--port", type=int, default=8765, help="Port to bind.")
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not auto-open browser.",
    )
    parser.add_argument(
        "--clone-timeout",
        type=float,
        default=30.0,
        help="Git clone timeout for GitHub URL scans.",
    )
    ns = parser.parse_args(argv)
    if ns.port <= 0 or ns.port > 65535:
        print("Error: --port must be in range 1..65535.")
        return 1
    if ns.clone_timeout <= 0:
        print("Error: --clone-timeout must be > 0.")
        return 1
    return run_ui_server(
        host=ns.host,
        port=ns.port,
        no_browser=ns.no_browser,
        clone_timeout=ns.clone_timeout,
    )

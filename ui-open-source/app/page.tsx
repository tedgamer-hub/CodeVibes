"use client";

import { FormEvent, useMemo, useState } from "react";

import type {
  DiffPayload,
  DiffResponse,
  RiskFinding,
  ScanPayload,
  ScanResponse,
} from "@/lib/types";

type UiStatus = { level: "idle" | "busy" | "error"; text: string };

export default function HomePage() {
  const [tab, setTab] = useState<"scan" | "diff">("scan");

  const [scanTarget, setScanTarget] = useState(".");
  const [topFiles, setTopFiles] = useState("5");
  const [maxFindings, setMaxFindings] = useState("");
  const [roastMode, setRoastMode] = useState(false);
  const [scanStatus, setScanStatus] = useState<UiStatus>({ level: "idle", text: "Idle" });
  const [scanPayload, setScanPayload] = useState<ScanPayload | null>(null);
  const [scanWarnings, setScanWarnings] = useState<string[]>([]);
  const [scanLoading, setScanLoading] = useState(false);

  const [diffRepoPath, setDiffRepoPath] = useState(".");
  const [diffMode, setDiffMode] = useState<"refs" | "baseline">("refs");
  const [baseRef, setBaseRef] = useState("main");
  const [headRef, setHeadRef] = useState("HEAD");
  const [baselinePath, setBaselinePath] = useState("");
  const [diffMaxFindings, setDiffMaxFindings] = useState("50");
  const [diffStatus, setDiffStatus] = useState<UiStatus>({ level: "idle", text: "Idle" });
  const [diffPayload, setDiffPayload] = useState<DiffPayload | null>(null);
  const [diffWarnings, setDiffWarnings] = useState<string[]>([]);
  const [diffLoading, setDiffLoading] = useState(false);

  const scanStatusClass = useMemo(() => toStatusClass(scanStatus.level), [scanStatus.level]);
  const diffStatusClass = useMemo(() => toStatusClass(diffStatus.level), [diffStatus.level]);

  async function onScanSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const trimmedTarget = scanTarget.trim();
    if (!trimmedTarget) {
      setScanStatus({ level: "error", text: "Path or URL is required." });
      return;
    }

    setScanLoading(true);
    setScanStatus({ level: "busy", text: "Scanning..." });
    try {
      const resp = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: trimmedTarget,
          top_files: parseInt(topFiles || "5", 10),
          max_findings: maxFindings.trim() ? parseInt(maxFindings, 10) : null,
          roast_mode: roastMode,
        }),
      });
      const body = (await resp.json()) as ScanResponse;
      if (!resp.ok || !body.ok || !body.data) {
        throw new Error(body.error ?? "Scan failed.");
      }
      setScanPayload(body.data.payload);
      setScanWarnings(body.data.warnings);
      setScanStatus({
        level: "idle",
        text: `Done: ${body.data.payload.scan_report.project_name}`,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : "Scan failed.";
      setScanStatus({ level: "error", text: message });
    } finally {
      setScanLoading(false);
    }
  }

  async function onDiffSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const repoPath = diffRepoPath.trim() || ".";
    if (diffMode === "baseline" && !baselinePath.trim()) {
      setDiffStatus({ level: "error", text: "Baseline path is required in baseline mode." });
      return;
    }

    setDiffLoading(true);
    setDiffStatus({ level: "busy", text: "Diffing..." });
    try {
      const resp = await fetch("/api/diff", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          repo_path: repoPath,
          base_ref: baseRef.trim() || "main",
          head_ref: headRef.trim() || "HEAD",
          baseline_path: diffMode === "baseline" ? baselinePath.trim() : null,
          max_findings: parseInt(diffMaxFindings || "50", 10),
        }),
      });
      const body = (await resp.json()) as DiffResponse;
      if (!resp.ok || !body.ok || !body.data) {
        throw new Error(body.error ?? "Diff failed.");
      }
      setDiffPayload(body.data.payload);
      setDiffWarnings(body.data.warnings);
      setDiffStatus({ level: "idle", text: `Done: ${body.data.payload.base_label} -> ${body.data.payload.head_label}` });
    } catch (error) {
      const message = error instanceof Error ? error.message : "Diff failed.";
      setDiffStatus({ level: "error", text: message });
    } finally {
      setDiffLoading(false);
    }
  }

  return (
    <main className="wrap">
      <section className="hero">
        <h1>CodeVibes Control Room</h1>
        <p>
          Scan repositories, run PR-style diff analysis, inspect risk and vibe regressions, and
          prioritize fixes in one dashboard.
        </p>
        <div className="tabs">
          <button
            type="button"
            className={tab === "scan" ? "tab active" : "tab"}
            onClick={() => setTab("scan")}
          >
            Scan
          </button>
          <button
            type="button"
            className={tab === "diff" ? "tab active" : "tab"}
            onClick={() => setTab("diff")}
          >
            Diff
          </button>
        </div>
      </section>

      {tab === "scan" ? (
        <ScanPanel
          onSubmit={onScanSubmit}
          loading={scanLoading}
          status={scanStatus}
          statusClass={scanStatusClass}
          target={scanTarget}
          setTarget={setScanTarget}
          topFiles={topFiles}
          setTopFiles={setTopFiles}
          maxFindings={maxFindings}
          setMaxFindings={setMaxFindings}
          roastMode={roastMode}
          setRoastMode={setRoastMode}
          payload={scanPayload}
          warnings={scanWarnings}
        />
      ) : (
        <DiffPanel
          onSubmit={onDiffSubmit}
          loading={diffLoading}
          status={diffStatus}
          statusClass={diffStatusClass}
          repoPath={diffRepoPath}
          setRepoPath={setDiffRepoPath}
          diffMode={diffMode}
          setDiffMode={setDiffMode}
          baseRef={baseRef}
          setBaseRef={setBaseRef}
          headRef={headRef}
          setHeadRef={setHeadRef}
          baselinePath={baselinePath}
          setBaselinePath={setBaselinePath}
          maxFindings={diffMaxFindings}
          setMaxFindings={setDiffMaxFindings}
          payload={diffPayload}
          warnings={diffWarnings}
        />
      )}
    </main>
  );
}

function ScanPanel(props: {
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  loading: boolean;
  status: UiStatus;
  statusClass: string;
  target: string;
  setTarget: (value: string) => void;
  topFiles: string;
  setTopFiles: (value: string) => void;
  maxFindings: string;
  setMaxFindings: (value: string) => void;
  roastMode: boolean;
  setRoastMode: (value: boolean) => void;
  payload: ScanPayload | null;
  warnings: string[];
}) {
  return (
    <section className="panel">
      <form onSubmit={props.onSubmit}>
        <div className="controls">
          <div className="field">
            <label htmlFor="scan-target">Project Path Or GitHub URL</label>
            <input
              id="scan-target"
              type="text"
              value={props.target}
              onChange={(event) => props.setTarget(event.target.value)}
              placeholder="C:\\projects\\repo or https://github.com/org/repo"
            />
          </div>
          <div className="field">
            <label htmlFor="scan-top-files">Top Long Files</label>
            <input
              id="scan-top-files"
              type="number"
              min={1}
              value={props.topFiles}
              onChange={(event) => props.setTopFiles(event.target.value)}
            />
          </div>
          <div className="field">
            <label htmlFor="scan-max-findings">Max Findings (Optional)</label>
            <input
              id="scan-max-findings"
              type="number"
              min={1}
              value={props.maxFindings}
              onChange={(event) => props.setMaxFindings(event.target.value)}
              placeholder="use config default"
            />
          </div>
        </div>
        <div className="actions">
          <label className="checkbox">
            <input
              type="checkbox"
              checked={props.roastMode}
              onChange={(event) => props.setRoastMode(event.target.checked)}
            />
            Roast mode verdict
          </label>
          <button disabled={props.loading} type="submit">
            {props.loading ? "Running..." : "Run Scan"}
          </button>
          <span className={props.statusClass}>{props.status.text}</span>
        </div>
      </form>

      <div className="grid">
        <section className="card span4">
          <h2>Overview</h2>
          <dl className="kv">
            <dt>Project</dt>
            <dd>{props.payload?.scan_report.project_name ?? "-"}</dd>
            <dt>Path</dt>
            <dd>{props.payload?.scan_report.root_path ?? "-"}</dd>
            <dt>Duration</dt>
            <dd>{props.payload ? `${props.payload.scan_report.duration_ms} ms` : "-"}</dd>
            <dt>Files</dt>
            <dd>{props.payload?.scan_report.file_count ?? "-"}</dd>
            <dt>Total Lines</dt>
            <dd>{props.payload?.scan_report.total_lines ?? "-"}</dd>
          </dl>
        </section>

        <section className="card span8">
          <h2>Core Scores</h2>
          <div className="metrics">
            <Metric name="Risk Score" value={props.payload?.scorecard.risk_score ?? 0} risk />
            <Metric name="Vibe Score" value={props.payload?.scorecard.vibe_score ?? 0} />
            <Metric
              name="Structure Score"
              value={props.payload?.scorecard.structure_score ?? 0}
            />
            <Metric
              name="Complexity Score"
              value={props.payload?.scorecard.complexity_score ?? 0}
            />
            <Metric
              name="Naming Chaos Index"
              value={props.payload?.scorecard.naming_chaos_index ?? 0}
              risk
            />
          </div>
          <div style={{ marginTop: 10 }} className="tag">
            {props.payload?.verdict ?? "No scan yet."}
          </div>
        </section>

        <section className="card span6">
          <h2>Suspicious Files</h2>
          <div className="tags">
            {props.payload?.top_suspicious_files?.length ? (
              props.payload.top_suspicious_files.map(([path, reasons]) => (
                <span key={path} className="tag">
                  {path}
                  {reasons.length ? ` | ${reasons.join(", ")}` : ""}
                </span>
              ))
            ) : (
              <p className="empty">No suspicious files yet.</p>
            )}
          </div>
        </section>

        <section className="card span6">
          <h2>Warnings</h2>
          {props.warnings.length ? (
            <ul className="list">
              {props.warnings.map((warning) => (
                <li className="item" key={warning}>
                  {warning}
                </li>
              ))}
            </ul>
          ) : (
            <p className="empty">No warnings.</p>
          )}
        </section>

        <section className="card span6">
          <h2>Security Findings</h2>
          <FindingList findings={props.payload?.security_findings ?? []} />
        </section>

        <section className="card span6">
          <h2>CodeVibes Findings</h2>
          <FindingList findings={props.payload?.vibe_findings ?? []} />
        </section>

        <section className="card span12">
          <div className="card-head">
            <h2>Raw JSON</h2>
            <button
              type="button"
              className="ghost"
              onClick={() => copyJson(props.payload)}
              disabled={!props.payload}
            >
              Copy JSON
            </button>
          </div>
          <pre>{props.payload ? JSON.stringify(props.payload, null, 2) : "No scan yet."}</pre>
        </section>
      </div>
    </section>
  );
}

function DiffPanel(props: {
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  loading: boolean;
  status: UiStatus;
  statusClass: string;
  repoPath: string;
  setRepoPath: (value: string) => void;
  diffMode: "refs" | "baseline";
  setDiffMode: (value: "refs" | "baseline") => void;
  baseRef: string;
  setBaseRef: (value: string) => void;
  headRef: string;
  setHeadRef: (value: string) => void;
  baselinePath: string;
  setBaselinePath: (value: string) => void;
  maxFindings: string;
  setMaxFindings: (value: string) => void;
  payload: DiffPayload | null;
  warnings: string[];
}) {
  const p = props.payload;
  return (
    <section className="panel">
      <form onSubmit={props.onSubmit}>
        <div className="controls">
          <div className="field">
            <label htmlFor="diff-repo-path">Git Repo Path</label>
            <input
              id="diff-repo-path"
              type="text"
              value={props.repoPath}
              onChange={(event) => props.setRepoPath(event.target.value)}
              placeholder="."
            />
          </div>
          <div className="field">
            <label htmlFor="diff-mode">Diff Mode</label>
            <select
              id="diff-mode"
              value={props.diffMode}
              onChange={(event) => props.setDiffMode(event.target.value as "refs" | "baseline")}
            >
              <option value="refs">Git refs</option>
              <option value="baseline">Baseline file</option>
            </select>
          </div>
          <div className="field">
            <label htmlFor="diff-max-findings">Max Findings</label>
            <input
              id="diff-max-findings"
              type="number"
              min={1}
              value={props.maxFindings}
              onChange={(event) => props.setMaxFindings(event.target.value)}
            />
          </div>
        </div>

        <div className="controls controls-inline">
          {props.diffMode === "refs" ? (
            <>
              <div className="field">
                <label htmlFor="diff-base-ref">Base Ref</label>
                <input
                  id="diff-base-ref"
                  type="text"
                  value={props.baseRef}
                  onChange={(event) => props.setBaseRef(event.target.value)}
                  placeholder="main"
                />
              </div>
              <div className="field">
                <label htmlFor="diff-head-ref">Head Ref</label>
                <input
                  id="diff-head-ref"
                  type="text"
                  value={props.headRef}
                  onChange={(event) => props.setHeadRef(event.target.value)}
                  placeholder="HEAD"
                />
              </div>
              <div className="field">
                <label>Mode Hint</label>
                <input type="text" value="Comparing git refs" disabled />
              </div>
            </>
          ) : (
            <>
              <div className="field field-span-2">
                <label htmlFor="diff-baseline-path">Baseline JSON Path</label>
                <input
                  id="diff-baseline-path"
                  type="text"
                  value={props.baselinePath}
                  onChange={(event) => props.setBaselinePath(event.target.value)}
                  placeholder="reports/baseline.json"
                />
              </div>
              <div className="field">
                <label>Mode Hint</label>
                <input type="text" value="Comparing against baseline file" disabled />
              </div>
            </>
          )}
        </div>

        <div className="actions">
          <button disabled={props.loading} type="submit">
            {props.loading ? "Running..." : "Run Diff"}
          </button>
          <span className={props.statusClass}>{props.status.text}</span>
        </div>
      </form>

      <div className="grid">
        <section className="card span4">
          <h2>CI Signals</h2>
          <dl className="kv">
            <dt>Risk Regression</dt>
            <dd>{p?.ci_signals.risk_regression ?? "-"}</dd>
            <dt>Vibe Drop</dt>
            <dd>{p?.ci_signals.vibe_drop ?? "-"}</dd>
            <dt>New Findings</dt>
            <dd>{p?.ci_signals.new_findings ?? "-"}</dd>
            <dt>New High Findings</dt>
            <dd>{p?.ci_signals.new_high_findings ?? "-"}</dd>
            <dt>Changed Files</dt>
            <dd>{p?.changed_file_count ?? "-"}</dd>
          </dl>
        </section>

        <section className="card span8">
          <h2>Score Deltas</h2>
          <div className="delta-grid">
            <Delta label="Risk Score" value={p?.score_deltas.risk_score ?? 0} invert />
            <Delta label="Vibe Score" value={p?.score_deltas.vibe_score ?? 0} />
            <Delta label="Structure Score" value={p?.score_deltas.structure_score ?? 0} />
            <Delta label="Complexity Score" value={p?.score_deltas.complexity_score ?? 0} />
            <Delta label="Naming Chaos Index" value={p?.score_deltas.naming_chaos_index ?? 0} invert />
            <Delta label="Total Findings" value={p?.score_deltas.total_findings ?? 0} invert />
          </div>
        </section>

        <section className="card span6">
          <h2>Regressions</h2>
          {p?.regressions?.length ? (
            <ul className="list">
              {p.regressions.map((item) => (
                <li className="item" key={`${item.metric}:${item.summary}`}>
                  {item.summary}
                </li>
              ))}
            </ul>
          ) : (
            <p className="empty">No score regressions detected.</p>
          )}
        </section>

        <section className="card span6">
          <h2>Warnings</h2>
          {props.warnings.length ? (
            <ul className="list">
              {props.warnings.map((warning) => (
                <li className="item" key={warning}>
                  {warning}
                </li>
              ))}
            </ul>
          ) : (
            <p className="empty">No warnings.</p>
          )}
        </section>

        <section className="card span6">
          <h2>Degradation Sources</h2>
          {p?.degradation_sources?.length ? (
            <ul className="list">
              {p.degradation_sources.map((item) => (
                <li className="item" key={item.file_path}>
                  <div>
                    <strong>{item.file_path}</strong>
                  </div>
                  <div>impact: {item.weighted_impact} | new findings: {item.new_findings}</div>
                  <div className="muted-text">{item.reasons.join(", ") || "signal regression"}</div>
                </li>
              ))}
            </ul>
          ) : (
            <p className="empty">No degradation sources yet.</p>
          )}
        </section>

        <section className="card span6">
          <h2>Fix Suggestions</h2>
          {p?.fix_suggestions?.length ? (
            <ul className="list">
              {p.fix_suggestions.map((item) => (
                <li className="item" key={`${item.priority}:${item.action}`}>
                  <div>
                    <strong>
                      {item.priority}. {item.action}
                    </strong>
                  </div>
                  <div>target: {item.target}</div>
                  <div>est. risk reduction: -{item.estimated_risk_reduction}</div>
                  <div className="muted-text">{item.details}</div>
                </li>
              ))}
            </ul>
          ) : (
            <p className="empty">No suggestions yet.</p>
          )}
        </section>

        <section className="card span12">
          <h2>New Findings</h2>
          <FindingList findings={p?.new_findings ?? []} />
        </section>

        <section className="card span12">
          <div className="card-head">
            <h2>Raw JSON</h2>
            <button
              type="button"
              className="ghost"
              onClick={() => copyJson(p)}
              disabled={!p}
            >
              Copy JSON
            </button>
          </div>
          <pre>{p ? JSON.stringify(p, null, 2) : "No diff yet."}</pre>
        </section>
      </div>
    </section>
  );
}

function Metric(props: { name: string; value: number; risk?: boolean }) {
  const safe = Math.max(0, Math.min(100, props.value));
  return (
    <div>
      <div className="metric-head">
        <span>{props.name}</span>
        <strong>{safe}/100</strong>
      </div>
      <div className={props.risk ? "bar risk" : "bar"}>
        <span style={{ width: `${safe}%` }} />
      </div>
    </div>
  );
}

function Delta(props: { label: string; value: number; invert?: boolean }) {
  const sign = props.value > 0 ? "+" : "";
  const worse =
    props.value !== 0 &&
    ((props.invert && props.value > 0) || (!props.invert && props.value < 0));
  return (
    <div className={worse ? "delta bad" : "delta"}>
      <span>{props.label}</span>
      <strong>
        {sign}
        {props.value}
      </strong>
    </div>
  );
}

function FindingList(props: { findings: RiskFinding[] }) {
  if (props.findings.length === 0) {
    return <p className="empty">No findings.</p>;
  }
  return (
    <ul className="list">
      {props.findings.map((item, idx) => (
        <li key={`${item.rule_id}:${item.file_path}:${item.line_no ?? "n"}:${idx}`} className="item">
          <div>
            <span className={`sev ${item.severity}`}>{item.severity}</span>
            <code>
              {item.file_path}
              {item.line_no ? `:${item.line_no}` : ""}
            </code>
          </div>
          <div style={{ marginTop: 6 }}>{item.snippet}</div>
        </li>
      ))}
    </ul>
  );
}

async function copyJson(payload: object | null) {
  if (!payload) {
    return;
  }
  try {
    await navigator.clipboard.writeText(JSON.stringify(payload, null, 2));
  } catch {
    // Clipboard access can fail in some browser contexts; fail silently.
  }
}

function toStatusClass(level: UiStatus["level"]) {
  if (level === "busy") return "status busy";
  if (level === "error") return "status error";
  return "status";
}


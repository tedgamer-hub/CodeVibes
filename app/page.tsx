"use client";

import { FormEvent, useMemo, useState } from "react";

import type { AnalyzeResponse, JsonScanPayload, RiskFinding } from "@/lib/types";

export default function HomePage() {
  const [target, setTarget] = useState(".");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [warnings, setWarnings] = useState<string[]>([]);
  const [payload, setPayload] = useState<JsonScanPayload | null>(null);

  const statusClass = useMemo(() => {
    if (error) return "status error";
    if (payload) return "status ok";
    return "status";
  }, [error, payload]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!target.trim()) {
      setError("请输入本地路径或 GitHub URL。");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const resp = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: target.trim() }),
      });
      const body = (await resp.json()) as AnalyzeResponse;
      if (!resp.ok || !body.ok || !body.data) {
        throw new Error(body.error ?? "Analyze failed.");
      }
      setPayload(body.data.payload);
      setWarnings(body.data.warnings);
    } catch (reqError) {
      const message =
        reqError instanceof Error ? reqError.message : "请求失败，请检查服务日志。";
      setError(message);
      setPayload(null);
      setWarnings([]);
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="wrap">
      <section className="hero">
        <h1>CodeVibes Thin UI</h1>
        <p>输入本地路径或 GitHub 仓库 URL，点击 Analyze，查看结构化分析结果。</p>
      </section>

      <section className="card">
        <form onSubmit={handleSubmit}>
          <div className="form-grid">
            <div>
              <label className="field-label" htmlFor="target">
                Path 或 GitHub URL
              </label>
              <input
                id="target"
                className="input"
                value={target}
                onChange={(event) => setTarget(event.target.value)}
                placeholder="例如: . 或 C:\\projects\\repo 或 https://github.com/user/repo"
              />
            </div>
            <div style={{ alignSelf: "end" }}>
              <button type="submit" className="button" disabled={loading}>
                {loading ? "Analyzing..." : "Analyze"}
              </button>
            </div>
          </div>
        </form>
        <div className={statusClass}>
          {error
            ? error
            : payload
              ? `完成: ${payload.scan_report.project_name}`
              : "等待分析"}
        </div>
      </section>

      {payload && (
        <>
          <section className="card">
            <div className="summary">
              <Metric name="Risk Score" value={payload.scorecard.risk_score} />
              <Metric name="Vibe Score" value={payload.scorecard.vibe_score} />
              <Metric
                name="Structure Score"
                value={payload.scorecard.structure_score}
              />
              <Metric
                name="Complexity Score"
                value={payload.scorecard.complexity_score}
              />
              <Metric
                name="Naming Chaos"
                value={payload.scorecard.naming_chaos_index}
              />
            </div>
            <div style={{ marginTop: 14 }}>
              <div className="muted">Verdict</div>
              <div>{payload.verdict}</div>
            </div>
          </section>

          <section className="card">
            <div className="muted">Overview</div>
            <div className="mono" style={{ marginTop: 8 }}>
              {payload.scan_report.project_name} | {payload.scan_report.root_path}
            </div>
            <div className="pill" style={{ marginTop: 10 }}>
              files: {payload.scan_report.file_count}
            </div>
            <div className="pill">lines: {payload.scan_report.total_lines}</div>
            <div className="pill">duration: {payload.scan_report.duration_ms}ms</div>
            <div className="pill">findings: {payload.scorecard.total_findings}</div>
          </section>

          {warnings.length > 0 && (
            <section className="card">
              <div className="muted">Warnings</div>
              <ul className="list" style={{ marginTop: 8 }}>
                {warnings.map((warning) => (
                  <li key={warning} className="item mono">
                    {warning}
                  </li>
                ))}
              </ul>
            </section>
          )}

          <section className="card">
            <div className="muted">Top Suspicious Files</div>
            <div style={{ marginTop: 8 }}>
              {payload.top_suspicious_files.length > 0 ? (
                payload.top_suspicious_files.map(([filePath, reasons]) => (
                  <div key={filePath} className="pill">
                    {filePath}
                    {reasons.length > 0 ? ` | ${reasons.join(", ")}` : ""}
                  </div>
                ))
              ) : (
                <div className="muted">No strongly suspicious files detected.</div>
              )}
            </div>
          </section>

          <section className="card">
            <div className="split">
              <FindingsPanel
                title="Security Findings"
                findings={payload.security_findings}
              />
              <FindingsPanel title="CodeVibes Findings" findings={payload.vibe_findings} />
            </div>
          </section>
        </>
      )}
    </main>
  );
}

function Metric(props: { name: string; value: number }) {
  return (
    <article className="metric">
      <div className="name">{props.name}</div>
      <div className="value">{props.value}</div>
    </article>
  );
}

function FindingsPanel(props: { title: string; findings: RiskFinding[] }) {
  return (
    <article>
      <div className="muted" style={{ marginBottom: 8 }}>
        {props.title}
      </div>
      {props.findings.length > 0 ? (
        <ul className="list">
          {props.findings.map((finding, index) => (
            <li
              key={`${finding.rule_id}:${finding.file_path}:${finding.line_no ?? 0}:${index}`}
              className="item"
            >
              <div>
                <span className={`sev ${finding.severity}`}>{finding.severity}</span>
                <span className="mono">
                  {finding.file_path}
                  {finding.line_no ? `:${finding.line_no}` : ""}
                </span>
              </div>
              <div style={{ marginTop: 6 }}>{finding.snippet}</div>
            </li>
          ))}
        </ul>
      ) : (
        <div className="muted">No findings.</div>
      )}
    </article>
  );
}

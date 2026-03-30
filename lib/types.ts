export type FindingSeverity = "critical" | "high" | "medium" | "low" | string;

export interface RiskFinding {
  rule_id: string;
  severity: FindingSeverity;
  file_path: string;
  line_no: number | null;
  snippet: string;
}

export interface ScanReport {
  project_name: string;
  root_path: string;
  file_count: number;
  total_lines: number;
  max_depth: number;
  duration_ms: number;
}

export interface RepoScorecard {
  risk_score: number;
  risk_level: string;
  naming_chaos_index: number;
  structure_score: number;
  complexity_score: number;
  vibe_score: number;
  overall_verdict: string;
  total_findings: number;
}

export interface JsonScanPayload {
  scan_report: ScanReport;
  scorecard: RepoScorecard;
  top_suspicious_files: [string, string[]][];
  security_findings: RiskFinding[];
  vibe_findings: RiskFinding[];
  verdict: string;
  roast_mode: boolean;
  max_findings: number;
  truncated: boolean;
}

export interface AnalyzeResponse {
  ok: boolean;
  data?: {
    payload: JsonScanPayload;
    warnings: string[];
  };
  error?: string;
}


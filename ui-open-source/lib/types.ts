export type Severity = "critical" | "high" | "medium" | "low" | string;

export interface RiskFinding {
  rule_id: string;
  severity: Severity;
  file_path: string;
  line_no: number | null;
  snippet: string;
}

export interface Scorecard {
  risk_score: number;
  risk_level: string;
  naming_chaos_index: number;
  structure_score: number;
  complexity_score: number;
  vibe_score: number;
  total_findings: number;
  overall_verdict: string;
}

export interface ScanReport {
  project_name: string;
  root_path: string;
  file_count: number;
  total_lines: number;
  max_depth: number;
  duration_ms: number;
}

export interface ScanPayload {
  scan_report: ScanReport;
  scorecard: Scorecard;
  top_suspicious_files: [string, string[]][];
  security_findings: RiskFinding[];
  vibe_findings: RiskFinding[];
  verdict: string;
  roast_mode: boolean;
  max_findings: number;
  truncated: boolean;
}

export interface ScanResponse {
  ok: boolean;
  data?: {
    payload: ScanPayload;
    warnings: string[];
  };
  error?: string;
}

export interface DiffRegression {
  metric: string;
  worse_by: number;
  summary: string;
}

export interface DiffSource {
  file_path: string;
  weighted_impact: number;
  new_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  reasons: string[];
}

export interface FixSuggestion {
  priority: number;
  action: string;
  target: string;
  details: string;
  estimated_risk_reduction: number;
}

export interface DiffSignals {
  risk_regression: number;
  vibe_drop: number;
  new_findings: number;
  new_high_findings: number;
}

export interface DiffPayload {
  mode: "baseline" | "git_refs" | string;
  base_label: string;
  head_label: string;
  changed_file_count: number;
  changed_files: string[];
  score_deltas: {
    risk_score: number;
    vibe_score: number;
    structure_score: number;
    complexity_score: number;
    naming_chaos_index: number;
    total_findings: number;
  };
  regressions: DiffRegression[];
  new_findings_total: number;
  new_findings: RiskFinding[];
  degradation_sources: DiffSource[];
  fix_suggestions: FixSuggestion[];
  ci_signals: DiffSignals;
}

export interface DiffResponse {
  ok: boolean;
  data?: {
    payload: DiffPayload;
    warnings: string[];
  };
  error?: string;
}

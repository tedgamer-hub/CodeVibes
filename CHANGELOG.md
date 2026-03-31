# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Notes

- Ongoing stabilization and polish.

## [1.1.0] - 2026-03-31

### Added (1.1.0)

- New `diff` command for change-focused analysis:
  - `codevibes diff <path> --base <ref> --head <ref>`
  - `codevibes diff <path> --baseline <scan-json>`
- Diff output now includes:
  - `new_findings` and `resolved_findings`
  - `score_deltas` and `regressions`
  - `degradation_sources`
  - `fix_suggestions` with estimated risk reduction
  - `ci_signals` for regression-aware gating
- Regression-aware CI gates for diff mode:
  - `--fail-on-risk-regression`
  - `--fail-on-vibe-drop`
  - `--fail-on-new-findings`
  - `--fail-on-new-high`
- Scanner now supports `only_paths` to analyze targeted file subsets (used by diff mode).
- Reintroduced and expanded frontend workspace in `ui/` (Next.js + React).
- Frontend now provides both `Scan` and `Diff` workspaces in one dashboard.
- Added frontend API bridges:
  - `POST /api/scan` -> calls Python CLI scan JSON output
  - `POST /api/diff` -> calls Python CLI diff JSON output
- Added UI runtime controls for `codevibes ui`:
  - `--frontend {next,legacy}`
  - `--legacy`
  - `--skip-install`

### Changed (1.1.0)

- `codevibes ui` now defaults to Next.js frontend and falls back to legacy Python UI when frontend runtime is unavailable.
- `codevibes ui` auto-installs frontend dependencies when `ui/node_modules` is missing (unless `--skip-install` is set).
- `codevibes-ui` entrypoint now routes through `codevibes ui` so behavior stays consistent with CLI UI mode.
- Frontend dashboard now includes:
  - score/regression visualization
  - degradation source and fix-priority views
  - copyable raw JSON output
  - warnings and friendlier API error feedback
- README updated with UI runtime usage and frontend workspace structure.

### Fixed (1.1.0)

- Fixed Pylance type error in legacy `web_ui.py` where `top_files` could be inferred as `int | None`.
- Improved frontend API error messages for GitHub clone/network failures (connection reset, DNS, 443 access issues).
- Fixed diff noise issue where unchanged baseline comparisons could surface zero-impact source files.

## [1.0.0] - 2026-03-25

### Added (1.0.0)

- CLI subcommand: `codevibes scan <path-or-github-url>`
- Output formats: `text`, `markdown`, `json`
- Optional report export via `--output`
- GitHub URL scan via shallow clone
- Clone timeout control via `--clone-timeout`
- Webhook submit via `--submit-webhook` and `--submit-timeout`
- Submission metadata in webhook payload:
  - `project_path`
  - `submitted_at`
  - `tool_version`
- CI policy gates:
  - `--fail-on-risk`
  - `--fail-on-findings`
- Config loader for `.codevibes.json` with legacy compatibility
- `.gitignore` support and glob include/exclude filters
- Repo scorecard dimensions:
  - Risk Score
  - Naming Chaos Index
  - Structure Score
  - Complexity Score
  - Vibe Score
  - Overall Verdict
- Test suite coverage for scanner/scoring/formatter/CLI smoke paths

### Changed (1.0.0)

- Standardized relative paths in scan outputs and findings for better sharing in PR/issues
- Separated module responsibilities:
  - `scanner.py`: data collection
  - `scoring.py`: scoring and verdict
  - `formatter.py`: report rendering
  - `cli.py`: orchestration only

### Notes (1.0.0)

- Version source is package `__version__`.

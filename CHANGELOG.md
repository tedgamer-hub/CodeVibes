# Changelog

All notable changes to this project are documented in this file.

## [1.0.0] - 2026-03-25

### Added

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

### Changed

- Standardized relative paths in scan outputs and findings for better sharing in PR/issues
- Separated module responsibilities:
  - `scanner.py`: data collection
  - `scoring.py`: scoring and verdict
  - `formatter.py`: report rendering
  - `cli.py`: orchestration only

### Notes

- Version source is package `__version__`, currently locked at `1.0.0`.

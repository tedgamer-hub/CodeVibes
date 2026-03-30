# CodeVibes

Brutally honest repository analysis for local projects and GitHub repos.

`CodeVibes` scans a codebase, calculates engineering + "repo vibe" signals, and outputs a report in text, markdown, or JSON. It can also submit JSON to a webhook and enforce CI thresholds.

![CodeVibes Poster](./assets.picture/<img width="1834" height="857" alt="d5c74d2d-1299-4253-8006-b0c665006cd2" src="https://github.com/user-attachments/assets/42776ebf-a62e-456a-bc38-cd8d5e961f41" />
.png)

## 1.0.0 Scope

- Local path scan and GitHub URL scan (shallow clone to temp dir)
- Security findings and vibe findings in one report
- Core scores:
  - `Risk Score`
  - `Naming Chaos Index`
  - `Structure Score`
  - `Complexity Score`
  - `Vibe Score`
- One-line `Overall Verdict`
- Output formats: `text`, `markdown`, `json`
- Optional webhook submission
- Optional CI fail policies
- Config via `.codevibes.json`
- `.gitignore` + glob include/exclude support

## Install

Python 3.10+ is required.

```bash
pip install .
```

After install:

```bash
codevibes scan .
```

## CLI Usage

```bash
codevibes scan <path-or-github-url> [options]
```

### Arguments

- `path`: local project path, or `https://github.com/<owner>/<repo>`

### Options

- `--format {text,markdown,json}`: output format (default: `text`)
- `--top-files N`: number of top long files to show (default: `5`)
- `--max-findings N`: max findings shown in detail sections (default from config, fallback `50`)
- `--output PATH`: save report to file instead of stdout
- `--roast`: use more sarcastic verdict style
- `--fail-on-risk N`: exit non-zero when `risk_score >= N` (`0..100`)
- `--fail-on-findings N`: exit non-zero when `total_findings >= N`
- `--submit-webhook URL`: POST JSON report to webhook
- `--submit-timeout SECONDS`: webhook timeout (default: `10`)
- `--clone-timeout SECONDS`: git clone timeout for GitHub URL scans (default: `30`)

## Examples

```bash
codevibes scan .
codevibes scan . --format markdown
codevibes scan . --format json --output reports/latest.json
codevibes scan . --top-files 10 --max-findings 80
codevibes scan . --roast
codevibes scan . --fail-on-risk 70 --fail-on-findings 25
codevibes scan . --submit-webhook https://example.com/hook
codevibes scan https://github.com/user/repo --clone-timeout 45
```

## Exit Codes

- `0`: success
- `1`: input/scan/runtime error
- `2`: policy failure (`--fail-on-risk` or `--fail-on-findings`)
- `3`: webhook submission failure

## Config File: `.codevibes.json`

Put this file in project root to override defaults.

```json
{
  "included_extensions": [".py", ".ts", ".md"],
  "excluded_extensions": [".min.js"],
  "excluded_dirs": [".git", "node_modules", "dist"],
  "include_globs": ["src/**", "*.py"],
  "exclude_globs": ["coverage/**", "generated/**", "*.snap"],
  "respect_gitignore": true,
  "generic_folder_names": ["utils", "helpers", "common", "misc", "shared", "temp"],
  "suspicious_name_keywords": ["temp", "final", "backup", "copy", "new", "old", "test2"],
  "line_thresholds": {
    "medium": 300,
    "high": 500,
    "critical": 800
  },
  "max_findings_default": 50
}
```

Notes:

- `line_thresholds` and `oversized_file_line_thresholds` are both accepted.
- Extensions can be with or without leading dot.
- Legacy config filename from early builds is still supported.

## Webhook Payload

When `--submit-webhook` is set, JSON payload includes:

- `scan_report`
- `scorecard`
- `top_suspicious_files`
- `security_findings`
- `vibe_findings`
- `verdict`
- `submission_metadata`:
  - `project_path`
  - `submitted_at` (UTC ISO-8601)
  - `tool_version`

## Project Structure

```text
codevibes/
├─ main.py
├─ README.md
├─ pyproject.toml
└─ core package/
   ├─ __init__.py
   ├─ cli.py
   ├─ config.py
   ├─ models.py
   ├─ rules.py
   ├─ scanner.py
   ├─ scoring.py
   └─ formatter.py
```

## Development

Run tests:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

Local run without installation:

```bash
python main.py scan .
```

Backward-compatible shortcut is still supported:

```bash
python main.py .
```

Legacy CLI alias is still supported for compatibility.
test for yolo

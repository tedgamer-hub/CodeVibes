# CodeVibes v1.0.0

`CodeVibes` is now officially at 1.0.0.

This release turns the project into a practical CLI that can scan local repos or GitHub URLs, generate readable reports, and integrate with CI/webhooks.

## Highlights

- Scan local path or GitHub URL
- Output report as `text`, `markdown`, or `json`
- Export report to file with `--output`
- Scorecard includes:
  - Risk Score
  - Naming Chaos Index
  - Structure Score
  - Complexity Score
  - Vibe Score
  - Overall Verdict
- Webhook submission with metadata (`project_path`, `submitted_at`, `tool_version`)
- CI gating options:
  - `--fail-on-risk`
  - `--fail-on-findings`
- Configurable rules through `.codevibes.json` with legacy compatibility
- `.gitignore` and glob-based include/exclude support

## Quick Start

```bash
pip install .
codevibes scan .
codevibes scan . --format markdown
codevibes scan . --format json --output reports/codevibes.json
```

## CI Example

```bash
codevibes scan . --format json --fail-on-risk 70 --fail-on-findings 25
```

## Webhook Example

```bash
codevibes scan . --format json --submit-webhook https://example.com/hook
```

## Notes

- Python 3.10+ required.
- Git is required only when scanning GitHub URLs.

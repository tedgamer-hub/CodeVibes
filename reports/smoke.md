# Repo Vibes Report

## Project Overview
- Project: `repo-vibes`
- Path: `C:\Users\tedga\Desktop\LoneByte\repo-vibes`
- Duration: `9 ms`
- Scanned files: `12`
- Total lines: `1741`
- Max depth: `1`
- Total size: `61.82 KB`

## Core Scores
- Complexity Score: `84/100`
- Structure Score: `100/100`
- Naming Chaos Index: `0/100`
- Risk Score: `10/100 (low)`
- Vibe Score: `95/100`

## Overall Verdict
Overall healthy and maintainable. No major hotspot dominates yet; small cleanup now prevents big pain later.

## Top Suspicious Files
- `C:\Users\tedga\Desktop\LoneByte\repo-vibes\repo_vibes\formatter.py` - too large
- `C:\Users\tedga\Desktop\LoneByte\repo-vibes\repo_vibes\scoring.py` - too large
- `C:\Users\tedga\Desktop\LoneByte\repo-vibes\reports\repo-report.json` - contains risky patterns
- `C:\Users\tedga\Desktop\LoneByte\repo-vibes\repo_vibes\rules.py` - contains risky patterns

## Naming / Structure Notes
- Naming chaos signals: 0 suspicious paths, 0 filename keyword hits, 0 generic file names, 0 numeric suffix names.
- Structure pressure: 0 deep paths (>=4), 0 generic-folder hits, 3 root-level files.

## Top File Types
- `.py`: 8
- `.json`: 2
- `.toml`: 1
- `.md`: 1

## Top Long Files
- `C:\Users\tedga\Desktop\LoneByte\repo-vibes\repo_vibes\scoring.py` - 458 lines, 14.27 KB
- `C:\Users\tedga\Desktop\LoneByte\repo-vibes\repo_vibes\formatter.py` - 427 lines, 15.27 KB
- `C:\Users\tedga\Desktop\LoneByte\repo-vibes\reports\repo-report.json` - 297 lines, 8.76 KB
- `C:\Users\tedga\Desktop\LoneByte\repo-vibes\repo_vibes\scanner.py` - 236 lines, 6.87 KB
- `C:\Users\tedga\Desktop\LoneByte\repo-vibes\repo_vibes\cli.py` - 154 lines, 4.97 KB

## Risk Details
### Security Findings
- **Debug Markers** (5 shown)
  - (low) `C:\Users\tedga\Desktop\LoneByte\repo-vibes\reports\repo-report.json:145` | "snippet": "DEBUG_PATTERN = re.compile(r\"\\b(TODO|FIXME|HACK|XXX)\\b\")"
  - (low) `C:\Users\tedga\Desktop\LoneByte\repo-vibes\reports\repo-report.json:164` | "snippet": "DEBUG_PATTERN = re.compile(r\"\\b(TODO|FIXME|HACK|XXX)\\b\")"
  - (low) `C:\Users\tedga\Desktop\LoneByte\repo-vibes\reports\repo-report.json:189` | "snippet": "DEBUG_PATTERN = re.compile(r\"\\b(TODO|FIXME|HACK|XXX)\\b\")"
  - (low) `C:\Users\tedga\Desktop\LoneByte\repo-vibes\reports\repo-report.json:276` | "snippet": "DEBUG_PATTERN = re.compile(r\"\\b(TODO|FIXME|HACK|XXX)\\b\")"
  - (low) `C:\Users\tedga\Desktop\LoneByte\repo-vibes\repo_vibes\rules.py:79` | DEBUG_PATTERN = re.compile(r"\b(TODO|FIXME|HACK|XXX)\b")

### Repo Vibes Findings
- **Oversized Code File** (2 shown)
  - (medium) `C:\Users\tedga\Desktop\LoneByte\repo-vibes\repo_vibes\scoring.py` | 458 lines in a single file.
  - (medium) `C:\Users\tedga\Desktop\LoneByte\repo-vibes\repo_vibes\formatter.py` | 427 lines in a single file.
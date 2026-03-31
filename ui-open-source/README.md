# CodeVibes Frontend

React/Next.js UI for CodeVibes.

## Start

```bash
cd ui
npm install
npm run dev
```

Open `http://localhost:3000`.

The frontend calls `POST /api/scan`, which invokes the existing Python CLI:

```bash
python main.py scan <target> --format json
```

## Optional env vars

- `CODEVIBES_PYTHON`: python executable path (default: `python`)
- `CODEVIBES_ROOT`: repository root path (default: parent folder of `ui/`)


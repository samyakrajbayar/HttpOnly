# Lightweight Vulnerability Scanner Dashboard

HTTPSOnly is a full-stack security dashboard for quick pre-commit or pre-release checks. It accepts either a public website URL or a GitHub repository link, runs a lightweight scan, and returns a clean risk classification report with prioritized findings.

This project is intentionally safe and non-destructive. It performs passive HTTP checks, dependency version lookups, repository hygiene checks, and harmless reflected-parameter probes. It does not crawl aggressively, brute force, authenticate, exploit, or submit forms.

## Features

- URL scanning for common missing security headers:
  - `Content-Security-Policy`
  - `Strict-Transport-Security`
  - `X-Frame-Options`
  - `X-Content-Type-Options`
  - `Referrer-Policy`
  - `Permissions-Policy`
- Cookie flag checks for `HttpOnly`, `Secure`, and `SameSite`.
- Basic XSS surface review:
  - Detects forms with text-like inputs.
  - Sends one harmless marker query and reports if the marker is reflected.
- Mixed-content and broad CORS checks.
- GitHub repository scanning:
  - Reads public repository metadata and file tree.
  - Looks for `package.json` and `requirements.txt`.
  - Compares npm dependencies with the npm registry.
  - Compares pinned Python requirements with PyPI.
  - Flags loose dependency ranges, missing lockfiles, missing `SECURITY.md`, missing Dependabot config, committed `.env`-style files, and key-like filenames.
- Risk scoring with `Clean`, `Low`, `Medium`, `High`, and `Critical` classifications.
- Responsive React dashboard with category filters, evidence panels, dependency summaries, and severity badges.

## Tech Stack

- Frontend: React 19, Vite, lucide-react
- Backend: Node.js, Express, Cheerio, Semver, Zod
- Package management: npm workspaces

## Project Structure

```text
.
├── client/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── main.jsx
│   │   └── styles.css
│   ├── index.html
│   └── vite.config.js
├── server/
│   └── src/
│       ├── index.js
│       ├── demo-scan.js
│       └── scanner/
│           ├── http.js
│           ├── index.js
│           ├── repoScanner.js
│           ├── risk.js
│           ├── target.js
│           └── urlScanner.js
├── package.json
└── README.md
```

## Requirements

- Node.js 20.11 or newer
- npm 10 or newer
- Internet access for external website scans, GitHub API requests, npm registry checks, and PyPI checks

## Setup

Install all workspace dependencies from the project root:

```bash
npm install
```

Start the backend and frontend together:

```bash
npm run dev
```

Open the dashboard:

```text
http://localhost:5173
```

The Express API runs on:

```text
http://localhost:4000
```

## Useful Commands

Build the React app:

```bash
npm run build
```

Run the frontend linter:

```bash
npm run lint
```

Run a terminal demo scan:

```bash
npm run scan:demo -- https://example.com
```

Scan a GitHub repository from the terminal:

```bash
npm run scan:demo -- https://github.com/expressjs/express
```

Start only the API:

```bash
npm run start -w server
```

## API

### `GET /api/health`

Returns service health.

### `POST /api/scan`

Request body:

```json
{
  "target": "https://example.com"
}
```

Or:

```json
{
  "target": "https://github.com/expressjs/express"
}
```

Response shape:

```json
{
  "id": "scan-id",
  "target": "https://example.com/",
  "targetType": "url",
  "scannedAt": "2026-06-14T00:00:00.000Z",
  "durationMs": 832,
  "summary": {
    "score": 42,
    "classification": "Medium",
    "counts": {
      "critical": 0,
      "high": 1,
      "medium": 1,
      "low": 1,
      "info": 0
    },
    "totalFindings": 3
  },
  "status": {},
  "findings": [],
  "assets": {}
}
```

## How Risk Scoring Works

Each finding has a severity:

- `critical`: 35 points
- `high`: 25 points
- `medium`: 12 points
- `low`: 5 points
- `info`: 0 points

The total is capped at 100. The dashboard then maps the score to a classification:

- `Critical`: score is 70 or higher, or any critical finding exists
- `High`: score is 45 or higher, or any high finding exists
- `Medium`: score is 20 or higher, or any medium finding exists
- `Low`: score is above 0
- `Clean`: no scored findings

## Scanner Scope and Safety

This scanner is meant for developer hygiene and educational security review. It should be used only against systems and repositories you own or have permission to test.

The URL scanner:

- Fetches the target page.
- Reads response headers.
- Parses HTML locally.
- Sends one harmless query marker to detect reflection.
- Does not submit forms.
- Does not brute force paths.
- Does not exploit vulnerabilities.

The GitHub scanner:

- Works with public GitHub repositories.
- Uses the public GitHub API.
- Downloads supported manifests from `raw.githubusercontent.com`.
- Queries npm and PyPI for latest package versions.
- Limits dependency checks per manifest to keep scans fast.

## Environment Variables

Optional backend variables:

```bash
PORT=4000
CLIENT_ORIGIN=http://localhost:5173
```

If you deploy the frontend and backend separately, set `CLIENT_ORIGIN` to the deployed frontend origin.

- GitHub token support for higher API rate limits.
- `package-lock.json`, `pnpm-lock.yaml`, and `poetry.lock` exact-version scanning.
- OWASP ZAP integration for authorized deeper testing.
- Saved scan history with SQLite or Postgres.
- Exportable PDF or JSON reports.
- CI mode that fails builds above a configured risk threshold.

# TrailSight Dashboard — Design

Status: draft
Date: 2026-07-15

## Summary

A self-hosted web dashboard for TrailSight. You run `trailsight serve`, open the
page in a browser, upload a CloudTrail JSON file (or load the demo dataset), and
the findings are shown as severity-coloured cards instead of terminal text. It
runs entirely on the user's machine and keeps the project's ethos: nothing is
sent anywhere, and the core engine stays dependency-free.

## Goal

Give small AWS users a clearer, friendlier way to read scan results than the
plain-text CLI output, without adding infrastructure. The dashboard is a
presentation layer on top of the existing, tested detection engine.

## How it runs

- A new CLI command, `trailsight serve`, starts a Flask server bound to
  `127.0.0.1:5000` (localhost only, so logs are never exposed on the network).
- Flask is an optional dependency: `pip install trailsight[dashboard]`. The core
  engine and CLI keep working with no extra dependencies for anyone who only
  wants the command line.
- The `serve` command lazy-imports the dashboard, so importing the core package
  never requires Flask.

## Data flow

1. Browser loads the landing page with an upload area and a "Load demo data"
   button.
2. The user uploads a CloudTrail JSON file (or clicks demo).
3. The server parses the file in memory, runs the existing detection engine, and
   renders a results page.
4. Nothing is written to disk; the uploaded data is discarded after rendering.

## Architecture

A new optional subpackage `src/trailsight/dashboard/`, imported only when
serving.

- **`dashboard/app.py`** — a Flask application factory `create_app()` with three
  routes:
  - `GET /` renders the landing/upload page.
  - `POST /scan` reads the uploaded file, runs detection, renders results.
  - `GET /demo` loads the synthetic dataset and renders results.
- **`events_from_records(records)`** — a small helper added to `events.py` that
  turns already-parsed CloudTrail records into `Event` objects, reusing
  `event_from_record`. This lets the dashboard feed uploaded data straight into
  the existing `run_rules()` without duplicating any detection logic or touching
  disk.
- **`cli.py`** gains a `serve` subcommand that lazy-imports the dashboard and
  runs it, with `--port` and `--host` options (defaulting to localhost).
- **Templates and assets** — Jinja templates under `dashboard/templates/`
  (`base.html`, `index.html`, `results.html`) and static files under
  `dashboard/static/` (`style.css`, `app.js`). No build step; `app.js` only
  handles the severity filter.

The detection engine is unchanged. The dashboard imports and calls it.

## Page states

- **Landing** — header, an upload area (drag-and-drop or file picker), and a
  "Load demo data" button.
- **Results** — a header summary showing the total finding count and a count per
  severity, a severity filter, and one card per finding (most severe first).
  Each card shows the title, rule, identity, and description, with a toggle that
  expands the triggering CloudTrail events as evidence.
- **Clean** — when a scan produces no findings, a reassuring "no findings" panel
  instead of cards.
- **Error** — an invalid or non-CloudTrail upload shows a clear message on the
  page ("that does not look like a CloudTrail export"), never a server error.

## Visual direction

A dark theme suited to a security tool, with a severity colour system
(critical, high, medium, low), readable typography, and clear spacing so the
page stays scannable. The specific palette, type, and layout polish are decided
during implementation with the frontend-design skill; this spec fixes the
structure and states, not the exact styling.

## Error handling

- Uploads that are not valid JSON, or valid JSON without CloudTrail records, are
  caught and shown as a friendly message on the page.
- A file size limit guards against very large uploads.
- The server binds to localhost only.

## Testing

Flask's test client drives the routes. Tests skip cleanly when Flask is not
installed.

- `GET /` returns 200 and contains the upload prompt.
- `POST /scan` with the synthetic dataset returns a page containing all six
  finding types and the severity summary.
- `GET /demo` renders findings.
- A scan of empty records shows the clean state.
- A garbage upload shows the error message, not a 500.
- `events_from_records` produces the same events as loading the equivalent file.

## Packaging

- Add an optional dependency group: `dashboard = ["flask>=3"]`.
- The `trailsight serve` entry works only when the dashboard extra is installed;
  running it without Flask prints a clear message telling the user to install
  `trailsight[dashboard]`.

## Non-goals

- No accounts, authentication, or multi-user support. It is a local tool.
- No persistence or database. Each scan is independent.
- No continuous ingestion or auto-refresh yet; that remains a later step.
- No scanning of multiple files at once.

## Success criteria

- `trailsight serve` opens a working dashboard on localhost.
- Uploading a CloudTrail file shows the same findings the CLI produces, as
  readable severity-coloured cards with expandable evidence.
- The core engine and CLI still install and run with no extra dependencies.
- Every route is covered by a test, and the suite passes with and without Flask
  installed.

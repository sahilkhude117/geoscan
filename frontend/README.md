# GeoScan frontend handoff

This is the frontend teammate's starting point: an official Next.js App Router template with TypeScript, React and Tailwind, a working scan form, a typed API client, and a polling hook. Build the dashboard on top of these integrations. The Rust backend already handles scanning, jobs, validation, persistence and reproduction commands.

Read `AGENTS.md` and the relevant installed Next.js guides before changing Next.js code. This template uses Next.js 16.3.5 / React 19.2.8 and TypeScript 5. The build uses TypeScript's JavaScript compiler API; reconsider `experimental.useTypeScriptCli` if upgrading to TypeScript 7.

## Start the whole project

Use separate terminals. Backend commands run from the **repository root**, not from `frontend/`, so the API shares the CLI's `geoscan.db`.

Prerequisites: Rust supporting edition 2024, Docker Compose, Python 3, a working `nuclei` executable for CVE checks, and Node.js **22.18+** for the TypeScript client tests (Next.js itself supports 20.9+). Configuration-only scans use the built-in Rust HTTP probes and do not require Nuclei. Use `geoscan doctor` if your CLI is already installed.

### 1. Start the existing demo target (repository root)

```bash
docker compose --profile sqli-demo up -d --wait
python3 scripts/setup_sqli_demo.py
```

The setup script asks for the GeoServer administrator password and publishes `geoscan_sqli_demo:items`, containing the String attribute `json_data`, from the demo PostGIS database. Give GeoServer time to become ready if the script cannot connect. These commands prepare a **local target**; the database is not the scanner's SQLite database.

The application does not provision GeoServer or upload layers when starting a scan. On a different deployment, provide an existing public PostGIS layer/property instead. A missing demo layer causes the SQLi check to be skipped, not a finding.

### 2. Start the Axum backend (repository root)

```bash
cargo run -p geoscan-api --locked -- --db ./geoscan.db
```

The API listens on **http://127.0.0.1:8787**. SQLite history and configuration checks are available even if the CVE scanner executable is missing; `/health` exposes `scanner.available`. After installing or changing that executable, restart the API to refresh this startup diagnostic.

To select another binary, database, port, or allowed target:

```bash
cargo run -p geoscan-api --locked -- \
  --bind 127.0.0.1:8787 \
  --db ./geoscan.db \
  --nuclei nuclei \
  --allow-target http://127.0.0.1:8080/geoserver \
  --allow-target https://your-own-server.example/geoserver
```

Equivalent process environment variables: `GEOSCAN_BIND`, `GEOSCAN_DB`, `GEOSCAN_NUCLEI`, and `GEOSCAN_ALLOWED_TARGETS` (comma-separated application URLs). The Rust process does **not** load `.env` automatically. The default allowed target is `http://127.0.0.1:8080/geoserver/`; `localhost` is a different host and needs its own allowed entry.

The API is a local, single-instance development service, with one active scan at a time and loopback binding. Run one API process per database. Internet hosting, user accounts and a distributed job queue are later work. Do not publish this development service as a public scanner.

### 3. Start this frontend (another terminal)

```bash
cd frontend
cp .env.example .env.local
npm ci
npm run dev
```

Open **http://127.0.0.1:3000**. The starter fetches API health and existing CLI scan history, submits real scans, polls job status, and renders the saved report with finding severity, CVSS, remediation and reproduction commands. It uses real responses; it does not insert fake findings.

`GEOSCAN_API_URL` configures Next.js's server-side rewrite to Axum. Browser requests use relative `/api/v1/...` URLs, so no browser CORS configuration is needed. Keep this environment variable server-only; do not rename it to `NEXT_PUBLIC_...`. Restart development after changing it; rebuild for a changed production proxy destination. The proxy allows up to 65 seconds for detection; scan submission itself returns immediately.

## What the frontend teammate owns

Replace the starter layout in `src/app/page.tsx` with the dashboard. Reuse:

| File | Purpose |
| --- | --- |
| `src/lib/api-types.ts` | Complete TypeScript wire types, preserving Rust's snake_case JSON fields |
| `src/lib/api.ts` | API methods, error normalization, validated pagination/IDs, and bounded polling |
| `src/hooks/use-scan.ts` | Start/resume a job, update its status, fetch its report, and clean up polling on unmount |
| `next.config.ts` | Server-side `/api/v1` proxy to the Rust process |
| `.env.example` | Local proxy configuration |
| `tests/api.test.ts` | Client contract/lifecycle checks without a live server |

Suggested screens: target/login form, scan progress, findings with expandable reproduction steps, saved scan history, and check catalogue. Add the optional advanced `sqli_layer` and `sqli_property` inputs for real deployments. The starter now includes configuration-only mode, deployment context, and declared private layers. The factory-login check runs automatically on every scan. Use `/health` for allowed targets, defaults and supported check IDs. Style these screens freely while preserving the contract below.

The Rust implementation is in `../crates/geoscan-api/src/` (HTTP transport), `../crates/geoscan-core/src/web/` (durable background jobs), and `../crates/geoscan-core/src/scan.rs` (shared scanner/report reader). SQLite belongs to Rust; the Next.js app should use HTTP instead of opening the database or spawning the scanner.

## HTTP contract: `/api/v1`

All successful responses are JSON. Every API response has `Cache-Control: no-store`. Request bodies must use `Content-Type: application/json`, fit within 16 KiB, and contain only documented fields.

| Method | Path | Response |
| --- | --- | --- |
| GET | `/health` | `Health`: startup scanner availability, allowed targets, defaults, coverage |
| GET | `/checks` | `Catalog`: CVE `items`, CVE `supported_checks`, and implemented `misconfigurations` |
| POST | `/detect` | `Detection`: GeoServer identity/version, WMS/WFS availability and evidence; does not start a vulnerability scan |
| POST | `/scans` | **202** `Job`, with `Location: /api/v1/jobs/{id}` |
| GET | `/jobs/{id}` | `Job`: poll a submitted job |
| GET | `/jobs?limit=25&offset=0` | `Page<Job>`: find active/previous web jobs after a page reload |
| GET | `/scans?limit=25&offset=0` | `Page<ScanSummary>`: shared CLI/API scan history, newest first |
| GET | `/scans/{id}` | `ScanReport`: saved findings, checks, evidence, fixes and reproduction commands |

IDs are positive integers. `limit` is 1–100; `offset` is nonnegative. List defaults are 25/0. A page contains `items`, `total`, `limit`, and `offset`; there is no implicit infinite list.

### Submit or detect a target

Both POST endpoints accept `ScanInput`:

```json
{
  "target": "http://127.0.0.1:8080/geoserver",
  "sqli_layer": "geoscan_sqli_demo:items",
  "sqli_property": "json_data"
}
```

Only `target` is required. Omit the SQLi fields to use the values from `health.defaults`. Optional `username` and `password` must both be present and nonempty, or both omitted/null. Blank UI inputs should be omitted. This supplied login is used only to identify the GeoServer version. Credentials are never saved in jobs, scan history or reports, and are not forwarded to the scanning engine or configuration probes. Every scan includes a check for the fixed factory admin/geoserver login, with at most one authentication attempt after an anonymous-denied baseline. Clear the password field after submission; do not put it in browser storage, URLs or logs.

## Configuration checks

Default scans run the two existing CVE probes and eleven configuration assessments. Private-layer and production-transport assessments require a declared policy, so a recorded check is not necessarily an executed probe. These findings have project-assigned risk severity; no CVSS score or CVE number is invented.

| ID | Assessment | Activation |
| --- | --- | --- |
| `GS-MISC-001` | Factory admin/geoserver credentials, with an anonymous-denied baseline | Every scan; at most one authentication attempt |
| `GS-MISC-002` | Anonymous workspace REST configuration reads | Default |
| `GS-MISC-003` | Anonymous named GeoWebCache layer configuration reads | Default; public tile access alone is not a finding |
| `GS-MISC-004` | Anonymous REST status/system diagnostics | Default |
| `GS-MISC-005` | Java implementation, SQL or internal-path leakage in a bounded invalid WFS request | Default |
| `GS-MISC-006` | Known private configuration/backup files or a data-directory index | Default; four fixed application-relative paths |
| `GS-MISC-007` | Anonymous GeoJSON access to existing layers declared private | Operator names up to five private layers |
| `GS-MISC-008` | Reflection of two untrusted origins with credentialed CORS on a configuration route | Default; proves header policy, not authenticated data access |
| `GS-MISC-009` | Production HTTP without HTTPS enforcement, or missing positive HSTS on HTTPS | Explicit production context; HSTS absence is rated Low |
| `GS-MISC-010` | Session-cookie HttpOnly/Secure/SameSite=None weaknesses | Default; Secure is required on HTTPS, not a plain-HTTP localhost lab |
| `GS-MISC-011` | Enforced CSP, framing restrictions and nosniff on administration HTML | Default; CSP frame-ancestors can replace X-Frame-Options |

Ordinary public WFS/WMS layers and wildcard CORS on public maps are not automatically vulnerabilities. Missing SameSite alone is not a finding. Lab/unspecified deployment contexts skip production transport assessment. Selecting production explicitly applies that policy even to a loopback test target. Login pages/errors/soft 404s must not be mistaken for successful configuration or feature responses.

Probe limits: GET requests only, at most five per second, five-second request timeout, 64 KiB response limit, and a forty-second overall configuration budget. Only same-application administration-page redirects are followed, at most twice; external or HTTPS-upgrade redirects are assessed without following them. Probes do not use an ambient HTTP proxy. Private-layer reads request at most one feature. Response bodies, cookie values, configuration secrets and feature values are not retained in evidence. Timeout/unsupported responses remain inconclusive instead of becoming clean results.

From the repository root, install/update the CLI and run configuration checks:

```bash
cargo install --path crates/geoscan --locked --force
geoscan misconfigurations
geoscan scan --only-misconfigurations
```

The target and optional version login use the existing prompts. The factory-login check is mandatory in both ordinary and configuration-only scans; it has no CLI flag, API toggle or frontend checkbox. If the anonymous baseline is already accessible, the factory-login result is inconclusive because that response cannot prove authentication worked; the anonymous configuration exposure is assessed separately. Historical jobs containing the old opt-in flag remain readable.

For an existing layer that should be protected:

```bash
geoscan scan --target http://127.0.0.1:8080/geoserver --no-input \
  --only-misconfigurations --private-layer private_workspace:confidential_layer
```

Repeat `--private-layer` for additional names (maximum five; no duplicates). Do not mark the intentionally public SQLi demo layer private just to create a finding. Add `--deployment production` when assessing a deployment against production transport requirements, or `--deployment lab` to state lab context.

The same options are accepted through POST `/scans` in the optional nested `misconfigurations` object:

```json
{
  "target": "http://127.0.0.1:8080/geoserver",
  "misconfigurations": {
    "only_misconfigurations": true,
    "private_layers": [],
    "deployment": "lab"
  }
}
```

All option fields have defaults: false, false, empty array, `unspecified`. Unknown fields are rejected. Selected options are saved with the job, without version-login credentials. Jobs from the earlier schema are migrated with default options. GET `/health` adds `supported_misconfiguration_checks`; `supported_checks` continues to mean executable CVE checks. GET `/checks` adds the `misconfigurations` definition array while keeping the CVE `items` unchanged.

Each finding/check now has `check_id` and `kind` (`cve` or `misconfiguration`). `cve_id` remains the CVE ID for CVE findings and is **null** for configuration findings. Check results also have nullable `severity`. Use `check_id` for labels/keys and `kind` for classification. Configuration findings have `cvss: []`; show the supplied risk severity without a numerical CVSS label. `advisory_url` points to configuration guidance for these findings. Old CVE reports are enriched with their identifiers when read; earlier report/check data remains usable.

`report.not_run` counts omitted **CVE catalogue entries only**, never subtracting configuration checks from CVE coverage. Overall status includes both check types and retains partial findings. Missing Nuclei in a mixed scan records failed CVE checks while still running configuration checks. Configuration-only mode skips CVE requests and the Nuclei version check. A `no_match` result covers only the fixed endpoints and declared layers examined.

Targets must be complete HTTP(S) application URLs with no embedded credentials, query or fragment. Rust normalizes the trailing slash and checks the backend's exact allowed-target list. The browser cannot choose an executable, database path, template or shell command. SQLi layer/property identifiers use the same validation as the CLI.

### Follow a scan

`POST /scans` creates a durable job and returns before scanning completes:

```json
{
  "id": 12,
  "state": "queued",
  "target": "http://127.0.0.1:8080/geoserver/",
  "sqli_layer": "geoscan_sqli_demo:items",
  "sqli_property": "json_data",
  "scan_id": null,
  "outcome": null,
  "error": null,
  "created_at": "2026-10-13T10:00:00Z",
  "started_at": null,
  "finished_at": null
}
```

This is an example response, not a fixture inserted by the application.

Poll `/jobs/12` roughly every 1.5 seconds. A job transitions `queued → running → completed`, or ends `failed` / `interrupted`. When `completed`, fetch `/scans/{job.scan_id}`. **Job IDs and scan IDs are different sequences**; do not assume `/scans/12` is its report. `scan_id` may become available during execution, but reading a still-running report returns `409 scan_running`.

`completed` means a report was produced. Its `outcome` can still be `partial`, `failed`, or `inconclusive`; show the report's per-check details. Early detection/engine failures produce a `failed` job with a safe error message and possibly no scan ID. After an unclean restart, unfinished jobs become `interrupted`; submit a new scan explicitly.

One job may run at a time; overlapping submissions return `409 scanner_busy`. Each job has a 240-second execution limit. Browser polling stops after 300 seconds, but stopping/unmounting the page **does not cancel** the backend job. Use `/jobs` or `resume(id)` after a reload/timeout. Never automatically retry a POST: it may already have created a job. There is no cancellation endpoint or live percentage/check-by-check event stream in v1. Display actual job states instead of invented progress percentages.

### Use the existing client and hook

```tsx
"use client";
import { useScan } from "@/hooks/use-scan";

export function ScanButton() {
  const { start, busy, job, report, error } = useScan();
  return (
    <div>
      <button disabled={busy} onClick={() => start({
        target: "http://127.0.0.1:8080/geoserver"
      })}>Start scan</button>
      <p>{job?.state}</p>
      {error && <p role="alert">{error}</p>}
      {report && <p>{report.findings.length} findings</p>}
    </div>
  );
}
```

For custom hooks, call `api.startScan(input)`, `waitForJob(job.id, { signal, onUpdate })`, then `api.report(finished.scan_id)`. `api.health`, `api.detect`, `api.checks`, `api.jobs` and `api.scans` are also available. Use an `AbortController` for read/poll requests and clean it up when the component unmounts.

## Display results accurately

`ScanReport` has `id`, `target`, nullable `geoserver_version`, `version_note`, `status`, `reported_events`, `not_run`, `checks`, and `findings`. Its types are defined in `api-types.ts`.

| Result status | UI meaning |
| --- | --- |
| `matches` | Evidence matched; manual verification is still needed |
| `no_match` | The checks run found no matching evidence |
| `partial` | Some checks completed and others failed/were inconclusive; retain findings |
| `inconclusive` | No reliable final outcome; show notes/errors |
| `not_applicable` | Required layer/property/service prerequisites were absent |
| `failed` | A scan/check failed; show its error |
| `running` | A persisted scan has not finished |

Each check has `check_id`, `kind`, nullable `cve_id`/`severity`, `status`, `ran`, `matches`, `reported_events`, `note`, `diagnostics`, and nullable `error`. Show notes for skipped/incomplete checks. A catalogue/version match is potential exposure, not a confirmed finding. **32 CVE catalogue entries currently exist; two CVE checks and eleven configuration assessments are implemented.** Use the two supported-check lists to label coverage and `not_run` for omitted CVEs. Never translate zero findings or a skipped check into “this server is secure.” Older CLI reports can have no recorded per-check coverage.

Each finding includes severity (`critical`, `high`, `medium`, `low`), an ordered `cvss` array with source links, `description`, `matched_at`, `evidence`, `remediation`, `advisory_url`, and `reproduction`. The first CVSS rating determines CVE severity; retain alternative sourced scores in details. Configuration risk has no numeric CVSS rating. Each reproduction step has `title`, `command`, and `expected`. Display commands in a scrollable `<pre>`, offer copying, and preserve the exact string. The factory-login reproduction prompts for its known factory password; it never embeds the operator's supplied password. The app must not execute these shell commands in the browser. Render all returned text as text, not HTML.

The SQLi match demonstrates a generated-SQL quoting error on a selected public PostGIS layer, not arbitrary SQL execution. HTTP 200 can contain an XML service exception. The normal/probe reproduction steps explain the expected differences.

Job timestamps use ISO UTC (`...Z`). Older scan-summary timestamps use SQLite UTC (`YYYY-MM-DD HH:MM:SS`); normalize them to UTC before browser formatting. JSON download can use `JSON.stringify(report, null, 2)` in a Blob; this is the same report the CLI displays.

### Errors

Errors have this shape:

```json
{"error":{"code":"scanner_busy","message":"A scan is already running or the API is shutting down"}}
```

`ApiError` exposes `status`, `code`, and `message`. Important codes: `invalid_request` (400), `invalid_json` (400/413/415/422 depending on parsing), `target_not_allowed` (403), `not_found` (404), `method_not_allowed` (405), `scanner_busy` / `scan_running` (409), `database_error` / `catalog_error` / `report_error` (500), and `detection_failed` (502). The client also produces `api_unreachable`, `invalid_response` and `poll_timeout`. Proxy failures may return non-JSON; the client handles those too.

## Smoke test without the frontend

Run from any terminal while Axum is running:

```bash
curl -sS http://127.0.0.1:8787/api/v1/health
curl -sS 'http://127.0.0.1:8787/api/v1/scans?limit=25&offset=0'
curl -i -X POST http://127.0.0.1:8787/api/v1/scans \
  -H 'Content-Type: application/json' \
  -d '{"target":"http://127.0.0.1:8080/geoserver"}'
```

Use the returned **job ID** in `GET /api/v1/jobs/{id}`, then its **scan_id** in `GET /api/v1/scans/{scan_id}`. Existing CLI reports, including your matched SQLi scan, appear immediately in history when both processes use the same database.

## Checks before handing off UI work

```bash
# Repository root; first build fetches any newly needed Axum packages.
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check

# frontend/
npm ci
npm run typecheck
npm run lint
npm test
npm run build
```

`npm run build -- --webpack` is available when a restricted environment cannot open the local sockets used by Turbopack's CSS workers. Builds do not download Google Fonts; the starter uses system fonts.

Configuration-check verification: 97 Rust CLI/core and background-job tests passed, including automatic factory-login checks, configuration probes, evidence redaction, saved reports and historical job-options compatibility; one optional real-Nuclei HTTP test remains ignored. Frontend TypeScript and lint checks passed. Rust checks ran in an isolated workspace excluding the HTTP adapter, whose crate archives were not cached and whose package-registry downloads were blocked. The Axum HTTP adapter and live API/UI integration remain unverified in this session. Run the full workspace commands above and the live smoke test on your development machine before treating HTTP integration as verified.

CVE probes use Nuclei as their HTTP execution engine. Configuration probes use bounded Rust HTTP requests for context-dependent header/cookie and access assessments. GeoScan's Rust code owns scope/parameter validation, reviewed template selection, evidence validation, job lifecycle, database persistence and reports. Credit the engine in the project's technical explanation while keeping the UI branded GeoScan. Live API/UI testing and access control remain later project work.

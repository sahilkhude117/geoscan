# GeoScan

A Rust CLI for identifying GeoServer and comparing its release version with a
researched CVE catalogue. The shared `geoscan-core` crate will also support a future
web backend. `doctor` checks SQLite access and the Nuclei installation. `scan`
runs reviewed REST-index and PostGIS JSON-filter checks and stores per-CVE
outcomes in SQLite. `report` displays a saved scan without sending requests.

## Run the CLI

Run these commands from the project root:

```sh
cargo run -p geoscan -- --help
cargo run -p geoscan -- detect --target http://127.0.0.1:8080/geoserver
cargo run -p geoscan -- checks list
cargo run -p geoscan -- checks show --id CVE-2025-30220
cargo run -p geoscan -- checks list --json
cargo run -p geoscan -- checks assess --geoserver-version 2.28.2
cargo run -p geoscan -- checks assess --geoserver-version 3.0.1
cargo run -p geoscan -- checks assess
```

`checks assess` uses the supplied GeoServer version and makes no network requests.
Pass the release reported by `detect` or your deployment configuration.
Omitting the version gives an unknown assessment.

To install or update the `geoscan` command on your PATH:

```sh
cargo install --path crates/geoscan --locked --force
geoscan checks list
geoscan checks show --id CVE-2025-58360
geoscan checks assess --geoserver-version 2.28.2
geoscan report
```

Export metadata for another program or the future web backend:

```sh
geoscan checks list --json > cves-export.json
```

JSON export contains only a JSON array, with no human-readable banner.
Unknown CVE IDs passed to `checks show` exit with an error.

## Run the CVE checks

After rebuilding the installed command, run these commands from the project root:

```sh
docker compose up -d
geoscan scan --help
geoscan doctor --db geoscan.db
geoscan detect --target http://127.0.0.1:8080/geoserver
geoscan scan --target http://127.0.0.1:8080/geoserver --db geoscan.db
```

Allow GeoServer to finish starting before running detection or scanning. Nuclei
must be installed and on your PATH; alternatively, pass `--nuclei /path/to/nuclei`.

For interactive setup, just run:

```sh
geoscan scan
```

The terminal prompts for the target URL (defaulting to your Docker deployment),
an optional username, and a hidden password when login is selected. Press Enter
at the username to skip login. Invalid URLs are prompted again. Provided flags
fill their corresponding fields, so `geoscan scan --username admin` prompts for
the target and password without asking for the username again.

Credentials are used only to detect the release through
`rest/about/version.json`; both CVE probes remain unauthenticated.
Credentials are not saved in SQLite or passed to Nuclei. The scan output includes
the detected version and its detection status.

For scripts, use `--no-input`. An authenticated version lookup also requires
`GEOSCAN_PASSWORD` in the environment; there is no password command-line flag.

```sh
geoscan scan --no-input --target http://127.0.0.1:8080/geoserver
# With GEOSCAN_PASSWORD already set by your shell or CI secret store:
geoscan scan --no-input --target http://127.0.0.1:8080/geoserver --username admin
```

Without a terminal, supplied flags are used without prompting. A missing target
or a username without a password fails before any scan request is made.

This command identifies GeoServer and supports two reviewed checks:

- **CVE-2025-27505:** GET-based detection of REST-index exposure at `/rest.html`.
- **CVE-2026-76904:** a WFS schema preflight followed by two GET requests that
  compare a valid `jsonArrayContains` filter with an apostrophe-containing value.
  A match requires a successful GeoJSON baseline and a PostgreSQL or PostgreSQL
  JDBC quoting error in the second response. This reports SQL-generation error
  evidence and requires verification; no additional SQL statements, delays, or
  file operations are sent.

With prepared statements enabled, the apostrophe probe can return an
`Unterminated identifier ... in SQL SELECT ... jsonb_path_exists(...)` exception.
This PostgreSQL JDBC parser error is recognized even when the response omits the
`PSQLException` class name. The matcher still requires a successful baseline,
an OGC exception response, and the expected quote-error and SQL/function context.
Such a failure can occur before the database executes the query, so a match does
not establish arbitrary SQL execution. See the
[PostgreSQL JDBC parser](https://github.com/pgjdbc/pgjdbc/blob/master/pgjdbc/src/main/java/org/postgresql/core/Parser.java).

The SQLi check selects `geoscan_sqli_demo:items` and its String attribute
`json_data` by default. Use `--sqli-layer workspace:layer --sqli-property field`
for another published PostGIS layer with JSON stored in a String-mapped attribute.
The schema preflight cannot establish the underlying database type or version;
the comparison checks observable response behavior. It covers only the selected
layer and attribute. Only scan deployments you own or have permission to assess.

The other 30 catalogue entries have no implemented active probe. If the selected
layer or String attribute is unavailable, the SQLi probe is skipped and the
printed catalogue entries not run count is 31.

- `matches`: the response matched the exposure template; verify the finding.
- `no_match`: the engine completed without reporting an error and returned a
  negative matcher result for this check. Nuclei omits `matched-at` for these
  results; GeoScan accepts them without requiring a positive-match URL.
- `inconclusive`: the engine returned no request outcome; exit code 2.
- `not_applicable`: a required layer or String attribute is missing; no SQLi
  template is run.
- `failed`: an engine check failed; its error is saved with that CVE.
- Overall `partial` means a completed check and an incomplete or failed check;
  findings from the completed check are retained, and the CLI exits with code 2.
- A wholly failed scan or a setup failure exits with code 1.

Overall `matches` and `no_match` both exit with code 0. These results cover the
probes actually run and do not establish whether the deployment is secure overall.

View stored outcomes without a history command:

```sh
sqlite3 -header -column geoscan.db 'SELECT id, target, check_id, status, reported_events, error FROM scans ORDER BY id DESC;'
sqlite3 -header -column geoscan.db 'SELECT scan_id, cve_id, status, matched_count FROM scan_checks ORDER BY scan_id DESC, cve_id;'
sqlite3 -header -column geoscan.db 'SELECT scan_id, cve_id, matched_at FROM findings ORDER BY id DESC;'
```

Each new scan stores one row per supported CVE in `scan_checks`, including skipped
checks. Existing scan rows and findings are preserved; old records do not gain
invented per-check outcomes. The legacy `scans.check_id` column stores the two
supported IDs separated by a comma for new scans. Notes and diagnostics are in
`scan_checks.details_json`.

## Readable reports and reproduction steps

`scan` and `report` use the same terminal layout: a summary card, a compact table
of check results, and a finding card for each match. Findings show the vulnerability
name, severity, sourced CVSS scores, evidence, remediation, advisory, and manual
reproduction commands with expected responses. Commands use the saved target,
selected layer, and attribute. The baseline and apostrophe probe remain GET requests.

```sh
geoscan report                      # Latest saved scan; no scan requests
geoscan report --scan-id 7          # Your successful SQLi demo scan
geoscan report --scan-id 7 --json > scan-7.json
NO_COLOR=1 geoscan report --scan-id 7
```

Colors are enabled for supported terminals and disabled when output is redirected
or `NO_COLOR` is set. Metadata wraps to the terminal width. The narrower layout
stacks check results; copyable reproduction commands retain their exact contents.
The severity column describes each CVE; the severity summary counts matched
findings only. `NO MATCH`, `SKIPPED`, `INCONCLUSIVE`, and `FAILED` remain distinct.

JSON reports include `findings[].cvss`, `description`, `evidence`, `remediation`,
`advisory_url`, and `reproduction[]` (`title`, `command`, `expected`). These are
shared backend data for the future React UI. New findings save these fields in
`findings.details_json`. Reading an older scan regenerates metadata and commands
from the bundled catalogue and saved match URL, preserving the original database.
Older scans without per-check records show that coverage was not recorded.

To export a new scan, supply the target explicitly:

```sh
geoscan scan --target http://127.0.0.1:8080/geoserver --json > scan.json
```

`--json` disables prompts and progress text. Use `GEOSCAN_PASSWORD` with
`--username` if an authenticated version lookup is needed. Saved reports do not
need credentials or a running GeoServer. The `report` command exits successfully
when a report is displayed, including saved scans that were partial or failed;
`scan` keeps its existing outcome-based exit codes.

## Exercise CVE-2026-76904 on GeoServer 2.28.2

GeoServer **2.28.2** is within this CVE's affected range, but the deployment must
publish a qualifying PostGIS layer. The base image's sample layers alone do not
establish that prerequisite. The optional demo keeps your GeoServer version and
adds a PostgreSQL 16/PostGIS service with two synthetic rows and a limited,
read-only database login.
Source: [GeoServer advisory](https://github.com/geoserver/geoserver/security/advisories/GHSA-jvpx-6qxg-whgc).

These commands use this project's Docker Compose network:

```sh
docker compose --profile sqli-demo up -d --wait
python3 scripts/setup_sqli_demo.py
cargo install --path crates/geoscan --locked --force
geoscan scan
```

Wait until your GeoServer web page opens before running setup. The setup script
uses Python's standard library, prompts for the GeoServer administrator password
(or reads `GEOSCAN_PASSWORD`), and creates the demo workspace, datastore, and layer.
It supports `--target` and `--username`, accepts only local targets, and does not
overwrite existing resources that belong to another configuration. Rerunning it
reuses the matching demo resources. The PostgreSQL service has no published host
port; its fixed credentials are for this learning lab only.

For an unpatched 2.28.2 deployment with the demo available, the expected pattern is:

```text
[no_match] CVE-2025-27505 (0 matches)
[matches] CVE-2026-76904 (1 matches)
```

These are expected outcomes, not a claim that a live Docker scan was verified in
the restricted development environment. A locally patched library, protected WFS,
different error handling, or unsupported function evaluation can change the result.
Keep the match evidence and per-check diagnostics when investigating a difference.
The scan requests leave the demo configuration and data unchanged.

## Classroom demonstration

The issue is **CVE-2026-76904**, a SQL-injection vulnerability in GeoTools' PostGIS
implementation of `jsonArrayContains`. GeoServer accepts an ordinary WFS filter
and uses GeoTools to turn it into a SQL query. On affected releases, the filter's
expected value can reach the SQL string without the needed escaping. An apostrophe
inside ordinary data can therefore change SQL syntax. The CVE record rates it
**9.8 Critical**; GeoServer's advisory records **9.1 Critical**. The report keeps
both scores with their sources instead of averaging them. GeoServer 2.28.2 is in
the affected branch; the first fixed 2.28 release is 2.28.5.
Sources: [CVE record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/76xxx/CVE-2026-76904.json),
[GeoServer advisory](https://github.com/geoserver/geoserver/security/advisories/GHSA-jvpx-6qxg-whgc).

The project uses the following lab:

| Component | Role |
| --- | --- |
| GeoServer 2.28.2 | Exposes WFS at `http://127.0.0.1:8080/geoserver/wfs` |
| PostgreSQL 16 with PostGIS | Stores two synthetic points and JSON text |
| `geoscan_reader` | Limited database login with SELECT access and read-only transactions |
| `geoscan_sqli_demo:items` | Published WFS layer backed by `geoscan.items` |
| `json_data` | String attribute with values such as `{"a":["x"]}` |
| Rust CLI and shared core | Validate inputs, identify GeoServer, orchestrate checks, build reports |
| Nuclei | Runs the two reviewed HTTP requests and response matchers |
| SQLite | Stores scan, per-check, and finding records in `geoscan.db` |

Both containers share this project's Compose network. GeoServer connects to the
database using the internal name `postgis-demo`; PostgreSQL has no published host
port. `lab/postgis/init.sql` creates the demo rows and limited database role.
`scripts/setup_sqli_demo.py` uses an administrator login to publish the workspace,
datastore, and layer; scanning uses public WFS access afterward.

1. Start the containers and wait for the GeoServer web page to load:

   ```sh
   docker compose --profile sqli-demo up -d --wait
   ```

2. Publish the demo layer, entering your GeoServer administrator password:

   ```sh
   python3 scripts/setup_sqli_demo.py
   ```

3. Install the updated command and run the guided scan:

   ```sh
   cargo install --path crates/geoscan --locked --force
   geoscan scan
   ```

   Accept the localhost target. Login is optional and used only to read the
   version. The result should show one SQLi finding when the valid baseline and
   quote-error probe meet the matcher conditions. REST-index exposure is normally
   `NO MATCH` on this lab's release.

4. Run the two curl commands printed under the SQLi finding. The first sends
   `jsonArrayContains("json_data",'/a','x') = true` and should return GeoJSON.
   The second sends `jsonArrayContains("json_data",'/a','x''') = true`; CQL's doubled
   apostrophe represents a literal apostrophe inside the value. In this lab,
   prepared statements can produce an XML exception containing:

   ```text
   Borrow prepareStatement from pool failed
   Unterminated identifier ... in SQL SELECT ... jsonb_path_exists(...) ... Expected quote char
   ```

   HTTP 200 alone does not establish success: the response content is an OGC
   exception, not the requested GeoJSON. The JDBC parser detects broken SQL while
   preparing it. The demonstrated evidence is unsafe SQL generation and quote
   handling; arbitrary SQL execution is not tested.

5. Show the saved result and export it for your presentation:

   ```sh
   geoscan report
   geoscan report --json > demo-report.json
   ```

Explain the implementation using this flow:

```text
Rust CLI -> geoscan-core -> Nuclei template -> GeoServer WFS
                                                   |
                                            GeoTools / JDBC
                                                   |
                                            PostgreSQL / PostGIS

Nuclei JSONL -> Rust validation -> SQLite -> terminal / JSON report
```

`scan_input.rs` collects and validates the target and optional credentials.
`detect.rs` identifies GeoServer using several endpoints and reads the version.
`scan/sqli.rs` uses DescribeFeatureType to ensure the selected attribute is a
String. `scan.rs` writes the embedded template into a temporary directory, starts
the engine with direct arguments, bounds its runtime and request rate, validates
the returned CVE and matched URL, and saves results transactionally. The template
requires a successful GeoJSON baseline plus the specific PostgreSQL or JDBC
quote-error signature in an OGC exception. `scan/reproduce.rs` generates manual
commands from the validated match URL, and `scan_output.rs` renders the result.

The student's contribution is the Rust orchestration, detection, reviewed checks,
SQLite storage, catalogue, input validation, reports, and reproduction workflow.
Nuclei provides the HTTP execution and matching engine; describe that dependency
accurately when explaining the project. Only two of the 32 catalogue entries have
implemented active checks, and the SQLi test covers one selected layer/attribute.

## Read assessment results

- `PotentiallyAffected`: the release matches an affected range. Check the printed
  configuration requirements and advisory; a version match does not confirm
  exploitation or account for vendor backports and local mitigations.
- `OutsideAffectedRanges`: the release is outside that entry's affected ranges.
  This says nothing about vulnerabilities absent from the catalogue or insecure
  deployment settings.
- `Unknown`: the version is missing, malformed, or a prerelease/snapshot; the
  affected versions refer to another component; or the advisory is too ambiguous
  for a reliable release comparison.

A completed assessment exits successfully even if it reports possible exposure
or unknown versions. Command-line errors and catalogue errors exit unsuccessfully.
This step does not yet provide a CI failure policy.

A 2.28.2 assessment flags possible exposure to the PostGIS SQL injection and the
administrator-only logging-path issue. It also returns unknown for the
GeoWebCache-only version record and the disputed Welcome/About patch record.
Configuration requirements remain unverified.

## Catalogue metadata

The catalogue embeds all 31 CVEs supplied for this project and retains the existing
CVE-2026-76904 entry: **32 records**, researched on **2026-10-12**. It is not a
complete inventory of every GeoServer vulnerability.

Each entry in [cves.json](crates/geoscan-core/data/cves.json) includes:

- Issue type, description, component, authentication requirements, and CWEs.
- CVSS scores, severities, vectors where available, and a source for each rating.
- Separate CVE publication, NVD publication, advisory publication, and CVE
  modification dates, with sources.
- Affected and fixed release ranges, their version scope, and interpretation notes.
- Configuration prerequisites, remediation, advisory links, research references,
  and recorded CISA KEV metadata where verified.
- Probe policy, template mapping, and probe notes.
- The user's original score, severity, and reported publication date, kept
  separately as `reported_metadata`.

The first CVSS rating determines the displayed severity. A CVE record is preferred
when available, followed by the reviewed advisory database and then the vendor
advisory. Alternative scores retain their sources. A publication date is selected
from verified CVE, NVD, or advisory publication dates, in that order; modification
dates and user-reported dates are never substituted.

`kev: null` means no KEV entry is recorded in this snapshot. It is not a live
confirmation that CISA has never listed that CVE.

## Research findings and limitations

The supplied footnote does not apply uniformly to all three June 2026 records:
CVE-2025-52465's CVE record identifies **2026-06-18 as publication**, while the
vendor advisory dates to June 11. CVE-2025-27511's reviewed advisory also reports
NVD publication on June 18. For CVE-2025-58175, the vendor advisory date is verified
as June 11, while the supplied June 18 date remains user-reported because the
original CVE/NVD publication could not be independently retrieved.
Sources: [52465 CVE record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2025/52xxx/CVE-2025-52465.json),
[27511 reviewed advisory](https://github.com/advisories/GHSA-g628-r368-6vh7),
[58175 vendor advisory](https://github.com/geoserver/geoserver/security/advisories/GHSA-x4r9-gmw3-hxww).

Several ratings differ by source and are deliberately retained:

| CVE | CVE / reviewed database score | GeoServer advisory score |
| --- | --- | --- |
| CVE-2025-30220 | 9.9 critical | 8.2 high |
| CVE-2024-34711 | 9.3 critical | 6.5 medium |
| CVE-2024-24749 | 7.5 high | 5.9 medium |
| CVE-2026-76904 | 9.8 critical | 9.1 critical |

The complete source links are available through `checks show` and JSON export.

For [CVE-2024-35230](https://github.com/geoserver/geoserver/security/advisories/GHSA-6pfc-w86r-54q6),
the vendor's version table lists a patch but the description says no patch is
available. This record remains `Unknown` for version-only assessment rather than
inventing a reliable fixed range.

[CVE-2023-5786](https://vuldb.com/vuln/243592) names GeoWebCache 1.15.0 and 1.15.1.
These are dependency versions and cannot be compared with a GeoServer 2.x release.
Its `version_scope` is `geo_web_cache`; assessment requires component information
or a future endpoint check. No fixed release is verified in this catalogue.

The [current logging-path advisory](https://github.com/geoserver/geoserver/security/advisories/GHSA-8g7v-vjrc-x4g5)
identifies GeoServer 3.0.0 as the fix. Older database bounds are retained as
references, while the assessment uses the current vendor range.

Branch ranges are normalized around documented fixes instead of treating comma
separated branch summaries as one SemVer intersection. This prevents backported
fixes from matching another release branch. Interpretation differences are recorded
in each entry's `version_notes`. WMS/WPS URL-check settings and status-page settings
may still matter after a version falls outside an affected range.

## Researched coverage

The date column states which kind of publication date was verified. Each CVE link
opens its principal advisory; additional source records are in the JSON catalogue.

| CVE | Displayed CVSS / severity | Issue | Publication date / source kind |
| --- | --- | --- | --- |
| [CVE-2025-58175](https://github.com/geoserver/geoserver/security/advisories/GHSA-x4r9-gmw3-hxww) | 6.5 medium | SSRF in XML entity resolution | 2026-06-11 (Advisory) |
| [CVE-2025-52465](https://github.com/geoserver/geoserver/security/advisories/GHSA-7qmg-grcp-qf25) | 7.2 high | Arbitrary file write through Master Password Dump | 2026-06-18 (CVE) |
| [CVE-2025-27511](https://github.com/geoserver/geoserver/security/advisories/GHSA-g628-r368-6vh7) | 7.2 high | JNDI injection in DB2 datastore connections | 2026-06-18 (NVD) |
| [CVE-2025-21621](https://github.com/geoserver/geoserver/security/advisories/GHSA-w66h-j855-qr72) | 6.1 medium | Reflected XSS in WMS GetFeatureInfo HTML | 2025-11-25 (NVD) |
| [CVE-2025-58360](https://github.com/geoserver/geoserver/security/advisories/GHSA-fjf5-xgmq-5525) | 8.2 high | Unauthenticated XXE through WMS GetMap | 2025-11-25 (CVE) |
| [CVE-2025-30220](https://github.com/geoserver/geoserver/security/advisories/GHSA-jj54-8f66-c5pc) | 9.9 critical | WFS XML external entity processing | 2025-06-10 (CVE) |
| [CVE-2025-30145](https://github.com/geoserver/geoserver/security/advisories/GHSA-gr67-pwcv-76gf) | 7.5 high | Infinite-loop denial of service in Jiffle | 2025-06-10 (NVD) |
| [CVE-2025-27505](https://github.com/geoserver/geoserver/security/advisories/GHSA-h86g-x8mm-78m5) | 5.3 medium | Missing authorization on REST API index | 2025-06-10 (CVE) |
| [CVE-2024-40625](https://github.com/geoserver/geoserver/security/advisories/GHSA-r4hf-r8gj-jgw2) | 5.5 medium | SSRF through Coverage REST API | 2025-06-10 (CVE) |
| [CVE-2024-38524](https://github.com/geoserver/geoserver/security/advisories/GHSA-jm79-7xhw-6f6f) | 5.3 medium | Information disclosure on GeoWebCache home page | 2025-06-10 (NVD) |
| [CVE-2024-34711](https://github.com/geoserver/geoserver/security/advisories/GHSA-mc43-4fqr-c965) | 9.3 critical | SSRF through XML URI validation | 2025-06-10 (CVE) |
| [CVE-2024-29198](https://github.com/geoserver/geoserver/security/advisories/GHSA-5gw5-jccf-6hxw) | 7.5 high | Unauthenticated SSRF through TestWfsPost | 2025-06-10 (NVD) |
| [CVE-2024-35230](https://github.com/geoserver/geoserver/security/advisories/GHSA-6pfc-w86r-54q6) | 5.3 medium | Build information exposed on Welcome and About pages | 2024-12-16 (NVD) |
| [CVE-2024-36401](https://github.com/geoserver/geoserver/security/advisories/GHSA-6jj6-gm7p-fcvv) | 9.8 critical | Property-expression remote code execution | 2024-07-01 (CVE) |
| [CVE-2024-34696](https://github.com/geoserver/geoserver/security/advisories/GHSA-j59v-vgcr-hxvf) | 4.5 medium | Environment variables and Java properties exposed in Server Status | 2024-07-01 (NVD) |
| [CVE-2024-24749](https://github.com/geoserver/geoserver/security/advisories/GHSA-jhqx-5v5g-mpf3) | 7.5 high | Classpath resource disclosure through GeoWebCache | 2024-07-01 (NVD) |
| [CVE-2024-23821](https://github.com/geoserver/geoserver/security/advisories/GHSA-88wc-fcj9-q3r9) | 4.8 medium | Stored XSS in GeoWebCache Demos | 2024-03-20 (NVD) |
| [CVE-2024-23819](https://github.com/geoserver/geoserver/security/advisories/GHSA-7x76-57fr-m5r5) | 4.8 medium | Stored XSS in MapML HTML output | 2024-03-20 (NVD) |
| [CVE-2024-23818](https://github.com/geoserver/geoserver/security/advisories/GHSA-fcpm-hchj-mh72) | 4.8 medium | Stored XSS in WMS OpenLayers output | 2024-03-20 (NVD) |
| [CVE-2024-23643](https://github.com/geoserver/geoserver/security/advisories/GHSA-56r3-f536-5gf7) | 4.8 medium | Stored XSS in GeoWebCache Seed form | 2024-03-20 (NVD) |
| [CVE-2024-23642](https://github.com/geoserver/geoserver/security/advisories/GHSA-fg9v-56hw-g525) | 4.8 medium | Stored XSS in Simple SVG renderer | 2024-03-20 (NVD) |
| [CVE-2024-23640](https://github.com/geoserver/geoserver/security/advisories/GHSA-9rfr-pf2x-g4xf) | 4.8 medium | Stored XSS in Style Publisher | 2024-03-20 (NVD) |
| [CVE-2024-23634](https://github.com/geoserver/geoserver/security/advisories/GHSA-75m5-hh4r-q9gx) | 6.0 medium | Arbitrary file renaming through store REST APIs | 2024-03-20 (NVD) |
| [CVE-2023-51445](https://github.com/geoserver/geoserver/security/advisories/GHSA-fh7p-5f6g-vj2w) | 4.8 medium | Stored XSS through REST Resources API | 2024-03-20 (NVD) |
| [CVE-2023-51444](https://github.com/geoserver/geoserver/security/advisories/GHSA-9v5q-2gwq-q9hq) | 7.2 high | Arbitrary file upload through Coverage Store REST API | 2024-03-20 (CVE) |
| [CVE-2023-41877](https://github.com/geoserver/geoserver/security/advisories/GHSA-8g7v-vjrc-x4g5) | 7.2 high | Log file path traversal | 2024-03-20 (NVD) |
| [CVE-2023-5786](https://vuldb.com/vuln/243592) | 5.3 medium | Direct access to GeoWebCache REST HTML index | 2023-10-26 (Advisory) |
| [CVE-2023-43795](https://github.com/geoserver/geoserver/security/advisories/GHSA-5pr3-m5hm-9956) | 8.6 high | SSRF through WPS remote inputs | 2023-10-25 (NVD) |
| [CVE-2023-41339](https://github.com/geoserver/geoserver/security/advisories/GHSA-cqpc-x2c6-2gmf) | 8.6 high | Blind SSRF through WMS remote styles | 2023-10-25 (NVD) |
| [CVE-2023-25157](https://github.com/geoserver/geoserver/security/advisories/GHSA-7g5f-wrx8-5ccf) | 9.8 critical | SQL injection through OGC filters | 2023-02-21 (NVD) |
| [CVE-2022-24847](https://github.com/geoserver/geoserver/security/advisories/GHSA-4pm3-f52j-8ggh) | 7.2 high | Unsafe JNDI lookup and deserialization | 2022-04-13 (CVE) |
| [CVE-2026-76904](https://github.com/geoserver/geoserver/security/advisories/GHSA-jvpx-6qxg-whgc) | 9.8 critical | PostGIS jsonArrayContains SQL injection | 2026-08-21 (CVE) |

## Probe coverage

These 32 research records do not imply 32 executable Nuclei checks.

- `ReadOnly`: CVE-2025-27505 and CVE-2026-76904 have reviewed GET-based templates.
- `LabOnly`: CVE-2024-36401 and CVE-2025-30220 have intrusive or external-callback
  template mappings.
- `Unreviewed`: the other 28 records have no active template mapped.

`checks` commands execute no templates. `scan` selects the two implemented CVEs,
verifies their `ReadOnly` policies, and runs their embedded templates. SQLi schema
preflight failures or unavailable prerequisites are reported separately.
No `LabOnly` or `Unreviewed` checks are executed.

## Verify changes

```sh
cargo fmt --all --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build -p geoscan --locked
python3 -m unittest discover -s scripts/tests -v
nuclei -validate -templates crates/geoscan-core/templates/http/cves -disable-update-check -no-interactsh
```

The optional Nuclei integration test replays the captured PostgreSQL JDBC error
and checks positive and negative matcher cases against a local HTTP fixture.
It needs Nuclei on `PATH` and permission to open a local socket:

```sh
cargo test -p geoscan-core --locked --test nuclei_sqli -- --ignored
```

Set `GEOSCAN_TEST_NUCLEI` to an executable path when Nuclei is outside `PATH`.
This test uses synthetic responses and requires neither GeoServer nor PostGIS.

Tests cover all requested IDs, affected/fixed boundaries, version scope, unknown
versions, score/date provenance, invalid metadata, JSON export, CLI details, help
and errors, and using the embedded catalogue outside the source directory.
Existing detection tests use HTTP fixtures. Scanner tests check JSONL parsing,
deduplication, negative versus missing outcomes, failed requests, unexpected
check IDs and match URLs, and saving findings and final status in SQLite.
CLI input tests cover the Docker default, skipping login, invalid URLs, partial
flags, password whitespace, missing script inputs, and keeping passwords out of
error output.
Additional tests cover SQLi argument validation, schema prerequisites, exact match
URL scope, requiring the final SQLi request outcome, mixed scan results, retaining
findings when another check fails, upgrading existing SQLite databases, and demo
setup idempotence and credential handling.

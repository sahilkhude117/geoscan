# GeoScan

A Rust CLI for identifying GeoServer and comparing its release version with a
researched CVE catalogue. The shared `geoscan-core` crate will also support a future
web backend. SQLite access and the Nuclei installation can be checked with
`doctor`; active vulnerability scanning and scan history are future steps.

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
cargo install --path crates/geoscan --locked
geoscan checks list
geoscan checks show --id CVE-2025-58360
geoscan checks assess --geoserver-version 2.28.2
```

Export metadata for another program or the future web backend:

```sh
geoscan checks list --json > cves-export.json
```

JSON export contains only a JSON array, with no human-readable banner.
Unknown CVE IDs passed to `checks show` exit with an error.

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
- Future probe policy, template mapping, and probe notes.
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

- `ReadOnly`: CVE-2025-27505 has a reviewed GET-based template mapping.
- `LabOnly`: CVE-2024-36401 and CVE-2025-30220 have intrusive or external-callback
  template mappings.
- `Unreviewed`: the other 29 records have no active template mapped.

The commands execute no templates. Policy labels describe future scanning
requirements and are not yet enforced by a scanning runner.

## Verify changes

```sh
cargo fmt --all --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build -p geoscan --locked
```

Tests cover all requested IDs, affected/fixed boundaries, version scope, unknown
versions, score/date provenance, invalid metadata, JSON export, CLI details, help
and errors, and using the embedded catalogue outside the source directory.
Existing detection tests use HTTP fixtures.

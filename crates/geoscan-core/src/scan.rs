use std::{collections::HashSet, path::Path, process::Stdio, time::Duration};

use reqwest::Url;
use serde::{Deserialize, Serialize};
use sqlx::{Connection, Row, SqliteConnection, sqlite::SqliteConnectOptions};
use tokio::{process::Command, time::timeout};

use crate::{
    catalog::{CveCheck, CvssRating, ProbePolicy, Severity, load_catalog},
    check_nuclei,
    detect::detect_geoserver,
};

mod reproduce;
mod sqli;
pub use reproduce::ReproductionStep;
pub use sqli::{DEFAULT_LAYER, DEFAULT_PROPERTY, SqliTarget};

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckKind {
    #[default]
    Cve,
    Misconfiguration,
}

const REST_CHECK: &str = "CVE-2025-27505";
const SQLI_CHECK: &str = "CVE-2026-76904";
const CHECK_IDS: [&str; 2] = [REST_CHECK, SQLI_CHECK];

/// Implemented checks; catalogue entries alone do not imply scan coverage.
pub const SUPPORTED_CHECKS: &[&str] = &CHECK_IDS;
const REST_TEMPLATE: &str = include_str!("../templates/http/cves/2025/CVE-2025-27505.yaml");
const SQLI_TEMPLATE: &str = include_str!("../templates/http/cves/2026/CVE-2026-76904.yaml");

#[derive(Debug, Deserialize, Serialize)]
pub struct Finding {
    #[serde(default)]
    pub check_id: String,
    #[serde(default)]
    pub kind: CheckKind,
    pub cve_id: Option<String>,
    pub name: String,
    pub severity: Severity,
    pub matched_at: String,
    pub description: String,
    pub cvss: Vec<CvssRating>,
    pub remediation: String,
    pub advisory_url: String,
    pub evidence: String,
    pub reproduction: Vec<ReproductionStep>,
}

#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub id: i64,
    pub target: String,
    pub geoserver_version: Option<String>,
    pub version_note: String,
    pub status: String,
    pub reported_events: usize,
    pub not_run: usize,
    pub checks: Vec<CheckResult>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CheckResult {
    #[serde(default)]
    pub check_id: String,
    #[serde(default)]
    pub kind: CheckKind,
    pub cve_id: Option<String>,
    #[serde(default)]
    pub severity: Option<Severity>,
    pub status: String,
    pub ran: bool,
    pub reported_events: usize,
    pub matches: usize,
    pub note: String,
    pub diagnostics: String,
    pub error: Option<String>,
}

impl Finding {
    pub fn id(&self) -> &str {
        if self.check_id.is_empty() {
            self.cve_id.as_deref().unwrap_or("")
        } else {
            &self.check_id
        }
    }
}

impl CheckResult {
    pub fn id(&self) -> &str {
        if self.check_id.is_empty() {
            self.cve_id.as_deref().unwrap_or("")
        } else {
            &self.check_id
        }
    }
}

fn finding(check: &CveCheck, target: &str, matched_at: String) -> Result<Finding, String> {
    let (evidence, reproduction) = reproduce::steps(&check.id, target, &matched_at)?;
    Ok(Finding {
        check_id: check.id.clone(),
        kind: CheckKind::Cve,
        cve_id: Some(check.id.clone()),
        name: check.name.clone(),
        severity: check.severity,
        matched_at,
        description: check.description.clone(),
        cvss: check.cvss.clone(),
        remediation: check.remediation.clone(),
        advisory_url: check.advisory_url.clone(),
        evidence,
        reproduction,
    })
}

/// Read a saved result without scanning or modifying the database. Metadata and
/// reproduction steps use the bundled catalogue and the saved, validated URL.
pub async fn read_scan_report(database: &Path, scan_id: Option<i64>) -> Result<ScanReport, String> {
    let options = SqliteConnectOptions::new()
        .filename(database)
        .read_only(true)
        .busy_timeout(Duration::from_secs(5));
    let mut db = SqliteConnection::connect_with(&options)
        .await
        .map_err(|error| format!("Could not read {}: {error}", database.display()))?;
    let row = sqlx::query("SELECT id, target, geoserver_version, status, reported_events FROM scans WHERE (? IS NULL OR id = ?) ORDER BY id DESC LIMIT 1")
        .bind(scan_id).bind(scan_id).fetch_optional(&mut db).await.map_err(|error| error.to_string())?
        .ok_or_else(|| match scan_id {
            Some(id) => format!("Scan #{id} was not found"),
            None => "No saved scans were found; run geoscan scan first".into(),
        })?;
    let id: i64 = row.get("id");
    let target: String = row.get("target");
    let catalog = load_catalog()?;
    let has_checks: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'scan_checks'",
    )
    .fetch_one(&mut db)
    .await
    .map_err(|error| error.to_string())?;
    let mut checks = Vec::new();
    if has_checks != 0 {
        let details: Vec<String> = sqlx::query_scalar(
            "SELECT details_json FROM scan_checks WHERE scan_id = ? ORDER BY cve_id",
        )
        .bind(id)
        .fetch_all(&mut db)
        .await
        .map_err(|error| error.to_string())?;
        for detail in details {
            let mut check = serde_json::from_str::<CheckResult>(&detail)
                .map_err(|error| format!("Invalid saved check: {error}"))?;
            if check.check_id.is_empty() {
                check.check_id = check
                    .cve_id
                    .clone()
                    .ok_or("Saved check has no identifier")?;
            }
            if check.severity.is_none() {
                check.severity = catalog
                    .iter()
                    .find(|entry| entry.id == check.id())
                    .map(|entry| entry.severity);
            }
            checks.push(check);
        }
    }
    let rows = sqlx::query(
        "SELECT cve_id, matched_at, details_json FROM findings WHERE scan_id = ? ORDER BY id",
    )
    .bind(id)
    .fetch_all(&mut db)
    .await
    .map_err(|error| error.to_string())?;
    let mut findings = Vec::new();
    for row in rows {
        let cve_id: String = row.get("cve_id");
        if cve_id.starts_with("GS-MISC-") {
            findings.push(crate::misconfig::restore_finding(
                &target,
                &cve_id,
                row.get("matched_at"),
                row.get("details_json"),
            )?);
            continue;
        }
        let check = catalog
            .iter()
            .find(|check| check.id == cve_id)
            .ok_or_else(|| format!("Saved finding {cve_id} is absent from the catalogue"))?;
        findings.push(finding(check, &target, row.get("matched_at"))?);
    }
    let reported_events = usize::try_from(row.get::<i64, _>("reported_events"))
        .map_err(|_| "Invalid saved event count".to_owned())?;
    let report = ScanReport {
        id,
        target,
        geoserver_version: row.get("geoserver_version"),
        version_note: "Version stored with the saved scan".into(),
        status: row.get("status"),
        reported_events,
        not_run: catalog.len().saturating_sub(
            checks
                .iter()
                .filter(|check| check.ran && check.kind == CheckKind::Cve)
                .count(),
        ),
        checks,
        findings,
    };
    db.close().await.map_err(|error| error.to_string())?;
    Ok(report)
}

#[derive(Deserialize)]
struct EngineEvent {
    #[serde(rename = "template-id")]
    template_id: String,

    #[serde(rename = "matcher-status")]
    matcher_status: bool,

    #[serde(rename = "matched-at", default)]
    matched_at: String,

    #[serde(default)]
    error: String,
}

struct EngineOutput {
    events: usize,
    matched_urls: Vec<String>,
    final_outcome: bool,
    diagnostics: String,
}

fn same_endpoint(actual: &Url, expected: &Url) -> bool {
    let mut actual_query = actual.query_pairs().collect::<Vec<_>>();
    let mut expected_query = expected.query_pairs().collect::<Vec<_>>();
    actual_query.sort();
    expected_query.sort();
    actual.origin() == expected.origin()
        && actual.path() == expected.path()
        && actual.username().is_empty()
        && actual.password().is_none()
        && actual.fragment().is_none()
        && actual_query == expected_query
}

fn parse_events(
    text: &str,
    check_id: &str,
    expected: &Url,
    require_final_endpoint: bool,
) -> Result<EngineOutput, String> {
    let mut events = 0;
    let mut matches = Vec::new();
    let mut seen = HashSet::new();
    let mut final_outcome = false;

    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let event: EngineEvent =
            serde_json::from_str(line).map_err(|e| format!("Invalid engine JSON: {e}"))?;

        if event.template_id != check_id {
            return Err("Engine returned an unexpected check ID".into());
        }

        if !event.error.is_empty() {
            return Err(format!("Engine request failed: {}", event.error));
        }

        events += 1;
        let matched = (!event.matched_at.is_empty())
            .then(|| Url::parse(&event.matched_at).map_err(|error| error.to_string()))
            .transpose()?;
        let selected_endpoint = matched
            .as_ref()
            .is_some_and(|url| same_endpoint(url, expected));
        // Nuclei's matcher-status failure writer emits a template-level no-match
        // without matched-at. Request errors have already been rejected above;
        // run_engine also requires a successful process exit before parsing.
        let no_match_outcome = !event.matcher_status && matched.is_none();
        final_outcome |= selected_endpoint || !require_final_endpoint || no_match_outcome;

        if !event.matcher_status {
            continue;
        }

        if !selected_endpoint {
            return Err("Engine returned a match outside the selected endpoint".into());
        }

        let matched = matched.expect("a selected endpoint has a parsed URL");
        if seen.insert(expected.to_string()) {
            matches.push(matched.to_string());
        }
    }

    Ok(EngineOutput {
        events,
        matched_urls: matches,
        final_outcome,
        diagnostics: String::new(),
    })
}

async fn run_engine(
    executable: &Path,
    target: &str,
    check_id: &str,
    selected: &SqliTarget,
) -> Result<EngineOutput, String> {
    // The template is embedded in our binary.
    let directory = tempfile::tempdir().map_err(|e| e.to_string())?;

    let template = directory.path().join(format!("{check_id}.yaml"));
    let (content, expected) = match check_id {
        REST_CHECK => (
            REST_TEMPLATE,
            Url::parse(target)
                .map_err(|error| error.to_string())?
                .join("rest.html")
                .map_err(|error| error.to_string())?,
        ),
        SQLI_CHECK => (SQLI_TEMPLATE, selected.filter_url(target, true)?),
        _ => return Err("No reviewed template is implemented for this check".into()),
    };
    std::fs::write(&template, content).map_err(|e| e.to_string())?;

    // Use a separate user configuration directory for this run.
    std::fs::write(directory.path().join("config.yaml"), "{}\n").map_err(|e| e.to_string())?;

    // Pass arguments directly. Do not construct a shell command.
    let mut command = Command::new(executable);

    command
        .env_remove("GEOSCAN_PASSWORD")
        .env("NUCLEI_CONFIG_DIR", directory.path())
        .arg("-target")
        .arg(target.trim_end_matches('/'))
        .arg("-templates")
        .arg(&template)
        .args([
            "-jsonl",
            "-silent",
            "-no-color",
            "-matcher-status",
            "-omit-raw",
            "-omit-template",
            "-no-interactsh",
            "-disable-update-check",
            "-no-stdin",
            "-disable-redirects",
            "-rate-limit",
            "5",
            "-concurrency",
            "1",
            "-timeout",
            "10",
            "-retries",
            "0",
        ])
        .stdin(Stdio::null())
        .kill_on_drop(true);

    if check_id == SQLI_CHECK {
        command
            .arg("-var")
            .arg(format!("sqli_layer={}", selected.layer))
            .arg("-var")
            .arg(format!("sqli_property={}", selected.property));
    }

    let output = timeout(Duration::from_secs(60), command.output())
        .await
        .map_err(|_| "Scan timed out after 60 seconds".to_owned())?
        .map_err(|e| format!("Could not start scanning engine: {e}"))?;

    let diagnostics: String = String::from_utf8_lossy(&output.stderr)
        .chars()
        .take(8192)
        .collect();

    if !output.status.success() {
        return Err(format!(
            "Engine exited with {}: {diagnostics}",
            output.status
        ));
    }

    let text =
        String::from_utf8(output.stdout).map_err(|_| "Engine output was not UTF-8".to_owned())?;

    let mut result = parse_events(&text, check_id, &expected, check_id == SQLI_CHECK)?;
    result.diagnostics = diagnostics;
    Ok(result)
}

async fn open_database(path: &Path) -> Result<SqliteConnection, String> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5));

    let mut db = SqliteConnection::connect_with(&options)
        .await
        .map_err(|e| e.to_string())?;

    for statement in [
        "CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY,
            target TEXT NOT NULL,
            geoserver_version TEXT,
            check_id TEXT NOT NULL,
            engine_version TEXT NOT NULL,
            status TEXT NOT NULL,
            started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            finished_at TEXT,
            reported_events INTEGER NOT NULL DEFAULT 0,
            diagnostics TEXT NOT NULL DEFAULT '',
            error TEXT
        )",
        "CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY,
            scan_id INTEGER NOT NULL REFERENCES scans(id),
            cve_id TEXT NOT NULL,
            matched_at TEXT NOT NULL,
            details_json TEXT NOT NULL,
            UNIQUE(scan_id, cve_id, matched_at)
        )",
        "CREATE TABLE IF NOT EXISTS scan_checks (
            scan_id INTEGER NOT NULL REFERENCES scans(id),
            cve_id TEXT NOT NULL,
            status TEXT NOT NULL,
            reported_events INTEGER NOT NULL,
            matched_count INTEGER NOT NULL,
            details_json TEXT NOT NULL,
            PRIMARY KEY(scan_id, cve_id)
        )",
    ] {
        sqlx::query(statement)
            .execute(&mut db)
            .await
            .map_err(|e| e.to_string())?;
    }

    Ok(db)
}

/// Initialize the shared schema so a new API instance can serve empty history.
pub async fn initialize_database(path: &Path) -> Result<(), String> {
    open_database(path)
        .await?
        .close()
        .await
        .map_err(|error| error.to_string())
}

async fn save_completed(
    db: &mut SqliteConnection,
    report: &ScanReport,
    diagnostics: &str,
) -> Result<(), String> {
    // Save findings and final status together.
    let mut transaction = db.begin().await.map_err(|e| e.to_string())?;

    for check in &report.checks {
        sqlx::query(
            "INSERT INTO scan_checks
             (scan_id, cve_id, status, reported_events, matched_count, details_json)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(report.id)
        .bind(check.id())
        .bind(&check.status)
        .bind(check.reported_events as i64)
        .bind(check.matches as i64)
        .bind(serde_json::to_string(check).map_err(|error| error.to_string())?)
        .execute(&mut *transaction)
        .await
        .map_err(|error| error.to_string())?;
    }

    for finding in &report.findings {
        let details = serde_json::to_string(finding).map_err(|e| e.to_string())?;

        sqlx::query(
            "INSERT INTO findings
             (scan_id, cve_id, matched_at, details_json)
             VALUES (?, ?, ?, ?)",
        )
        .bind(report.id)
        .bind(finding.id())
        .bind(&finding.matched_at)
        .bind(details)
        .execute(&mut *transaction)
        .await
        .map_err(|e| e.to_string())?;
    }

    let errors = report
        .checks
        .iter()
        .filter_map(|check| {
            check
                .error
                .as_ref()
                .map(|error| format!("{}: {error}", check.id()))
        })
        .collect::<Vec<_>>();
    let error = (!errors.is_empty()).then(|| errors.join("\n"));

    sqlx::query(
        "UPDATE scans
         SET status = ?, reported_events = ?, diagnostics = ?,
             error = ?, finished_at = CURRENT_TIMESTAMP
         WHERE id = ?",
    )
    .bind(&report.status)
    .bind(report.reported_events as i64)
    .bind(diagnostics)
    .bind(error)
    .bind(report.id)
    .execute(&mut *transaction)
    .await
    .map_err(|e| e.to_string())?;

    transaction.commit().await.map_err(|e| e.to_string())
}

fn overall_status(checks: &[CheckResult]) -> &'static str {
    let completed = checks
        .iter()
        .any(|check| check.matches > 0 || matches!(check.status.as_str(), "matches" | "no_match"));
    let failed = checks
        .iter()
        .any(|check| matches!(check.status.as_str(), "failed" | "partial"));
    let inconclusive = checks.iter().any(|check| check.status == "inconclusive");
    if failed || inconclusive {
        if completed {
            "partial"
        } else if failed && !inconclusive {
            "failed"
        } else {
            "inconclusive"
        }
    } else if checks.iter().any(|check| check.status == "matches") {
        "matches"
    } else if completed {
        "no_match"
    } else {
        "not_applicable"
    }
}

pub async fn scan_geoserver(
    target: &str,
    executable: &Path,
    database: &Path,
    auth: Option<(&str, &str)>,
    selected: &SqliTarget,
) -> Result<ScanReport, String> {
    scan_geoserver_tracked(target, executable, database, auth, selected, None).await
}

/// The optional sender exposes the persisted scan ID to the background-job API.
/// The ordinary CLI uses the same runner without a sender.
pub async fn scan_geoserver_tracked(
    target: &str,
    executable: &Path,
    database: &Path,
    auth: Option<(&str, &str)>,
    selected: &SqliTarget,
    started: Option<tokio::sync::oneshot::Sender<i64>>,
) -> Result<ScanReport, String> {
    scan_geoserver_with_options(
        target,
        executable,
        database,
        auth,
        selected,
        &crate::misconfig::Options::default(),
        started,
    )
    .await
}

pub async fn scan_geoserver_with_options(
    target: &str,
    executable: &Path,
    database: &Path,
    auth: Option<(&str, &str)>,
    selected: &SqliTarget,
    options: &crate::misconfig::Options,
    started: Option<tokio::sync::oneshot::Sender<i64>>,
) -> Result<ScanReport, String> {
    options.validate()?;
    let catalogue = load_catalog()?;

    for check_id in CHECK_IDS {
        let check = catalogue
            .iter()
            .find(|check| check.id == check_id)
            .ok_or_else(|| format!("Reviewed check {check_id} is missing from the catalogue"))?;
        if check.probe_policy != ProbePolicy::ReadOnly {
            return Err(format!("{check_id} has not been reviewed as read-only"));
        }
    }

    // Credentials identify the release. The exposure probe below stays anonymous.
    let detection = detect_geoserver(target, auth).await?;

    if !detection.likely_geoserver {
        return Err("GeoServer identification was inconclusive; scan not started".into());
    }

    let engine_version = if options.only_misconfigurations {
        Ok("builtin-http".to_owned())
    } else {
        check_nuclei(executable).await
    };
    let mut db = open_database(database).await?;

    let id = sqlx::query(
        "INSERT INTO scans
         (target, geoserver_version, check_id, engine_version, status)
         VALUES (?, ?, ?, ?, 'running')",
    )
    .bind(&detection.target)
    .bind(detection.version.as_deref())
    .bind(
        CHECK_IDS
            .iter()
            .copied()
            .chain(
                crate::misconfig::catalog()?
                    .iter()
                    .map(|check| check.id.as_str()),
            )
            .collect::<Vec<_>>()
            .join(","),
    )
    .bind(engine_version.as_deref().unwrap_or("unavailable"))
    .execute(&mut db)
    .await
    .map_err(|e| e.to_string())?
    .last_insert_rowid();

    if let Some(started) = started {
        let _ = started.send(id);
    }

    let result: Result<ScanReport, String> = async {
        let mut checks = Vec::new();
        let mut findings = Vec::new();
        for check_id in CHECK_IDS {
            let check = catalogue.iter().find(|entry| entry.id == check_id).expect("validated check");
            let mut outcome = CheckResult {
                check_id: check.id.clone(),
                kind: CheckKind::Cve,
                cve_id: Some(check.id.clone()),
                severity: Some(check.severity),
                status: "inconclusive".into(),
                ran: false,
                reported_events: 0,
                matches: 0,
                note: String::new(),
                diagnostics: String::new(),
                error: None,
            };
            if options.only_misconfigurations {
                outcome.status="not_applicable".into();
                outcome.note="CVE probe was not selected in this configuration-only scan".into();
                checks.push(outcome);
                continue;
            }
            if let Err(error)=&engine_version {
                outcome.status="failed".into();
                outcome.error=Some(error.clone());
                checks.push(outcome);
                continue;
            }
            if check_id == SQLI_CHECK {
                match sqli::preflight(&detection.target, selected).await {
                    sqli::Eligibility::Ready => {},
                    sqli::Eligibility::NotApplicable(note) => {
                        outcome.status = "not_applicable".into();
                        outcome.note = note;
                        checks.push(outcome);
                        continue;
                    },
                    sqli::Eligibility::Inconclusive(note) => {
                        outcome.note = note;
                        checks.push(outcome);
                        continue;
                    },
                }
            }
            outcome.ran = true;
            match run_engine(executable, &detection.target, check_id, selected).await {
                Ok(output) => {
                    outcome.reported_events = output.events;
                    outcome.matches = output.matched_urls.len();
                    outcome.diagnostics = output.diagnostics;
                    outcome.status = if output.events == 0 || !output.final_outcome {
                        "inconclusive"
                    } else if outcome.matches == 0 {
                        "no_match"
                    } else {
                        "matches"
                    }.into();
                    outcome.note = if outcome.status == "inconclusive" {
                        "The engine did not report the final probe outcome".into()
                    } else if check_id == SQLI_CHECK {
                        format!("Compared JSON filter quote handling on {}.{}; a match is SQL-generation error evidence requiring verification", selected.layer, selected.property)
                    } else {
                        "Checked unauthenticated access to the REST index".into()
                    };
                    for matched_at in output.matched_urls {
                        findings.push(finding(check, &detection.target, matched_at)?);
                    }
                },
                Err(error) => {
                    outcome.status = "failed".into();
                    outcome.error = Some(error);
                },
            }
            checks.push(outcome);
        }
        let configuration = crate::misconfig::scan(&detection.target,options).await?;
        checks.extend(configuration.checks);
        findings.extend(configuration.findings);
        let diagnostics = checks.iter()
            .filter(|check| !check.diagnostics.is_empty())
            .map(|check| format!("{}: {}", check.id(), check.diagnostics))
            .collect::<Vec<_>>()
            .join("\n");

        let report = ScanReport {
            id,
            target: detection.target.clone(),
            geoserver_version: detection.version.clone(),
            version_note: detection.version_note.clone(),
            status: overall_status(&checks).into(),
            reported_events: checks.iter().map(|check| check.reported_events).sum(),
            not_run: catalogue.len() - checks.iter().filter(|check| check.ran && check.kind == CheckKind::Cve).count(),
            checks,
            findings,
        };

        save_completed(&mut db, &report, &diagnostics).await?;

        Ok(report)
    }
    .await;

    if let Err(error) = &result {
        sqlx::query(
            "UPDATE scans
             SET status = 'failed', error = ?,
                 finished_at = CURRENT_TIMESTAMP
             WHERE id = ?",
        )
        .bind(error)
        .bind(id)
        .execute(&mut db)
        .await
        .map_err(|e| format!("Scan #{id} failed: {error}; could not save failure: {e}"))?;
    }

    db.close().await.map_err(|e| e.to_string())?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const TARGET: &str = "http://127.0.0.1:8080/geoserver";
    // Produced by Nuclei 3.11.1's StandardWriter::WriteFailure with the same
    // JSONL, matcher-status, omit-raw and omit-template options as our runner.
    const NUCLEI_NO_MATCH: &str = include_str!("../tests/fixtures/nuclei-no-match.jsonl");

    #[tokio::test]
    async fn configuration_findings_round_trip_without_using_up_cve_coverage() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mixed.db");
        let mut db = open_database(&path).await.unwrap();
        let id=sqlx::query("INSERT INTO scans (target,check_id,engine_version,status) VALUES (?,'mixed','fixture','running')").bind(TARGET).execute(&mut db).await.unwrap().last_insert_rowid();
        let definition = crate::misconfig::catalog()
            .unwrap()
            .into_iter()
            .find(|entry| entry.id == "GS-MISC-002")
            .unwrap();
        let cfg = Finding {
            check_id: definition.id.clone(),
            kind: CheckKind::Misconfiguration,
            cve_id: None,
            name: definition.name,
            severity: definition.severity,
            matched_at: format!("{TARGET}/rest/workspaces.json"),
            description: definition.description,
            cvss: vec![],
            remediation: definition.remediation,
            advisory_url: definition.reference_url,
            evidence: "Anonymous configuration response markers; body redacted".into(),
            reproduction: vec![],
        };
        let mut configuration = outcome("GS-MISC-002", "matches");
        configuration.kind = CheckKind::Misconfiguration;
        configuration.cve_id = None;
        configuration.severity = Some(Severity::Medium);
        let report = ScanReport {
            id,
            target: TARGET.into(),
            geoserver_version: None,
            version_note: String::new(),
            status: "matches".into(),
            reported_events: 2,
            not_run: 31,
            checks: vec![outcome(REST_CHECK, "no_match"), configuration],
            findings: vec![cfg],
        };
        save_completed(&mut db, &report, "").await.unwrap();
        db.close().await.unwrap();
        let restored = read_scan_report(&path, Some(id)).await.unwrap();
        assert_eq!(restored.not_run, 31);
        assert_eq!(restored.findings[0].cve_id, None);
        assert_eq!(restored.findings[0].id(), "GS-MISC-002");
        assert!(restored.findings[0].cvss.is_empty());
        assert!(
            restored.findings[0].reproduction[0]
                .command
                .contains("rest/workspaces.json")
        );
    }

    fn rest_endpoint() -> Url {
        Url::parse(&format!("{TARGET}/rest.html")).unwrap()
    }

    fn sqli_finding() -> Finding {
        let catalog = load_catalog().unwrap();
        let check = catalog.iter().find(|check| check.id == SQLI_CHECK).unwrap();
        finding(
            check,
            TARGET,
            SqliTarget::default()
                .filter_url(&format!("{TARGET}/"), true)
                .unwrap()
                .to_string(),
        )
        .unwrap()
    }

    fn outcome(id: &str, status: &str) -> CheckResult {
        CheckResult {
            check_id: id.into(),
            kind: CheckKind::Cve,
            cve_id: Some(id.into()),
            severity: None,
            status: status.into(),
            ran: status != "not_applicable",
            reported_events: 1,
            matches: usize::from(status == "matches"),
            note: String::new(),
            diagnostics: String::new(),
            error: None,
        }
    }

    #[test]
    fn parses_matches_and_deduplicates_the_same_endpoint() {
        let line = r#"{"template-id":"CVE-2025-27505","matcher-status":true,"matched-at":"http://127.0.0.1:8080/geoserver/rest.html"}"#;

        let input = format!("{line}\n{line}\n");
        let parsed = parse_events(&input, REST_CHECK, &rest_endpoint(), false).unwrap();

        assert_eq!(parsed.events, 2);
        assert_eq!(parsed.matched_urls.len(), 1);
    }

    #[test]
    fn distinguishes_no_match_from_no_reported_events() {
        let input = r#"{"template-id":"CVE-2025-27505","matcher-status":false}"#;

        let parsed = parse_events(input, REST_CHECK, &rest_endpoint(), false).unwrap();
        assert_eq!(parsed.events, 1);
        assert!(parsed.final_outcome);
        assert!(parsed.matched_urls.is_empty());
        let empty = parse_events("", REST_CHECK, &rest_endpoint(), false).unwrap();
        assert_eq!(empty.events, 0);
        assert!(!empty.final_outcome);
    }

    #[test]
    fn rejects_failed_requests_other_checks_and_out_of_scope_matches() {
        for input in [
            "not json",
            r#"{"template-id":"CVE-2025-27505","matcher-status":false,"error":"connection refused"}"#,
            r#"{"template-id":"CVE-2024-36401","matcher-status":true,"matched-at":"http://127.0.0.1:8080/geoserver/rest.html"}"#,
            r#"{"template-id":"CVE-2025-27505","matcher-status":true,"matched-at":"https://example.com/rest.html"}"#,
        ] {
            assert!(parse_events(input, REST_CHECK, &rest_endpoint(), false).is_err());
        }
    }

    #[test]
    fn sqli_matches_must_belong_to_the_exact_selected_filter_and_layer() {
        let selected = SqliTarget::default();
        let endpoint = selected.filter_url(&format!("{TARGET}/"), true).unwrap();
        let line = serde_json::json!({"template-id": SQLI_CHECK, "matcher-status": true, "matched-at": endpoint.as_str()}).to_string();
        let parsed = parse_events(&line, SQLI_CHECK, &endpoint, true).unwrap();
        assert_eq!(parsed.matched_urls.len(), 1);
        assert!(parsed.final_outcome);
        // Query order and equivalent percent encodings do not change scope.
        let alternate = endpoint
            .as_str()
            .replace("geoscan_sqli_demo%3Aitems", "geoscan_sqli_demo:items")
            .replace('+', "%20");
        assert!(same_endpoint(&Url::parse(&alternate).unwrap(), &endpoint));
        let alternate_event = serde_json::json!({"template-id": SQLI_CHECK, "matcher-status": true, "matched-at": alternate}).to_string();
        assert_eq!(
            parse_events(
                &format!("{line}\n{alternate_event}"),
                SQLI_CHECK,
                &endpoint,
                true
            )
            .unwrap()
            .matched_urls
            .len(),
            1
        );
        let wrong = serde_json::json!({"template-id": SQLI_CHECK, "matcher-status": true, "matched-at": format!("{TARGET}/wfs?typeName=other")}).to_string();
        assert!(parse_events(&wrong, SQLI_CHECK, &endpoint, true).is_err());
        let mut credentials = endpoint.clone();
        credentials.set_username("admin").unwrap();
        assert!(!same_endpoint(&credentials, &endpoint));
    }

    #[test]
    fn sqli_requires_a_reported_final_request_outcome() {
        let selected = SqliTarget::default();
        let target = format!("{TARGET}/");
        let probe = selected.filter_url(&target, true).unwrap();
        let baseline = selected.filter_url(&target, false).unwrap();
        let event = |url: &Url| {
            serde_json::json!({"template-id": SQLI_CHECK, "matcher-status": false, "matched-at": url.as_str()}).to_string()
        };
        assert!(
            !parse_events(&event(&baseline), SQLI_CHECK, &probe, true)
                .unwrap()
                .final_outcome
        );
        let parsed = parse_events(
            &format!("{}\n{}", event(&baseline), event(&probe)),
            SQLI_CHECK,
            &probe,
            true,
        )
        .unwrap();
        assert!(parsed.final_outcome);
        assert!(parsed.matched_urls.is_empty());
    }

    #[test]
    fn sqli_accepts_nuclei_no_match_output_without_matched_at() {
        let endpoint = SqliTarget::default()
            .filter_url(&format!("{TARGET}/"), true)
            .unwrap();
        let mut event: serde_json::Value = serde_json::from_str(NUCLEI_NO_MATCH).unwrap();
        event["matched-at"] = "".into();

        for input in [NUCLEI_NO_MATCH.to_owned(), event.to_string()] {
            let parsed = parse_events(&input, SQLI_CHECK, &endpoint, true).unwrap();
            assert_eq!(parsed.events, 1);
            assert!(parsed.final_outcome);
            assert!(parsed.matched_urls.is_empty());
        }
        let empty = parse_events("", SQLI_CHECK, &endpoint, true).unwrap();
        assert_eq!(empty.events, 0);
        assert!(!empty.final_outcome);
    }

    #[test]
    fn sqli_no_match_handling_preserves_error_and_positive_scope_validation() {
        let endpoint = SqliTarget::default()
            .filter_url(&format!("{TARGET}/"), true)
            .unwrap();
        let event: serde_json::Value = serde_json::from_str(NUCLEI_NO_MATCH).unwrap();
        for (key, value) in [
            ("error", serde_json::json!("connection refused")),
            ("error", serde_json::json!("context deadline exceeded")),
            ("template-id", serde_json::json!(REST_CHECK)),
            ("matcher-status", serde_json::json!(true)),
        ] {
            let mut invalid = event.clone();
            invalid[key] = value;
            assert!(parse_events(&invalid.to_string(), SQLI_CHECK, &endpoint, true).is_err());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn engine_no_match_requires_successful_exit_and_no_request_error() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("fixture-engine");
        let mut request_error: serde_json::Value = serde_json::from_str(NUCLEI_NO_MATCH).unwrap();
        request_error["error"] = "connection refused".into();
        for (events, exit_code, expected_error, completed) in [
            (NUCLEI_NO_MATCH.to_owned(), 0, false, true),
            (NUCLEI_NO_MATCH.to_owned(), 1, true, false),
            (request_error.to_string(), 0, true, false),
            (String::new(), 0, false, false),
        ] {
            std::fs::write(
                &executable,
                format!("#!/bin/sh\ncat <<'GEOSCAN_RESULT'\n{events}\nGEOSCAN_RESULT\nexit {exit_code}\n"),
            )
            .unwrap();
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
            let result = run_engine(
                &executable,
                &format!("{TARGET}/"),
                SQLI_CHECK,
                &SqliTarget::default(),
            )
            .await;
            assert_eq!(result.is_err(), expected_error);
            if let Ok(output) = result {
                assert_eq!(output.final_outcome, completed);
                assert!(output.matched_urls.is_empty());
            }
        }
    }

    #[test]
    fn overall_results_preserve_partial_coverage_and_missing_prerequisites() {
        for (first, second, expected) in [
            ("no_match", "matches", "matches"),
            ("no_match", "not_applicable", "no_match"),
            ("matches", "failed", "partial"),
            ("no_match", "inconclusive", "partial"),
            ("failed", "failed", "failed"),
            ("not_applicable", "not_applicable", "not_applicable"),
        ] {
            assert_eq!(
                overall_status(&[outcome(REST_CHECK, first), outcome(SQLI_CHECK, second)]),
                expected
            );
        }
    }

    #[tokio::test]
    async fn stores_findings_and_final_status_in_sqlite() {
        let directory = tempfile::tempdir().unwrap();

        let mut db = open_database(&directory.path().join("scan.db"))
            .await
            .unwrap();

        let id = sqlx::query(
            "INSERT INTO scans
             (target, check_id, engine_version, status)
             VALUES (?, ?, 'test', 'running')",
        )
        .bind(TARGET)
        .bind(CHECK_IDS.join(","))
        .execute(&mut db)
        .await
        .unwrap()
        .last_insert_rowid();

        let report = ScanReport {
            id,
            target: TARGET.into(),
            geoserver_version: Some("2.26.2".into()),
            version_note: "Reported by the REST API".into(),
            status: "matches".into(),
            reported_events: 1,
            not_run: 30,
            checks: vec![
                outcome(REST_CHECK, "no_match"),
                outcome(SQLI_CHECK, "matches"),
            ],
            findings: vec![sqli_finding()],
        };

        save_completed(&mut db, &report, "fixture diagnostics")
            .await
            .unwrap();

        let status: String = sqlx::query_scalar("SELECT status FROM scans WHERE id = ?")
            .bind(id)
            .fetch_one(&mut db)
            .await
            .unwrap();

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM findings WHERE scan_id = ?")
            .bind(id)
            .fetch_one(&mut db)
            .await
            .unwrap();

        assert_eq!(status, "matches");
        assert_eq!(count, 1);
        let check_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM scan_checks WHERE scan_id = ?")
                .bind(id)
                .fetch_one(&mut db)
                .await
                .unwrap();
        assert_eq!(check_count, 2);

        let details: String =
            sqlx::query_scalar("SELECT details_json FROM findings WHERE scan_id = ?")
                .bind(id)
                .fetch_one(&mut db)
                .await
                .unwrap();
        let stored: serde_json::Value = serde_json::from_str(&details).unwrap();
        assert_eq!(stored["reproduction"].as_array().unwrap().len(), 2);
        assert_eq!(stored["cvss"][0]["score"], 9.8);

        db.close().await.unwrap();
        let saved = read_scan_report(&directory.path().join("scan.db"), Some(id))
            .await
            .unwrap();
        assert_eq!(saved.status, "matches");
        assert_eq!(saved.findings.len(), 1);
        assert_eq!(saved.findings[0].reproduction.len(), 2);
        assert_eq!(saved.not_run, 30);
    }

    #[tokio::test]
    async fn existing_single_check_scans_survive_the_schema_upgrade() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("old-scans.db");
        let mut db = open_database(&path).await.unwrap();
        sqlx::query("DROP TABLE scan_checks")
            .execute(&mut db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO scans (target, check_id, engine_version, status) VALUES (?, ?, 'old-engine', 'no_match')")
            .bind(TARGET).bind(REST_CHECK).execute(&mut db).await.unwrap();
        db.close().await.unwrap();
        let legacy = read_scan_report(&path, None).await.unwrap();
        assert!(legacy.checks.is_empty());
        assert!(legacy.findings.is_empty());
        assert_eq!(legacy.not_run, 32);
        let mut upgraded = open_database(&path).await.unwrap();
        let check_id: String = sqlx::query_scalar("SELECT check_id FROM scans WHERE id = 1")
            .fetch_one(&mut upgraded)
            .await
            .unwrap();
        assert_eq!(check_id, REST_CHECK);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scan_checks")
            .fetch_one(&mut upgraded)
            .await
            .unwrap();
        assert_eq!(count, 0);
        upgraded.close().await.unwrap();
    }

    #[tokio::test]
    async fn partial_scan_stores_failed_check_without_losing_a_positive_finding() {
        let directory = tempfile::tempdir().unwrap();
        let mut db = open_database(&directory.path().join("partial.db"))
            .await
            .unwrap();
        let id = sqlx::query("INSERT INTO scans (target, check_id, engine_version, status) VALUES (?, ?, 'test', 'running')")
            .bind(TARGET).bind(CHECK_IDS.join(",")).execute(&mut db).await.unwrap().last_insert_rowid();
        let mut failed = outcome(REST_CHECK, "failed");
        failed.error = Some("Engine request failed".into());
        let report = ScanReport {
            id,
            target: TARGET.into(),
            geoserver_version: Some("2.28.2".into()),
            version_note: String::new(),
            status: "partial".into(),
            reported_events: 1,
            not_run: 30,
            checks: vec![failed, outcome(SQLI_CHECK, "matches")],
            findings: vec![sqli_finding()],
        };
        save_completed(&mut db, &report, "").await.unwrap();
        let error: Option<String> = sqlx::query_scalar("SELECT error FROM scans WHERE id = ?")
            .bind(id)
            .fetch_one(&mut db)
            .await
            .unwrap();
        assert!(error.unwrap().contains(REST_CHECK));
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM findings WHERE scan_id = ?")
            .bind(id)
            .fetch_one(&mut db)
            .await
            .unwrap();
        assert_eq!(count, 1);
        let stored: String =
            sqlx::query_scalar("SELECT status FROM scan_checks WHERE scan_id = ? AND cve_id = ?")
                .bind(id)
                .bind(REST_CHECK)
                .fetch_one(&mut db)
                .await
                .unwrap();
        assert_eq!(stored, "failed");
        db.close().await.unwrap();
    }
}

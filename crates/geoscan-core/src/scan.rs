use std::{collections::HashSet, path::Path, process::Stdio, time::Duration};

use reqwest::Url;
use serde::{Deserialize, Serialize};
use sqlx::{Connection, SqliteConnection, sqlite::SqliteConnectOptions};
use tokio::{process::Command, time::timeout};

use crate::{
    catalog::{ProbePolicy, Severity, load_catalog},
    check_nuclei,
    detect::detect_geoserver,
};

const CHECK_ID: &str = "CVE-2025-27505";

const TEMPLATE: &str = include_str!("../templates/http/cves/2025/CVE-2025-27505.yaml");

#[derive(Debug, Serialize)]
pub struct Finding {
    pub cve_id: String,
    pub name: String,
    pub severity: Severity,
    pub matched_at: String,
}

#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub id: i64,
    pub target: String,
    pub status: String,
    pub reported_events: usize,
    pub not_run: usize,
    pub findings: Vec<Finding>,
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
    diagnostics: String,
}

fn parse_events(text: &str, target: &str) -> Result<(usize, Vec<String>), String> {
    let base =
        Url::parse(&format!("{}/", target.trim_end_matches('/'))).map_err(|e| e.to_string())?;

    let expected = base.join("rest.html").map_err(|e| e.to_string())?;

    let mut events = 0;
    let mut matches = Vec::new();
    let mut seen = HashSet::new();

    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let event: EngineEvent =
            serde_json::from_str(line).map_err(|e| format!("Invalid engine JSON: {e}"))?;

        if event.template_id != CHECK_ID {
            return Err("Engine returned an unexpected check ID".into());
        }

        if !event.error.is_empty() {
            return Err(format!("Engine request failed: {}", event.error));
        }

        events += 1;

        if !event.matcher_status {
            continue;
        }

        let matched = Url::parse(&event.matched_at).map_err(|e| e.to_string())?;

        if matched != expected {
            return Err("Engine returned a match outside the selected endpoint".into());
        }

        if seen.insert(matched.to_string()) {
            matches.push(matched.to_string());
        }
    }

    Ok((events, matches))
}

async fn run_engine(executable: &Path, target: &str) -> Result<EngineOutput, String> {
    // The template is embedded in our binary.
    let directory = tempfile::tempdir().map_err(|e| e.to_string())?;

    let template = directory.path().join("CVE-2025-27505.yaml");

    std::fs::write(&template, TEMPLATE).map_err(|e| e.to_string())?;

    // Use a separate user configuration directory for this run.
    std::fs::write(directory.path().join("config.yaml"), "{}\n").map_err(|e| e.to_string())?;

    // Pass arguments directly. Do not construct a shell command.
    let mut command = Command::new(executable);

    command
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

    let (events, matched_urls) = parse_events(&text, target)?;

    Ok(EngineOutput {
        events,
        matched_urls,
        diagnostics,
    })
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
    ] {
        sqlx::query(statement)
            .execute(&mut db)
            .await
            .map_err(|e| e.to_string())?;
    }

    Ok(db)
}

async fn save_completed(
    db: &mut SqliteConnection,
    report: &ScanReport,
    diagnostics: &str,
) -> Result<(), String> {
    // Save findings and final status together.
    let mut transaction = db.begin().await.map_err(|e| e.to_string())?;

    for finding in &report.findings {
        let details = serde_json::to_string(finding).map_err(|e| e.to_string())?;

        sqlx::query(
            "INSERT INTO findings
             (scan_id, cve_id, matched_at, details_json)
             VALUES (?, ?, ?, ?)",
        )
        .bind(report.id)
        .bind(&finding.cve_id)
        .bind(&finding.matched_at)
        .bind(details)
        .execute(&mut *transaction)
        .await
        .map_err(|e| e.to_string())?;
    }

    sqlx::query(
        "UPDATE scans
         SET status = ?, reported_events = ?, diagnostics = ?,
             finished_at = CURRENT_TIMESTAMP
         WHERE id = ?",
    )
    .bind(&report.status)
    .bind(report.reported_events as i64)
    .bind(diagnostics)
    .bind(report.id)
    .execute(&mut *transaction)
    .await
    .map_err(|e| e.to_string())?;

    transaction.commit().await.map_err(|e| e.to_string())
}

pub async fn scan_geoserver(
    target: &str,
    executable: &Path,
    database: &Path,
) -> Result<ScanReport, String> {
    let catalogue = load_catalog()?;

    let check = catalogue
        .iter()
        .find(|check| check.id == CHECK_ID)
        .ok_or_else(|| "Read-only check is missing from the catalogue".to_owned())?;

    if check.probe_policy != ProbePolicy::ReadOnly {
        return Err("The selected check has not been approved as read-only".into());
    }

    let detection = detect_geoserver(target, None).await?;

    if !detection.likely_geoserver {
        return Err("GeoServer identification was inconclusive; scan not started".into());
    }

    let engine_version = check_nuclei(executable).await?;
    let mut db = open_database(database).await?;

    let id = sqlx::query(
        "INSERT INTO scans
         (target, geoserver_version, check_id, engine_version, status)
         VALUES (?, ?, ?, ?, 'running')",
    )
    .bind(&detection.target)
    .bind(detection.version.as_deref())
    .bind(CHECK_ID)
    .bind(engine_version)
    .execute(&mut db)
    .await
    .map_err(|e| e.to_string())?
    .last_insert_rowid();

    let result: Result<ScanReport, String> = async {
        let output = run_engine(executable, &detection.target).await?;

        let findings: Vec<Finding> = output
            .matched_urls
            .into_iter()
            .map(|matched_at| Finding {
                cve_id: check.id.clone(),
                name: check.name.clone(),
                severity: check.severity,
                matched_at,
            })
            .collect();

        let status = if output.events == 0 {
            "inconclusive"
        } else if findings.is_empty() {
            "no_match"
        } else {
            "matches"
        };

        let report = ScanReport {
            id,
            target: detection.target.clone(),
            status: status.into(),
            reported_events: output.events,
            not_run: catalogue.len() - 1,
            findings,
        };

        save_completed(&mut db, &report, &output.diagnostics).await?;

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

    #[test]
    fn parses_matches_and_deduplicates_the_same_endpoint() {
        let line = r#"{"template-id":"CVE-2025-27505","matcher-status":true,"matched-at":"http://127.0.0.1:8080/geoserver/rest.html"}"#;

        let input = format!("{line}\n{line}\n");
        let (events, matches) = parse_events(&input, TARGET).unwrap();

        assert_eq!(events, 2);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn distinguishes_no_match_from_no_reported_events() {
        let input = r#"{"template-id":"CVE-2025-27505","matcher-status":false}"#;

        assert_eq!(parse_events(input, TARGET).unwrap(), (1, vec![]));

        assert_eq!(parse_events("", TARGET).unwrap(), (0, vec![]));
    }

    #[test]
    fn rejects_failed_requests_other_checks_and_out_of_scope_matches() {
        for input in [
            "not json",
            r#"{"template-id":"CVE-2025-27505","matcher-status":false,"error":"connection refused"}"#,
            r#"{"template-id":"CVE-2024-36401","matcher-status":true,"matched-at":"http://127.0.0.1:8080/geoserver/rest.html"}"#,
            r#"{"template-id":"CVE-2025-27505","matcher-status":true,"matched-at":"https://example.com/rest.html"}"#,
        ] {
            assert!(parse_events(input, TARGET).is_err());
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
        .bind(CHECK_ID)
        .execute(&mut db)
        .await
        .unwrap()
        .last_insert_rowid();

        let report = ScanReport {
            id,
            target: TARGET.into(),
            status: "matches".into(),
            reported_events: 1,
            not_run: 31,
            findings: vec![Finding {
                cve_id: CHECK_ID.into(),
                name: "REST index exposure".into(),
                severity: Severity::Medium,
                matched_at: format!("{TARGET}/rest.html"),
            }],
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

        db.close().await.unwrap();
    }
}

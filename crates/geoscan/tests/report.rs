use std::{path::Path, process::Command};

use sqlx::{Connection, SqliteConnection, sqlite::SqliteConnectOptions};

async fn legacy_scan(path: &Path) {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true);
    let mut db = SqliteConnection::connect_with(&options).await.unwrap();
    for ddl in [
        "CREATE TABLE scans (id INTEGER PRIMARY KEY, target TEXT, geoserver_version TEXT, status TEXT, reported_events INTEGER)",
        "CREATE TABLE findings (id INTEGER PRIMARY KEY, scan_id INTEGER, cve_id TEXT, matched_at TEXT, details_json TEXT)",
        "CREATE TABLE scan_checks (scan_id INTEGER, cve_id TEXT, details_json TEXT)",
    ] {
        sqlx::query(ddl).execute(&mut db).await.unwrap();
    }
    sqlx::query(
        "INSERT INTO scans VALUES (42, 'http://localhost:8080/maps/', '2.28.2', 'matches', 2)",
    )
    .execute(&mut db)
    .await
    .unwrap();
    let matched = "http://localhost:8080/maps/wfs?service=WFS&version=1.0.0&request=GetFeature&typeName=lesson:locations&maxFeatures=1&outputFormat=application/json&CQL_FILTER=jsonArrayContains(%22payload_json%22,%27/a%27,%27x%27%27%27)%20%3D%20true";
    sqlx::query(
        "INSERT INTO findings VALUES (1, 42, 'CVE-2026-76904', ?, '{\"name\":\"legacy finding\"}')",
    )
    .bind(matched)
    .execute(&mut db)
    .await
    .unwrap();
    for (cve, status, matches) in [
        ("CVE-2025-27505", "no_match", 0),
        ("CVE-2026-76904", "matches", 1),
    ] {
        let details = serde_json::json!({
            "cve_id": cve, "status": status, "ran": true, "reported_events": 1,
            "matches": matches, "note": "Saved check", "diagnostics": "", "error": null,
        });
        sqlx::query("INSERT INTO scan_checks VALUES (42, ?, ?)")
            .bind(cve)
            .bind(details.to_string())
            .execute(&mut db)
            .await
            .unwrap();
    }
    db.close().await.unwrap();
}

#[tokio::test]
async fn saved_legacy_finding_gets_sourced_severity_and_correct_reproduction_without_db_changes() {
    let directory = tempfile::tempdir().unwrap();
    let db = directory.path().join("scan.db");
    legacy_scan(&db).await;
    let before = std::fs::read(&db).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_geoscan"))
        .args(["report", "--scan-id", "42", "--db"])
        .arg(&db)
        .env("NO_COLOR", "1")
        .env_remove("GEOSCAN_PASSWORD")
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "Scan #42",
        "CRITICAL",
        "9.8 (CVE record",
        "9.1 (GeoServer advisory",
        "REPRODUCE THIS FINDING",
        "typeName=lesson:locations",
        "payload_json",
        "/maps/wfs",
        "NO MATCH",
        "MATCHED",
    ] {
        assert!(text.contains(expected), "missing {expected}");
    }
    assert!(!text.contains('\u{1b}'));
    assert_eq!(std::fs::read(&db).unwrap(), before);
}

#[tokio::test]
async fn latest_saved_report_exports_only_json_with_reproduction_and_metadata() {
    let directory = tempfile::tempdir().unwrap();
    let db = directory.path().join("scan.db");
    legacy_scan(&db).await;
    let output = Command::new(env!("CARGO_BIN_EXE_geoscan"))
        .args(["report", "--json", "--db"])
        .arg(&db)
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["id"], 42);
    assert_eq!(report["not_run"], 30);
    let finding = &report["findings"][0];
    assert_eq!(finding["severity"], "critical");
    assert_eq!(finding["cvss"][0]["score"], 9.8);
    assert_eq!(finding["reproduction"].as_array().unwrap().len(), 2);
    assert!(
        finding["reproduction"][1]["command"]
            .as_str()
            .unwrap()
            .contains("x'''")
    );
    assert!(
        finding["reproduction"][1]["expected"]
            .as_str()
            .unwrap()
            .contains("Unterminated identifier")
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn missing_report_database_is_not_created_and_invalid_scan_ids_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let db = directory.path().join("missing.db");
    let output = Command::new(env!("CARGO_BIN_EXE_geoscan"))
        .args(["report", "--db"])
        .arg(&db)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!db.exists());
    let output = Command::new(env!("CARGO_BIN_EXE_geoscan"))
        .args(["report", "--scan-id", "0"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

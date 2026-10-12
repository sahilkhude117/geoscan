use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use geoscan_api::{AppState, Config, ScanFuture, ScanRequest, ScanRunner, ScannerStatus, router};
use geoscan_core::scan::read_scan_report;
use serde_json::{Value, json};
use sqlx::{Connection, SqliteConnection};
use tokio::sync::{Notify, oneshot};
use tower::ServiceExt;

const TARGET: &str = "http://127.0.0.1:8080/geoserver";

struct FixtureRunner {
    gate: Arc<Notify>,
    fail: bool,
}

impl ScanRunner for FixtureRunner {
    fn run(
        &self,
        request: ScanRequest,
        config: Config,
        started: oneshot::Sender<i64>,
    ) -> ScanFuture {
        let gate = self.gate.clone();
        let fail = self.fail;
        Box::pin(async move {
            let options = sqlx::sqlite::SqliteConnectOptions::new().filename(&config.database);
            let mut db = SqliteConnection::connect_with(&options)
                .await
                .map_err(|error| error.to_string())?;
            let id = sqlx::query("INSERT INTO scans (target,geoserver_version,check_id,engine_version,status) VALUES (?,'2.28.2','CVE-2025-27505','fixture','running')")
                .bind(&request.target).execute(&mut db).await.map_err(|error| error.to_string())?.last_insert_rowid();
            let _ = started.send(id);
            gate.notified().await;
            if fail {
                return Err("raw failure: very-secret-password".into());
            }
            sqlx::query("INSERT INTO findings (scan_id,cve_id,matched_at,details_json) VALUES (?,'CVE-2025-27505',?,'{}')")
                .bind(id).bind(format!("{}rest.html",request.target)).execute(&mut db).await.map_err(|error| error.to_string())?;
            sqlx::query("UPDATE scans SET status='matches', reported_events=1, finished_at=CURRENT_TIMESTAMP WHERE id=?")
                .bind(id).execute(&mut db).await.map_err(|error| error.to_string())?;
            db.close().await.map_err(|error| error.to_string())?;
            read_scan_report(&config.database, Some(id)).await
        })
    }
}

async fn setup(fail: bool) -> (tempfile::TempDir, AppState, Router, Arc<Notify>) {
    let dir = tempfile::tempdir().unwrap();
    let gate = Arc::new(Notify::new());
    let state = AppState::with_runner(
        Config {
            database: dir.path().join("test.db"),
            ..Config::default()
        },
        Arc::new(FixtureRunner {
            gate: gate.clone(),
            fail,
        }),
        ScannerStatus {
            available: true,
            version: Some("fixture".into()),
            error: None,
        },
    )
    .await
    .unwrap();
    let app = router(state.clone());
    (dir, state, app, gate)
}

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    payload: Option<Value>,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let mut builder = Request::builder().method(method).uri(path);
    let body = match payload {
        Some(payload) => {
            builder = builder.header("content-type", "application/json");
            Body::from(payload.to_string())
        }
        None => Body::empty(),
    };
    let response = app
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let value = serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
        .unwrap();
    (status, headers, value)
}

async fn wait(app: &Router, id: i64, terminal: bool) -> Value {
    for _ in 0..200 {
        let (_, _, job) = call(app, "GET", &format!("/api/v1/jobs/{id}"), None).await;
        let finished = matches!(
            job["state"].as_str(),
            Some("completed" | "failed" | "interrupted")
        );
        if (terminal && finished) || (!terminal && job["scan_id"].as_i64().is_some()) {
            return job;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    panic!("job did not reach expected state");
}

#[tokio::test]
async fn new_api_has_empty_history_and_distinguishes_catalogue_from_coverage() {
    let (_dir, state, app, _gate) = setup(false).await;
    let (status, headers, health) = call(&app, "GET", "/api/v1/health", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(health["supported_checks"].as_array().unwrap().len(), 2);
    assert_eq!(health["catalog_entries"], 32);
    let (_, _, catalog) = call(&app, "GET", "/api/v1/checks", None).await;
    assert_eq!(catalog["items"].as_array().unwrap().len(), 32);
    let (_, _, page) = call(&app, "GET", "/api/v1/scans", None).await;
    assert_eq!(page["total"], 0);
    assert_eq!(page["items"], json!([]));
    state.shutdown().await;
}

#[tokio::test]
async fn accepted_job_rejects_overlap_then_links_a_saved_report_without_credentials() {
    let (dir, state, app, gate) = setup(false).await;
    let (status, headers, queued) = call(
        &app,
        "POST",
        "/api/v1/scans",
        Some(json!({"target":TARGET,"username":"admin","password":"very-secret-password"})),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let id = queued["id"].as_i64().unwrap();
    assert_eq!(headers["location"], format!("/api/v1/jobs/{id}"));
    assert!(queued.get("password").is_none());
    let progress = wait(&app, id, false).await;
    let scan_id = progress["scan_id"].as_i64().unwrap();
    assert_eq!(
        call(&app, "GET", &format!("/api/v1/scans/{scan_id}"), None)
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/api/v1/scans",
            Some(json!({"target":TARGET}))
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    gate.notify_one();
    let job = wait(&app, id, true).await;
    assert_eq!(job["state"], "completed");
    assert_eq!(job["outcome"], "matches");
    let (status, _, report) = call(&app, "GET", &format!("/api/v1/scans/{scan_id}"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(report["findings"][0]["cve_id"], "CVE-2025-27505");
    assert!(
        !report["findings"][0]["reproduction"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let (_, _, history) = call(&app, "GET", "/api/v1/scans?limit=1&offset=0", None).await;
    assert_eq!(history["items"][0]["finding_count"], 1);
    state.shutdown().await;
    let bytes = std::fs::read(dir.path().join("test.db")).unwrap();
    assert!(
        !bytes
            .windows(b"very-secret-password".len())
            .any(|part| part == b"very-secret-password")
    );
}

#[tokio::test]
async fn runner_failure_is_terminal_and_does_not_leak_raw_output() {
    let (_dir, state, app, gate) = setup(true).await;
    let (_, _, queued) = call(
        &app,
        "POST",
        "/api/v1/scans",
        Some(json!({"target":TARGET})),
    )
    .await;
    let id = queued["id"].as_i64().unwrap();
    wait(&app, id, false).await;
    gate.notify_one();
    let job = wait(&app, id, true).await;
    assert_eq!(job["state"], "failed");
    assert!(!job.to_string().contains("very-secret-password"));
    let (_, _, report) = call(
        &app,
        "GET",
        &format!("/api/v1/scans/{}", job["scan_id"]),
        None,
    )
    .await;
    assert_eq!(report["status"], "failed");
    state.shutdown().await;
}

#[tokio::test]
async fn validation_rejects_unknown_fields_targets_credentials_and_bad_identifiers() {
    let (_dir, state, app, _gate) = setup(false).await;
    for (payload, status) in [
        (
            json!({"target":"http://other.invalid/geoserver"}),
            StatusCode::FORBIDDEN,
        ),
        (
            json!({"target":"http://admin:secret@127.0.0.1:8080/geoserver"}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"target":TARGET,"username":"admin"}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"target":TARGET,"sqli_property":"name;injection"}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"target":TARGET,"nuclei":"/bin/sh"}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
    ] {
        let (actual, _, body) = call(&app, "POST", "/api/v1/scans", Some(payload)).await;
        assert_eq!(actual, status);
        assert!(body["error"]["code"].is_string());
        assert!(!body.to_string().contains("secret"));
    }
    for path in [
        "/api/v1/jobs/0",
        "/api/v1/scans/nope",
        "/api/v1/scans?limit=101",
        "/api/v1/jobs?offset=-1",
    ] {
        assert_eq!(
            call(&app, "GET", path, None).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        call(&app, "GET", "/api/v1/jobs/999", None).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(&app, "GET", "/api/v1/scans/999", None).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(&app, "POST", "/api/v1/scans", None).await.0,
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    state.shutdown().await;
}

#[tokio::test]
async fn startup_recovers_only_scans_linked_to_interrupted_api_jobs() {
    let (dir, state, _app, _gate) = setup(false).await;
    state.shutdown().await;
    let options = sqlx::sqlite::SqliteConnectOptions::new().filename(dir.path().join("test.db"));
    let mut db = SqliteConnection::connect_with(&options).await.unwrap();
    for _ in 0..2 {
        sqlx::query("INSERT INTO scans (target,check_id,engine_version,status) VALUES (?,'fixture','fixture','running')").bind(TARGET).execute(&mut db).await.unwrap();
    }
    sqlx::query("INSERT INTO scan_jobs (state,target,sqli_layer,sqli_property,scan_id) VALUES ('running',?,'demo:items','json_data',1)").bind(TARGET).execute(&mut db).await.unwrap();
    db.close().await.unwrap();
    let next = AppState::with_runner(
        Config {
            database: dir.path().join("test.db"),
            ..Config::default()
        },
        Arc::new(FixtureRunner {
            gate: Arc::new(Notify::new()),
            fail: false,
        }),
        ScannerStatus {
            available: true,
            version: None,
            error: None,
        },
    )
    .await
    .unwrap();
    let app = router(next.clone());
    let (_, _, job) = call(&app, "GET", "/api/v1/jobs/1", None).await;
    assert_eq!(job["state"], "interrupted");
    let (_, _, history) = call(&app, "GET", "/api/v1/scans", None).await;
    assert_eq!(history["items"][0]["status"], "running");
    assert_eq!(history["items"][1]["status"], "failed");
    next.shutdown().await;
}

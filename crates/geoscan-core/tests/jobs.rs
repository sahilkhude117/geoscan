use std::sync::Arc;

use geoscan_core::{
    scan::read_scan_report,
    web::{AppState, Config, Job, JobError, ScanFuture, ScanRequest, ScanRunner, ScannerStatus},
};
use sqlx::{Connection, SqliteConnection};
use tokio::sync::{Notify, oneshot};

struct Fixture {
    gate: Arc<Notify>,
    fail: bool,
}
impl ScanRunner for Fixture {
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
            let id=sqlx::query("INSERT INTO scans (target,check_id,engine_version,status) VALUES (?,'fixture','fixture','running')")
                .bind(&request.target).execute(&mut db).await.map_err(|error|error.to_string())?.last_insert_rowid();
            let _ = started.send(id);
            gate.notified().await;
            if fail {
                return Err("Raw output: secret-password".into());
            }
            sqlx::query(
                "UPDATE scans SET status='no_match', finished_at=CURRENT_TIMESTAMP WHERE id=?",
            )
            .bind(id)
            .execute(&mut db)
            .await
            .map_err(|error| error.to_string())?;
            db.close().await.map_err(|error| error.to_string())?;
            read_scan_report(&config.database, Some(id)).await
        })
    }
}

fn input() -> ScanRequest {
    serde_json::from_str(r#"{"target":"http://127.0.0.1:8080/geoserver/","username":"admin","password":"secret-password"}"#).unwrap()
}

async fn setup(fail: bool) -> (tempfile::TempDir, AppState, Arc<Notify>) {
    let dir = tempfile::tempdir().unwrap();
    let gate = Arc::new(Notify::new());
    let state = AppState::with_runner(
        Config {
            database: dir.path().join("jobs.db"),
            ..Config::default()
        },
        Arc::new(Fixture {
            gate: gate.clone(),
            fail,
        }),
        ScannerStatus {
            available: true,
            version: None,
            error: None,
        },
    )
    .await
    .unwrap();
    (dir, state, gate)
}

async fn wait(state: &AppState, id: i64, terminal: bool) -> Job {
    for _ in 0..200 {
        let job = state.job(id).await.unwrap();
        let done = matches!(job.state.as_str(), "completed" | "failed" | "interrupted");
        if (terminal && done) || (!terminal && job.scan_id.is_some()) {
            return job;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    panic!("job did not reach its expected state");
}

#[tokio::test]
async fn jobs_are_persisted_bounded_and_link_to_the_same_cli_report() {
    let (dir, state, gate) = setup(false).await;
    assert_eq!(state.jobs(25, 0).await.unwrap().1, 0);
    let queued = state.submit(input()).await.unwrap();
    assert_eq!(queued.state, "queued");
    assert!(matches!(state.submit(input()).await, Err(JobError::Busy)));
    let progress = wait(&state, queued.id, false).await;
    assert_eq!(progress.state, "running");
    let scan_id = progress.scan_id.unwrap();
    gate.notify_one();
    let finished = wait(&state, queued.id, true).await;
    assert_eq!(finished.state, "completed");
    assert_eq!(finished.outcome.as_deref(), Some("no_match"));
    assert_eq!(
        read_scan_report(state.database(), Some(scan_id))
            .await
            .unwrap()
            .status,
        "no_match"
    );
    state.shutdown().await;
    assert!(matches!(state.submit(input()).await, Err(JobError::Busy)));
    let bytes = std::fs::read(dir.path().join("jobs.db")).unwrap();
    assert!(
        !bytes
            .windows(b"secret-password".len())
            .any(|part| part == b"secret-password")
    );
}

#[tokio::test]
async fn failures_finish_both_job_and_scan_without_saving_raw_output() {
    let (_dir, state, gate) = setup(true).await;
    let queued = state.submit(input()).await.unwrap();
    let running = wait(&state, queued.id, false).await;
    gate.notify_one();
    let job = wait(&state, queued.id, true).await;
    assert_eq!(job.state, "failed");
    assert!(!job.error.unwrap().contains("secret-password"));
    let report = read_scan_report(state.database(), running.scan_id)
        .await
        .unwrap();
    assert_eq!(report.status, "failed");
    state.shutdown().await;
}

#[tokio::test]
async fn restart_marks_only_linked_api_work_interrupted() {
    let (dir, state, _gate) = setup(false).await;
    state.shutdown().await;
    let options = sqlx::sqlite::SqliteConnectOptions::new().filename(dir.path().join("jobs.db"));
    let mut db = SqliteConnection::connect_with(&options).await.unwrap();
    for _ in 0..2 {
        sqlx::query("INSERT INTO scans (target,check_id,engine_version,status) VALUES ('http://127.0.0.1:8080/geoserver/','fixture','fixture','running')").execute(&mut db).await.unwrap();
    }
    sqlx::query("INSERT INTO scan_jobs (state,target,sqli_layer,sqli_property,scan_id) VALUES ('running','http://127.0.0.1:8080/geoserver/','demo:items','json_data',1)").execute(&mut db).await.unwrap();
    db.close().await.unwrap();
    let next = AppState::with_runner(
        Config {
            database: dir.path().join("jobs.db"),
            ..Config::default()
        },
        Arc::new(Fixture {
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
    assert_eq!(next.job(1).await.unwrap().state, "interrupted");
    assert_eq!(
        read_scan_report(next.database(), Some(1))
            .await
            .unwrap()
            .status,
        "failed"
    );
    assert_eq!(
        read_scan_report(next.database(), Some(2))
            .await
            .unwrap()
            .status,
        "running"
    );
    next.shutdown().await;
}

#[tokio::test]
async fn timed_out_job_stops_execution_and_finishes_its_linked_scan() {
    let (_dir, state, _gate) = setup(false).await;
    let queued = state.submit(input()).await.unwrap();
    let progress = wait(&state, queued.id, false).await;
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(241)).await;
    tokio::time::resume();
    let job = wait(&state, queued.id, true).await;
    assert_eq!(job.state, "failed");
    assert!(job.error.unwrap().contains("240-second"));
    assert_eq!(
        read_scan_report(state.database(), progress.scan_id)
            .await
            .unwrap()
            .status,
        "failed"
    );
    state.shutdown().await;
}

struct PanicRunner;
impl ScanRunner for PanicRunner {
    fn run(
        &self,
        _request: ScanRequest,
        _config: Config,
        _started: oneshot::Sender<i64>,
    ) -> ScanFuture {
        Box::pin(async { panic!("synthetic runner failure") })
    }
}

#[tokio::test]
async fn unexpected_runner_panic_becomes_a_failed_job() {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::with_runner(
        Config {
            database: dir.path().join("jobs.db"),
            ..Config::default()
        },
        Arc::new(PanicRunner),
        ScannerStatus {
            available: true,
            version: None,
            error: None,
        },
    )
    .await
    .unwrap();
    let queued = state.submit(input()).await.unwrap();
    let job = wait(&state, queued.id, true).await;
    assert_eq!(job.state, "failed");
    assert_eq!(job.scan_id, None);
    assert_eq!(
        job.error.as_deref(),
        Some("Scanner task stopped unexpectedly")
    );
    state.shutdown().await;
}

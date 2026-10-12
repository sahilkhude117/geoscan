use serde::Serialize;
use sqlx::{Row, SqlitePool};
use tokio::sync::{OwnedSemaphorePermit, oneshot};

use super::{AppState, JobError, ScanRequest};

#[derive(Serialize)]
pub struct Job {
    pub id: i64,
    pub state: String,
    pub target: String,
    pub sqli_layer: String,
    pub sqli_property: String,
    pub misconfigurations: crate::misconfig::Options,
    pub scan_id: Option<i64>,
    pub outcome: Option<String>,
    pub error: Option<String>,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
}

pub(crate) fn from_row(row: sqlx::sqlite::SqliteRow) -> Result<Job, JobError> {
    let options: String = row.get("options_json");
    let mut options: serde_json::Value =
        serde_json::from_str(&options).map_err(|_| JobError::Database)?;
    // Historical jobs stored this opt-in flag. The check is now mandatory;
    // discard that flag when reading history, without accepting it in new requests.
    if let Some(options) = options.as_object_mut() {
        options.remove("check_default_credentials");
    }
    let misconfigurations = serde_json::from_value(options).map_err(|_| JobError::Database)?;
    Ok(Job {
        id: row.get("id"),
        state: row.get("state"),
        target: row.get("target"),
        sqli_layer: row.get("sqli_layer"),
        sqli_property: row.get("sqli_property"),
        misconfigurations,
        scan_id: row.get("scan_id"),
        outcome: row.get("outcome"),
        error: row.get("error"),
        created_at: row.get("created_at"),
        started_at: row.get("started_at"),
        finished_at: row.get("finished_at"),
    })
}

pub(crate) async fn initialize(pool: &SqlitePool) -> Result<(), String> {
    let setup = async {
        sqlx::query("CREATE TABLE IF NOT EXISTS scan_jobs (
            id INTEGER PRIMARY KEY,
            state TEXT NOT NULL CHECK (state IN ('queued','running','completed','failed','interrupted')),
            target TEXT NOT NULL, sqli_layer TEXT NOT NULL, sqli_property TEXT NOT NULL,
            scan_id INTEGER REFERENCES scans(id), outcome TEXT, error TEXT,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
            started_at TEXT, finished_at TEXT, options_json TEXT NOT NULL DEFAULT '{}'
        )").execute(pool).await?;
        let columns=sqlx::query("PRAGMA table_info(scan_jobs)").fetch_all(pool).await?;
        if !columns.iter().any(|row|row.get::<String,_>("name")=="options_json") {
            sqlx::query("ALTER TABLE scan_jobs ADD COLUMN options_json TEXT NOT NULL DEFAULT '{}'").execute(pool).await?;
        }
        sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS one_active_api_job ON scan_jobs ((1)) WHERE state IN ('queued','running')")
            .execute(pool).await?;
        let mut transaction = pool.begin().await?;
        // Only recover scans owned by interrupted API jobs; leave CLI scans alone.
        sqlx::query("UPDATE scans SET status='failed', error='API restarted during this scan', finished_at=CURRENT_TIMESTAMP
            WHERE status='running' AND id IN (SELECT scan_id FROM scan_jobs WHERE state IN ('queued','running'))")
            .execute(&mut *transaction).await?;
        sqlx::query("UPDATE scan_jobs SET state='interrupted', error='API restarted during this scan; submit a new scan',
            finished_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE state IN ('queued','running')")
            .execute(&mut *transaction).await?;
        transaction.commit().await
    }.await;
    setup.map_err(|error: sqlx::Error| error.to_string())
}

pub(crate) async fn get(pool: &SqlitePool, id: i64) -> Result<Job, JobError> {
    sqlx::query("SELECT * FROM scan_jobs WHERE id=?")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .map(from_row)
        .transpose()?
        .ok_or(JobError::NotFound)
}

pub(crate) async fn submit(state: AppState, request: ScanRequest) -> Result<Job, JobError> {
    let mut tasks = state.tasks.lock().await;
    let permit = state
        .slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| JobError::Busy)?;
    let result = sqlx::query(
        "INSERT INTO scan_jobs (state,target,sqli_layer,sqli_property,options_json) VALUES ('queued',?,?,?,?)",
    )
    .bind(&request.target)
    .bind(&request.sqli_layer)
    .bind(&request.sqli_property)
    .bind(serde_json::to_string(&request.misconfigurations).map_err(|_|JobError::Database)?)
    .execute(&state.pool)
    .await
    .map_err(|error| {
        if error
            .as_database_error()
            .is_some_and(|error| error.is_unique_violation())
        {
            JobError::Busy
        } else {
            JobError::from(error)
        }
    })?;
    let id = result.last_insert_rowid();
    let job = get(&state.pool, id).await?;
    // Keep the task registered before returning 202, including during shutdown.
    tasks.retain(|task| !task.is_finished());
    tasks.push(tokio::spawn(run(state.clone(), id, request, permit)));
    Ok(job)
}

async fn run(state: AppState, id: i64, request: ScanRequest, _permit: OwnedSemaphorePermit) {
    if sqlx::query("UPDATE scan_jobs SET state='running', started_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id=?")
        .bind(id).execute(&state.pool).await.is_err() {
        let _ = finish(&state.pool, id, None, None, Some("Could not start the saved scan job".into())).await;
        return;
    }
    let (started, mut receiver) = oneshot::channel();
    let runner = state.runner.clone();
    // The extra task converts an unexpected runner panic into a failed job.
    let mut execution = tokio::spawn(runner.run(request, state.config.clone(), started));
    let mut scan_id = None;
    let wait = async {
        tokio::select! {
            biased;
            result = &mut receiver => {
                if let Ok(id_of_scan) = result {
                    scan_id = Some(id_of_scan);
                    let _ = sqlx::query("UPDATE scan_jobs SET scan_id=? WHERE id=?")
                        .bind(id_of_scan).bind(id).execute(&state.pool).await;
                }
                (&mut execution).await
            }
            result = &mut execution => {
                if let Ok(id_of_scan) = receiver.try_recv() { scan_id = Some(id_of_scan); }
                result
            }
        }
    };
    let result = tokio::time::timeout(std::time::Duration::from_secs(240), wait).await;
    let (outcome, error) = match result {
        Ok(Ok(Ok(report))) => {
            scan_id = Some(report.id);
            (Some(report.status), None)
        }
        // Do not put credentials or raw process/network output in job errors.
        Ok(Ok(Err(_))) => (
            None,
            Some(
                "Scan could not finish; check target reachability and scanner installation".into(),
            ),
        ),
        Ok(Err(_)) => (None, Some("Scanner task stopped unexpectedly".into())),
        Err(_) => {
            execution.abort();
            let _ = execution.await;
            (None, Some("Scan exceeded the 240-second job limit".into()))
        }
    };
    if finish(&state.pool, id, scan_id, outcome, error)
        .await
        .is_err()
    {
        eprintln!("Could not save final state of API job #{id}; inspect the database");
    }
}

async fn finish(
    pool: &SqlitePool,
    id: i64,
    scan_id: Option<i64>,
    outcome: Option<String>,
    error: Option<String>,
) -> Result<(), sqlx::Error> {
    let mut transaction = pool.begin().await?;
    if let (Some(scan_id), Some(error)) = (scan_id, error.as_deref()) {
        sqlx::query("UPDATE scans SET status='failed', error=?, finished_at=CURRENT_TIMESTAMP WHERE id=? AND status='running'")
            .bind(error).bind(scan_id).execute(&mut *transaction).await?;
    }
    sqlx::query("UPDATE scan_jobs SET state=?, scan_id=?, outcome=?, error=?, finished_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id=?")
        .bind(if error.is_some() { "failed" } else { "completed" })
        .bind(scan_id).bind(outcome).bind(error).bind(id)
        .execute(&mut *transaction).await?;
    transaction.commit().await
}

//! Transport-independent background jobs shared with the HTTP adapter.

mod jobs;

use std::{future::Future, path::PathBuf, pin::Pin, sync::Arc};

use crate::{
    check_nuclei,
    detect::normalize_target,
    scan::{ScanReport, SqliTarget, initialize_database, scan_geoserver_tracked},
};
use serde::{Deserialize, Serialize};
use sqlx::{SqlitePool, sqlite::SqliteConnectOptions};
use tokio::sync::{Semaphore, oneshot};

pub use jobs::Job;

#[derive(Clone)]
pub struct Config {
    pub database: PathBuf,
    pub engine: PathBuf,
    pub allowed_targets: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            database: "geoscan.db".into(),
            engine: "nuclei".into(),
            allowed_targets: vec!["http://127.0.0.1:8080/geoserver".into()],
        }
    }
}

/// Login exists only for the lifetime of this request/job; never persist it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanRequest {
    pub target: String,
    pub username: Option<String>,
    pub password: Option<String>,
    #[serde(default = "default_layer")]
    pub sqli_layer: String,
    #[serde(default = "default_property")]
    pub sqli_property: String,
}

fn default_layer() -> String {
    crate::scan::DEFAULT_LAYER.into()
}

fn default_property() -> String {
    crate::scan::DEFAULT_PROPERTY.into()
}

pub type ScanFuture = Pin<Box<dyn Future<Output = Result<ScanReport, String>> + Send>>;

/// Injectable execution boundary lets HTTP lifecycle tests run without sockets.
pub trait ScanRunner: Send + Sync {
    fn run(
        &self,
        request: ScanRequest,
        config: Config,
        started: oneshot::Sender<i64>,
    ) -> ScanFuture;
}

struct NativeRunner;

impl ScanRunner for NativeRunner {
    fn run(
        &self,
        request: ScanRequest,
        config: Config,
        started: oneshot::Sender<i64>,
    ) -> ScanFuture {
        Box::pin(async move {
            let selected = SqliTarget::new(&request.sqli_layer, &request.sqli_property)?;
            let auth = request.username.as_deref().zip(request.password.as_deref());
            scan_geoserver_tracked(
                &request.target,
                &config.engine,
                &config.database,
                auth,
                &selected,
                Some(started),
            )
            .await
        })
    }
}

#[derive(Clone, Serialize)]
pub struct ScannerStatus {
    pub available: bool,
    pub version: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone)]
pub struct AppState {
    config: Config,
    pool: SqlitePool,
    runner: Arc<dyn ScanRunner>,
    scanner: ScannerStatus,
    slots: Arc<Semaphore>,
    tasks: Arc<tokio::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl AppState {
    pub async fn new(config: Config) -> Result<Self, String> {
        let scanner = match check_nuclei(&config.engine).await {
            Ok(version) => ScannerStatus {
                available: true,
                version: Some(version),
                error: None,
            },
            Err(error) => ScannerStatus {
                available: false,
                version: None,
                error: Some(error),
            },
        };
        Self::with_runner(config, Arc::new(NativeRunner), scanner).await
    }

    pub async fn with_runner(
        mut config: Config,
        runner: Arc<dyn ScanRunner>,
        scanner: ScannerStatus,
    ) -> Result<Self, String> {
        if config.allowed_targets.is_empty() {
            return Err("Configure at least one allowed GeoServer application URL".into());
        }
        config.allowed_targets = config
            .allowed_targets
            .iter()
            .map(|target| normalize_target(target).map(|url| url.to_string()))
            .collect::<Result<_, _>>()?;
        initialize_database(&config.database).await?;
        let options = SqliteConnectOptions::new()
            .filename(&config.database)
            .foreign_keys(true)
            .busy_timeout(std::time::Duration::from_secs(5));
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .map_err(|error| error.to_string())?;
        jobs::initialize(&pool).await?;
        Ok(Self {
            config,
            pool,
            runner,
            scanner,
            slots: Arc::new(Semaphore::new(1)),
            tasks: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        })
    }

    /// Stop admitting jobs and wait for the bounded current scan before exit.
    pub async fn shutdown(&self) {
        self.slots.close();
        let tasks = std::mem::take(&mut *self.tasks.lock().await);
        for task in tasks {
            let _ = task.await;
        }
        self.pool.close().await;
    }
}

/// Storage and scheduling errors contain no request credentials or raw output.
#[derive(Debug)]
pub enum JobError {
    Busy,
    NotFound,
    Database,
}
impl From<sqlx::Error> for JobError {
    fn from(_: sqlx::Error) -> Self {
        Self::Database
    }
}

impl AppState {
    pub fn database(&self) -> &std::path::Path {
        &self.config.database
    }
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
    pub fn scanner(&self) -> &ScannerStatus {
        &self.scanner
    }
    pub fn allowed_targets(&self) -> &[String] {
        &self.config.allowed_targets
    }
    pub async fn submit(&self, request: ScanRequest) -> Result<Job, JobError> {
        jobs::submit(self.clone(), request).await
    }
    pub async fn job(&self, id: i64) -> Result<Job, JobError> {
        jobs::get(&self.pool, id).await
    }
    pub async fn jobs(&self, limit: i64, offset: i64) -> Result<(Vec<Job>, i64), JobError> {
        let total = sqlx::query_scalar("SELECT count(*) FROM scan_jobs")
            .fetch_one(&self.pool)
            .await?;
        let items = sqlx::query("SELECT * FROM scan_jobs ORDER BY id DESC LIMIT ? OFFSET ?")
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(jobs::from_row)
            .collect();
        Ok((items, total))
    }
}

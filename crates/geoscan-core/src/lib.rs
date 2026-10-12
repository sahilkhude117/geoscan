//! Shared scanner, storage and background jobs used by the CLI and HTTP API.

use std::{path::Path, time::Duration};

use sqlx::{Connection, SqliteConnection, sqlite::SqliteConnectOptions};
use tokio::{process::Command, time::timeout};

/// Check that the configured Nuclei executable runs and reports its version.
/// This command does not send scanning requests to a target.
pub async fn check_nuclei(executable: &Path) -> Result<String, String> {
    // Pass arguments directly to the executable, without invoking a shell.
    let mut command = Command::new(executable);
    command
        .env_remove("GEOSCAN_PASSWORD")
        .args(["-version", "-nc"])
        .kill_on_drop(true);

    let output = timeout(Duration::from_secs(10), command.output())
        .await
        .map_err(|_| "Nuclei version check timed out after 10 seconds".to_owned())?
        .map_err(|error| format!("Could not run {}: {error}", executable.display()))?;

    if !output.status.success() {
        return Err(format!(
            "Nuclei version check exited with {}",
            output.status
        ));
    }

    // Nuclei may write its version to stderr rather than stdout.
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    text.lines()
        .find_map(|line| {
            line.split_once("Nuclei Engine Version:")
                .map(|(_, version)| version.trim().to_owned())
        })
        .filter(|version| !version.is_empty())
        .ok_or_else(|| "The executable did not report a Nuclei engine version".to_owned())
}

/// Open or create our SQLite file and verify a write/read operation.
/// Roll back the transaction so the check leaves no application tables behind.
pub async fn check_database(path: &Path) -> Result<(), sqlx::Error> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .busy_timeout(Duration::from_secs(5));

    let mut connection = SqliteConnection::connect_with(&options).await?;
    let mut transaction = connection.begin().await?;

    // A real database write also checks access to SQLite's journal directory.
    sqlx::query("CREATE TABLE __geoscan_doctor_probe (value INTEGER NOT NULL)")
        .execute(&mut *transaction)
        .await?;

    sqlx::query("INSERT INTO __geoscan_doctor_probe (value) VALUES (1)")
        .execute(&mut *transaction)
        .await?;

    let value: i64 = sqlx::query_scalar("SELECT value FROM __geoscan_doctor_probe")
        .fetch_one(&mut *transaction)
        .await?;

    if value != 1 {
        return Err(sqlx::Error::Protocol(
            "SQLite read/write check returned an unexpected value".to_owned(),
        ));
    }

    transaction.rollback().await?;
    connection.close().await?;
    Ok(())
}

pub mod catalog;
pub mod detect;
pub mod scan;
pub mod web;

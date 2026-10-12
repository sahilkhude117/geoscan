use std::{path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};
use geoscan_core::{check_database, check_nuclei};

use geoscan_core::detect::detect_geoserver;

// Clap turns these Rust types into commands, flags, and --help text.
#[derive(Parser)]
#[command(name = "geoscan", version, about = "GeoServer security checker")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check Nuclei availability and SQLite read/write access
    Doctor {
        /// Database file to open or create (relative to the current directory)
        #[arg(long, default_value = "geoscan.db", value_name = "FILE")]
        db: PathBuf,

        /// Nuclei executable name or full path
        #[arg(long, default_value = "nuclei", value_name = "EXECUTABLE")]
        nuclei: PathBuf,
    },

    /// Check whether given url is geoserver
    Detect {
        #[arg(long)]
        target: String,

        #[arg(long)]
        username: Option<String>,
    },
}

// Tokio supplies the runtime needed by our async backend functions.
#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::Doctor { db, nuclei } => {
            println!("Checking GeoScan prerequisites...\n");
            let mut ready = true;

            match check_nuclei(&nuclei).await {
                Ok(version) => println!("[OK] Nuclei {version}"),
                Err(error) => {
                    println!("[FAIL] Nuclei: {error}");
                    println!("       Install Nuclei or pass --nuclei /path/to/nuclei");
                    ready = false;
                }
            }

            match check_database(&db).await {
                Ok(()) => println!("[OK] SQLite read/write access: {}", db.display()),
                Err(error) => {
                    println!("[FAIL] SQLite: {error}");
                    println!("       Check that the parent directory exists and is writable");
                    ready = false;
                }
            }

            if ready {
                println!("\nReady for Step 2: GeoServer detection.");
                ExitCode::SUCCESS
            } else {
                println!("\nFix the failed checks and run doctor again.");
                ExitCode::FAILURE
            }
        }

        Commands::Detect { target, username } => {
            let password = if username.is_some() {
                match std::env::var("GEOSCAN_PASSWORD") {
                    Ok(value) if !value.is_empty() => Some(value),

                    _ => {
                        eprintln!("Set GEOSCAN_PASSWORD when using --username");
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                None
            };

            let auth = username.as_deref().zip(password.as_deref());

            println!("Checking GeoServer endpoints...");

            match detect_geoserver(&target, auth).await {
                Ok(report) => {
                    println!("Target: {}", report.target);
                    println!("HTTP reachable: {}", report.reachable);
                    if report.likely_geoserver {
                        println!("GeoServer likely: true");
                    } else if report.reachable {
                        println!("GeoServer identification: Inconclusive");
                    } else {
                        println!("GeoServer identification: Unreachable");
                    }
                    for evidence in &report.evidence {
                        println!("Evidence: {evidence}");
                    }
                    println!(
                        "Version: {}",
                        report.version.as_deref().unwrap_or("Unknown")
                    );
                    println!("Version check: {}", report.version_note);
                    println!("WMS: {}", report.wms);
                    println!("WFS: {}", report.wfs);

                    if report.likely_geoserver {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }

                Err(error) => {
                    eprintln!("Detection failed: {error}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

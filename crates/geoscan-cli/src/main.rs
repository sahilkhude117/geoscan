use std::{path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};
use geoscan_core::{check_database, check_nuclei};

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
    }
}

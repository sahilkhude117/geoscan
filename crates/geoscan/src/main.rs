use std::{path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};
use geoscan_core::catalog::{CveCheck, VersionScope, VersionStatus, assess_version, load_catalog};
use geoscan_core::detect::detect_geoserver;
use geoscan_core::scan::scan_geoserver;
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

    /// Check whether given url is geoserver
    Detect {
        #[arg(long)]
        target: String,

        #[arg(long)]
        username: Option<String>,
    },

    /// List CVEs or assess a release version against the catalogue
    Checks {
        #[command(subcommand)]
        command: CheckCommands,
    },

    /// Run the reviewed read-only GeoServer check
    Scan {
        #[arg(long)]
        target: String,

        #[arg(long, default_value = "nuclei")]
        nuclei: PathBuf,

        #[arg(long, default_value = "geoscan.db")]
        db: PathBuf,
    },
}

#[derive(Subcommand)]
enum CheckCommands {
    /// List researched CVEs and their future probe policies
    List {
        /// Export all catalogue metadata as JSON
        #[arg(long)]
        json: bool,
    },

    /// Show sources, scores, dates, requirements, and fixes for a CVE
    Show {
        #[arg(long, value_name = "CVE-ID")]
        id: String,
    },

    /// Compare a release version with known affected ranges (no scan requests)
    Assess {
        /// GeoServer release, such as 2.28.2; omit it for an unknown assessment
        #[arg(long, value_name = "VERSION")]
        geoserver_version: Option<String>,
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
                println!("\nPrerequisites are ready. Use detect or checks to continue.");
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

        Commands::Checks { command } => match run_checks(command) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("Catalogue error: {error}");
                ExitCode::FAILURE
            }
        },

        Commands::Scan { target, nuclei, db } => {
            println!("Running the reviewed GeoServer REST-index check...");

            match scan_geoserver(&target, &nuclei, &db).await {
                Ok(report) => {
                    println!("Scan ID: {}", report.id);
                    println!("Target: {}", report.target);
                    println!("Status: {}", report.status);
                    println!("Check: CVE-2025-27505");
                    println!("Matches: {}", report.findings.len());
                    println!("Catalogue entries not run: {}", report.not_run);
                    println!("Saved to: {}", db.display());

                    for finding in &report.findings {
                        println!(
                            "[{:?}] {} at {}",
                            finding.severity, finding.cve_id, finding.matched_at
                        );
                    }

                    println!("Results cover this check only; matches need verification.");

                    if report.status == "inconclusive" {
                        eprintln!("No request outcome was returned; inspect scans.diagnostics.");
                        ExitCode::from(2)
                    } else {
                        ExitCode::SUCCESS
                    }
                }

                Err(error) => {
                    eprintln!("Scan failed: {error}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

fn run_checks(command: CheckCommands) -> Result<(), String> {
    let checks = load_catalog()?;

    match command {
        CheckCommands::List { json: true } => {
            let output = serde_json::to_string_pretty(&checks)
                .map_err(|error| format!("Could not export catalogue: {error}"))?;
            println!("{output}");
        }
        CheckCommands::List { json: false } => {
            println!(
                "Catalogue: {} CVEs (researched coverage; active probes are separate).",
                checks.len()
            );
            for check in checks {
                let rating = &check.cvss[0];
                let published = check
                    .publication_date()
                    .expect("validated publication date");
                println!(
                    "{} [{:?} CVSS {:.1}] {} — {:?}; {:?}: {}{}",
                    check.id,
                    check.severity,
                    rating.score,
                    check.name,
                    check.probe_policy,
                    published.kind,
                    published.date,
                    if check.kev.is_some() {
                        "; CISA KEV"
                    } else {
                        ""
                    }
                );
            }
        }
        CheckCommands::Show { id } => {
            let check = checks
                .iter()
                .find(|check| check.id.eq_ignore_ascii_case(&id))
                .ok_or_else(|| format!("Unknown CVE ID: {id}"))?;
            show_check(check);
        }
        CheckCommands::Assess { geoserver_version } => {
            println!(
                "Catalogue: {} CVEs (researched coverage; active probes are separate).",
                checks.len()
            );
            println!(
                "Version: {}",
                geoserver_version.as_deref().unwrap_or("Unknown")
            );
            println!("Version assessment; configuration requirements are unverified.");
            println!("OutsideAffectedRanges refers only to this catalogue, not overall security.");

            for check in checks {
                let status = assess_version(&check, geoserver_version.as_deref())?;
                println!("{}: {status:?}", check.id);
                if check.version_scope != VersionScope::GeoServer {
                    println!("  Assessment note: {}", check.version_notes);
                }
                if status == VersionStatus::PotentiallyAffected {
                    println!("  Requirements: {}", check.prerequisites.join("; "));
                    println!("  Fixed releases: {}", check.fixed_versions.join(", "));
                    println!("  Fix: {}", check.remediation);
                    println!("  Advisory: {}", check.advisory_url);
                }
            }
        }
    }
    Ok(())
}

fn show_check(check: &CveCheck) {
    println!("{}: {}", check.id, check.name);
    println!("Type: {}", check.vulnerability_type);
    println!("Component: {}", check.component);
    println!("Description: {}", check.description);
    println!("Authentication: {}", check.authentication);
    println!("CWEs: {}", check.cwes.join(", "));
    for rating in &check.cvss {
        println!(
            "CVSS {}: {:.1} [{:?}] — {}",
            rating.version, rating.score, rating.severity, rating.source
        );
        if let Some(vector) = &rating.vector {
            println!("  Vector: {vector}");
        }
    }
    for date in &check.dates {
        println!("{:?}: {} — {}", date.kind, date.date, date.source);
    }
    if let Some(kev) = &check.kev {
        println!("CISA KEV: added {} — {}", kev.date_added, kev.source);
    }
    println!("Version scope: {:?}", check.version_scope);
    println!("Affected ranges: {}", check.affected.join(" OR "));
    if check.fixed_versions.is_empty() {
        println!("Fixed releases: Unknown");
    } else {
        println!("Fixed releases: {}", check.fixed_versions.join(", "));
    }
    println!("Version notes: {}", check.version_notes);
    println!("Requirements: {}", check.prerequisites.join("; "));
    println!("Fix: {}", check.remediation);
    println!("Advisory: {}", check.advisory_url);
    println!("Probe policy: {:?}", check.probe_policy);
    println!(
        "Template: {}",
        check.template.as_deref().unwrap_or("Not mapped")
    );
    println!("Probe notes: {}", check.template_notes);
    println!("Researched: {}", check.researched_at);
    for reference in &check.references {
        println!("Reference: {reference}");
    }
    if let Some(reported) = &check.reported_metadata {
        println!(
            "User-reported metadata: CVSS {:.1} [{:?}], published {} (see sourced values above)",
            reported.cvss_score, reported.severity, reported.published
        );
        if let Some(note) = &reported.publication_note {
            println!("  Note: {note}");
        }
    }
}

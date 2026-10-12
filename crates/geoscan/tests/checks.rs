use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    // A real installed command must not depend on the source-tree data directory.
    Command::new(env!("CARGO_BIN_EXE_geoscan"))
        .args(args)
        .current_dir(std::env::temp_dir())
        .output()
        .expect("geoscan should start")
}

fn successful_stdout(args: &[&str]) -> String {
    let output = run(args);
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    String::from_utf8(output.stdout).unwrap()
}

fn assessments(stdout: &str) -> Vec<&str> {
    stdout
        .lines()
        .filter(|line| line.starts_with("CVE-"))
        .collect()
}

#[test]
fn list_shows_the_catalogue_and_review_policies_outside_the_project() {
    let stdout = successful_stdout(&["checks", "list"]);
    assert!(stdout.contains("32 CVEs"));
    assert!(stdout.contains("active probes are separate"));
    assert_eq!(assessments(&stdout).len(), 32);
    for (id, policy) in [
        ("CVE-2024-36401", "LabOnly"),
        ("CVE-2025-27505", "ReadOnly"),
        ("CVE-2025-30220", "LabOnly"),
        ("CVE-2026-76904", "ReadOnly"),
    ] {
        let entry = stdout.lines().find(|line| line.starts_with(id)).unwrap();
        assert!(entry.contains(policy));
    }
}

#[test]
fn docker_release_assessment_shows_conditional_sql_injection_exposure() {
    let stdout = successful_stdout(&["checks", "assess", "--geoserver-version", "2.28.2"]);
    let rows = assessments(&stdout);
    assert_eq!(rows.len(), 32);
    for expected in [
        "CVE-2024-36401: OutsideAffectedRanges",
        "CVE-2025-27505: OutsideAffectedRanges",
        "CVE-2025-30220: OutsideAffectedRanges",
        "CVE-2026-76904: PotentiallyAffected",
        "CVE-2023-41877: PotentiallyAffected",
        "CVE-2023-5786: Unknown",
        "CVE-2024-35230: Unknown",
    ] {
        assert!(rows.contains(&expected), "missing {expected}");
    }
    assert!(stdout.contains("configuration requirements are unverified"));
    assert!(stdout.contains("PostgreSQL 12 or newer"));
    assert!(stdout.contains("String or JSON field"));
    assert!(stdout.contains("Fixed releases: 2.27.6, 2.28.5, 3.0.1"));
    assert!(stdout.contains(
        "https://github.com/geoserver/geoserver/security/advisories/GHSA-jvpx-6qxg-whgc"
    ));
}

#[test]
fn patched_release_assessment_does_not_claim_overall_security() {
    let stdout = successful_stdout(&["checks", "assess", "--geoserver-version", "3.0.1"]);
    let rows = assessments(&stdout);
    assert_eq!(rows.len(), 32);
    assert_eq!(
        rows.iter()
            .filter(|row| row.ends_with(": OutsideAffectedRanges"))
            .count(),
        30
    );
    assert_eq!(
        rows.iter().filter(|row| row.ends_with(": Unknown")).count(),
        2
    );
    assert!(stdout.contains("not overall security"));
    assert!(!stdout.contains("  Requirements:"));
}

#[test]
fn older_release_assessment_shows_multiple_cves_and_fixes() {
    let stdout = successful_stdout(&["checks", "assess", "--geoserver-version", "2.25.1"]);
    let rows = assessments(&stdout);
    assert_eq!(rows.len(), 32);
    for id in [
        "CVE-2024-36401",
        "CVE-2025-27505",
        "CVE-2025-30220",
        "CVE-2026-76904",
    ] {
        assert!(rows.contains(&format!("{id}: PotentiallyAffected").as_str()));
    }
    let matches = rows
        .iter()
        .filter(|row| row.ends_with(": PotentiallyAffected"))
        .count();
    assert_eq!(stdout.matches("  Advisory:").count(), matches);
    assert_eq!(stdout.matches("  Fix:").count(), matches);
}

#[test]
fn omitted_invalid_and_snapshot_versions_are_unknown() {
    let mut outputs = vec![successful_stdout(&["checks", "assess"])];
    for version in ["Unknown", "2.28", "2.28.2-SNAPSHOT"] {
        outputs.push(successful_stdout(&[
            "checks",
            "assess",
            "--geoserver-version",
            version,
        ]));
    }
    for stdout in outputs {
        let rows = assessments(&stdout);
        assert_eq!(rows.len(), 32);
        assert!(rows.iter().all(|row| row.ends_with(": Unknown")));
        assert!(!stdout.contains("  Fix:"));
    }
}

#[test]
fn help_explains_checks_and_the_version_argument() {
    assert!(successful_stdout(&["--help"]).contains("checks"));
    let stdout = successful_stdout(&["checks", "--help"]);
    assert!(stdout.contains("list"));
    assert!(stdout.contains("assess"));
    assert!(stdout.contains("show"));
    let stdout = successful_stdout(&["checks", "assess", "--help"]);
    assert!(stdout.contains("--geoserver-version <VERSION>"));
    assert!(stdout.contains("no scan requests"));
}

#[test]
fn json_export_is_parseable_and_contains_all_research_metadata() {
    let stdout = successful_stdout(&["checks", "list", "--json"]);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let entries = json.as_array().unwrap();
    assert_eq!(entries.len(), 32);
    for check in entries {
        assert!(!check["cvss"].as_array().unwrap().is_empty());
        assert!(!check["dates"].as_array().unwrap().is_empty());
        assert!(!check["references"].as_array().unwrap().is_empty());
        assert!(!check["authentication"].as_str().unwrap().is_empty());
    }
    let entry = entries
        .iter()
        .find(|check| check["id"] == "CVE-2025-30220")
        .unwrap();
    assert_eq!(entry["cvss"][0]["score"], 9.9);
    assert_eq!(entry["cvss"][1]["score"], 8.2);
}

#[test]
fn show_explains_sources_and_dependency_version_limitations() {
    let stdout = successful_stdout(&["checks", "show", "--id", "cve-2025-30220"]);
    assert!(stdout.contains("CVSS 3.1: 9.9 [Critical]"));
    assert!(stdout.contains("CVSS 3.1: 8.2 [High]"));
    assert!(stdout.contains("CvePublication: 2025-06-10"));
    let stdout = successful_stdout(&["checks", "show", "--id", "CVE-2023-5786"]);
    assert!(stdout.contains("Version scope: GeoWebCache"));
    assert!(stdout.contains("Fixed releases: Unknown"));
    assert!(stdout.contains("not GeoServer releases"));
}

#[test]
fn unknown_cve_id_fails_without_printing_partial_catalogue_output() {
    let output = run(&["checks", "show", "--id", "CVE-2099-99999"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Unknown CVE ID"));
    assert!(output.stdout.is_empty());
}

#[test]
fn malformed_checks_command_is_rejected_with_an_explanation() {
    for (args, explanation) in [
        (vec!["checks"], "Usage: geoscan checks <COMMAND>"),
        (
            vec!["checks", "assess", "--geoserver-version"],
            "a value is required for '--geoserver-version <VERSION>'",
        ),
    ] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains(explanation));
        assert!(output.stdout.is_empty());
    }
}

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_geoscan"))
        .args(args)
        .env_remove("GEOSCAN_PASSWORD")
        .output()
        .expect("geoscan should start")
}

#[test]
fn scan_help_explains_optional_target_login_and_automation() {
    let output = run(&["scan", "--help"]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    for explanation in ["--target", "--username", "--no-input", "GEOSCAN_PASSWORD"] {
        assert!(stdout.contains(explanation));
    }
    assert!(stdout.contains("Usage: geoscan scan [OPTIONS]"));
}

#[test]
fn missing_target_fails_without_waiting_for_input_in_scripts() {
    for args in [vec!["scan"], vec!["scan", "--no-input"]] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("Supply --target"));
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn scripted_login_requires_a_password_before_scanning() {
    let output = run(&[
        "scan",
        "--target",
        "http://127.0.0.1:8080/geoserver",
        "--username",
        "admin",
        "--no-input",
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Set GEOSCAN_PASSWORD"));
    assert!(output.stdout.is_empty());
}

#[test]
fn invalid_script_target_is_rejected_without_disclosing_credentials() {
    let output = Command::new(env!("CARGO_BIN_EXE_geoscan"))
        .args([
            "scan",
            "--target",
            "ftp://example.org/geoserver",
            "--username",
            "admin",
            "--no-input",
        ])
        .env("GEOSCAN_PASSWORD", "synthetic-password-for-test")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("HTTP or HTTPS URL"));
    assert!(!stderr.contains("synthetic-password-for-test"));
    assert!(output.stdout.is_empty());
}

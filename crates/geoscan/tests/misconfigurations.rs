use std::process::Command;

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_geoscan"))
}

#[test]
fn configuration_catalogue_is_embedded_and_exports_eleven_actual_checks() {
    let directory = tempfile::tempdir().unwrap();
    let output = cli()
        .args(["misconfigurations", "--json"])
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let data: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let checks = data.as_array().unwrap();
    assert_eq!(checks.len(), 11);
    assert_eq!(checks[0]["id"], "GS-MISC-001");
    assert_eq!(checks[0]["activation"], "always");
    assert_eq!(checks[6]["activation"], "private_layers");
    assert_eq!(checks[8]["activation"], "production");
    assert!(!directory.path().join("geoscan.db").exists());
}

#[test]
fn scan_help_exposes_configuration_options() {
    let output = cli().args(["scan", "--help"]).output().unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    for flag in [
        "--only-misconfigurations",
        "--private-layer",
        "--deployment",
    ] {
        assert!(text.contains(flag));
    }
    assert!(!text.contains("--check-default-credentials"));
}

#[test]
fn unsafe_or_excessive_private_layer_input_is_rejected_before_scan_setup() {
    let output = cli()
        .args(["scan", "--private-layer", "bad;layer", "--no-input"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("SQLi layer")
    );
    let mut command = cli();
    command.args(["scan", "--no-input"]);
    for index in 0..6 {
        command.args(["--private-layer", &format!("private:layer{index}")]);
    }
    let output = command.output().unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("At most five")
    );
}

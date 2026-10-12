use std::{
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    thread,
    time::{Duration, Instant},
};

use reqwest::Url;
use tokio::{process::Command, time::timeout};

const TEMPLATE: &str = include_str!("../templates/http/cves/2026/CVE-2026-76904.yaml");
const DRIVER_ERROR: &str = include_str!("fixtures/postgresql-prepared-statement-error.xml");
const BASELINE: &str = r#"{"type":"FeatureCollection","features":[]}"#;

fn serve(
    baseline_status: u16,
    baseline: String,
    probe: String,
) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("fixture server requires local sockets");
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let worker = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(30);
        for expected in [
            "jsonArrayContains(\"json_data\",'/a','x') = true",
            "jsonArrayContains(\"json_data\",'/a','x''') = true",
        ] {
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "engine did not send both requests"
                        );
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("fixture server failed: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(&mut stream);
            let mut first_line = String::new();
            reader.read_line(&mut first_line).unwrap();
            let mut parts = first_line.split_whitespace();
            assert_eq!(parts.next(), Some("GET"));
            let url = Url::parse(&format!("http://{address}{}", parts.next().unwrap())).unwrap();
            assert_eq!(url.path(), "/geoserver/wfs");
            let filter = url
                .query_pairs()
                .find(|(key, _)| key == "CQL_FILTER")
                .unwrap()
                .1;
            assert_eq!(filter, expected);
            loop {
                let mut line = String::new();
                assert_ne!(reader.read_line(&mut line).unwrap(), 0);
                if line == "\r\n" {
                    break;
                }
            }
            let (status, body, content_type) = if expected.contains("x'''") {
                (200, &probe, "text/xml;charset=UTF-8")
            } else {
                (baseline_status, &baseline, "application/json")
            };
            let response = format!(
                "HTTP/1.1 {status} Fixture\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            reader.get_mut().write_all(response.as_bytes()).unwrap();
        }
    });
    (format!("http://{address}/geoserver"), worker)
}

// Run explicitly with Nuclei on PATH (or GEOSCAN_TEST_NUCLEI set to its path).
// Uses only synthetic local HTTP responses; no GeoServer or database is needed.
#[tokio::test]
#[ignore = "requires Nuclei and permission to open a local HTTP fixture server"]
async fn sqli_template_handles_driver_errors_without_matching_unrelated_failures() {
    let directory = tempfile::tempdir().unwrap();
    let template = directory.path().join("CVE-2026-76904.yaml");
    std::fs::write(&template, TEMPLATE).unwrap();
    std::fs::write(directory.path().join("config.yaml"), "{}\n").unwrap();
    let executable = std::env::var("GEOSCAN_TEST_NUCLEI").unwrap_or_else(|_| "nuclei".into());
    let server_error = "<ServiceExceptionReport><ServiceException>org.postgresql.util.PSQLException: ERROR: syntax error at or near x</ServiceException></ServiceExceptionReport>";
    let generic_error = "<ServiceExceptionReport><ServiceException>SQL SELECT jsonb_path_exists failed: syntax error</ServiceException></ServiceExceptionReport>";
    for (name, status, baseline, probe, expected) in [
        (
            "captured prepared-statement error",
            200,
            BASELINE,
            DRIVER_ERROR.to_owned(),
            1,
        ),
        (
            "decoded quote characters",
            200,
            BASELINE,
            DRIVER_ERROR.replace("&quot;", "\""),
            1,
        ),
        (
            "PostgreSQL server quote error",
            200,
            BASELINE,
            server_error.into(),
            1,
        ),
        ("patched response", 200, BASELINE, BASELINE.into(), 0),
        (
            "unrelated SQL function",
            200,
            BASELINE,
            DRIVER_ERROR.replace("jsonb_path_exists(", "other_function("),
            0,
        ),
        (
            "missing SQL context",
            200,
            BASELINE,
            DRIVER_ERROR.replace("in SQL SELECT", "in CQL FILTER"),
            0,
        ),
        (
            "missing expected quote",
            200,
            BASELINE,
            DRIVER_ERROR.replace("Expected &quot; char", "Expected closing parenthesis"),
            0,
        ),
        ("generic SQL error", 200, BASELINE, generic_error.into(), 0),
        ("failed baseline", 500, BASELINE, DRIVER_ERROR.to_owned(), 0),
        (
            "non-GeoJSON baseline",
            200,
            "<html>Sign in</html>",
            DRIVER_ERROR.to_owned(),
            0,
        ),
    ] {
        let (target, worker) = serve(status, baseline.into(), probe);
        let mut command = Command::new(&executable);
        command
            .env_remove("GEOSCAN_PASSWORD")
            .env("NUCLEI_CONFIG_DIR", directory.path())
            .arg("-target")
            .arg(&target)
            .arg("-templates")
            .arg(&template)
            .args([
                "-jsonl",
                "-silent",
                "-no-color",
                "-matcher-status",
                "-omit-raw",
                "-omit-template",
                "-no-interactsh",
                "-disable-update-check",
                "-no-stdin",
                "-disable-redirects",
                "-timeout",
                "5",
                "-retries",
                "0",
            ])
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true);
        let output = timeout(Duration::from_secs(30), command.output())
            .await
            .unwrap()
            .unwrap();
        assert!(
            output.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        worker.join().unwrap();
        let events = String::from_utf8(output.stdout).unwrap();
        let mut matches = 0;
        for line in events.lines().filter(|line| !line.trim().is_empty()) {
            let event: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(event["template-id"], "CVE-2026-76904");
            if status == 200 {
                assert!(event.get("error").is_none_or(|error| error == ""));
            }
            if event["matcher-status"] == true {
                matches += 1;
                let matched = Url::parse(event["matched-at"].as_str().unwrap()).unwrap();
                assert_eq!(matched.origin(), Url::parse(&target).unwrap().origin());
                assert_eq!(matched.path(), "/geoserver/wfs");
            }
        }
        assert_eq!(matches, expected, "{name}");
    }
}

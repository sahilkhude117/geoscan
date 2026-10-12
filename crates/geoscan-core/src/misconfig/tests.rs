use super::http::FetchFuture;
use super::*;
use reqwest::header::{HeaderMap, HeaderValue};
use std::sync::Mutex;

const TARGET: &str = "http://127.0.0.1:8080/geoserver/";

#[derive(Default)]
struct Fixture {
    requests: Mutex<Vec<Request>>,
    factory: bool,
    public_config: bool,
    leaks: bool,
    cors: bool,
    weak_web: bool,
    failed_private: bool,
    wildcard_cors: bool,
    weak_cookie_redirect: bool,
    https_upgrade: bool,
    report_only_csp: bool,
    valid_hsts: bool,
}

fn reply(status: u16, body: &str) -> Response {
    Response {
        status,
        headers: HeaderMap::new(),
        body: body.into(),
    }
}

impl Fetch for Fixture {
    fn get(&self, request: Request) -> FetchFuture<'_> {
        self.requests.lock().unwrap().push(request.clone());
        Box::pin(async move {
            let path = request.url.path().strip_prefix("/geoserver/").unwrap();
            let mut response = match path {
                "rest/workspaces.json" => {
                    if self.public_config || (request.factory_login && self.factory) {
                        reply(200, r#"{"workspaces":{"workspace":[]}}"#)
                    } else {
                        reply(401, "")
                    }
                }
                "gwc/rest/layers.json" if self.leaks => reply(200, r#"{"layers":["demo:cache"]}"#),
                "gwc/rest/layers/demo:cache.json" if self.leaks => {
                    reply(200, r#"{"GeoServerLayer":{"name":"demo:cache"}}"#)
                }
                "rest/about/status.json" if self.leaks => {
                    reply(200, r#"{"status":{"path":"private-path-secret"}}"#)
                }
                "rest/about/system-status.json" => reply(401, ""),
                "data/security/users.xml" if self.leaks => reply(
                    200,
                    "<userRegistry><user password='database-password-secret'/></userRegistry>",
                ),
                "web/" => {
                    if self.https_upgrade {
                        let mut redirect = reply(302, "");
                        redirect.headers.insert(
                            "location",
                            HeaderValue::from_static("https://127.0.0.1:8080/geoserver/web/"),
                        );
                        return Ok(redirect);
                    }
                    if self.weak_cookie_redirect && request.url.query().is_none() {
                        let mut redirect = reply(302, "");
                        redirect
                            .headers
                            .insert("location", HeaderValue::from_static("?0"));
                        redirect.headers.insert(
                            "set-cookie",
                            HeaderValue::from_static("JSESSIONID=cookie-secret"),
                        );
                        return Ok(redirect);
                    }
                    let mut page = reply(200, "<html><title>GeoServer</title></html>");
                    page.headers
                        .insert("content-type", HeaderValue::from_static("text/html"));
                    page.headers.insert(
                        "set-cookie",
                        HeaderValue::from_static(if self.weak_web {
                            "JSESSIONID=cookie-secret; SameSite=None"
                        } else {
                            "JSESSIONID=cookie-secret; HttpOnly; SameSite=Lax"
                        }),
                    );
                    if !self.weak_web {
                        page.headers.insert(
                            "content-security-policy",
                            HeaderValue::from_static("default-src 'self'; frame-ancestors 'self'"),
                        );
                        page.headers.insert(
                            "x-content-type-options",
                            HeaderValue::from_static("nosniff"),
                        );
                    }
                    if self.report_only_csp {
                        let policy = page.headers.remove("content-security-policy").unwrap();
                        page.headers
                            .insert("content-security-policy-report-only", policy);
                        page.headers
                            .insert("x-frame-options", HeaderValue::from_static("SAMEORIGIN"));
                    }
                    if self.valid_hsts {
                        page.headers.insert(
                            "strict-transport-security",
                            HeaderValue::from_static("max-age = 63072000; includeSubDomains"),
                        );
                        page.headers.insert(
                            "set-cookie",
                            HeaderValue::from_static(
                                "JSESSIONID=cookie-secret; HttpOnly; Secure; SameSite=Lax",
                            ),
                        );
                    }
                    page
                }
                "wfs" => {
                    let layer = request
                        .url
                        .query_pairs()
                        .find(|(key, _)| key == "typeName")
                        .unwrap()
                        .1
                        .into_owned();
                    if layer == "geoscan_missing_probe_4c:missing" {
                        reply(
                            200,
                            if self.leaks {
                                "<ServiceExceptionReport><ServiceException>java.lang.RuntimeException: private-error-secret</ServiceException></ServiceExceptionReport>"
                            } else {
                                "<ServiceExceptionReport><ServiceException>Unknown layer</ServiceException></ServiceExceptionReport>"
                            },
                        )
                    } else if self.failed_private && layer == "demo:missing" {
                        return Err("Synthetic request failure".into());
                    } else if self.leaks {
                        reply(
                            200,
                            r#"{"type":"FeatureCollection","features":[{"properties":{"secret":"private-feature-secret"}}]}"#,
                        )
                    } else {
                        reply(403, "")
                    }
                }
                "gwc/rest/layers.json" | "rest/about/status.json" => reply(401, ""),
                _ => reply(404, ""),
            };
            if self.cors
                && let Some(origin) = request.origin
            {
                response.headers.insert(
                    "access-control-allow-origin",
                    HeaderValue::from_static(origin),
                );
                response.headers.insert(
                    "access-control-allow-credentials",
                    HeaderValue::from_static("true"),
                );
            }
            if self.wildcard_cors {
                response
                    .headers
                    .insert("access-control-allow-origin", HeaderValue::from_static("*"));
                response.headers.insert(
                    "access-control-allow-credentials",
                    HeaderValue::from_static("true"),
                );
            }
            Ok(response)
        })
    }
}

fn check<'a>(result: &'a Results, id: &str) -> &'a CheckResult {
    result.checks.iter().find(|check| check.id() == id).unwrap()
}

#[tokio::test]
async fn protected_lab_checks_factory_login_and_skips_undeclared_policy_checks() {
    let fixture = Fixture::default();
    let result = scan_with(&fixture, TARGET, &Options::default())
        .await
        .unwrap();
    assert_eq!(result.checks.len(), 11);
    assert!(result.findings.is_empty());
    for id in ["GS-MISC-007", "GS-MISC-009"] {
        assert_eq!(check(&result, id).status, "not_applicable");
        assert!(!check(&result, id).ran);
    }
    assert_eq!(check(&result, "GS-MISC-001").status, "no_match");
    assert!(check(&result, "GS-MISC-001").ran);
    assert_eq!(check(&result, "GS-MISC-010").status, "no_match");
    assert_eq!(check(&result, "GS-MISC-011").status, "no_match");
    let requests = fixture.requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.factory_login)
            .count(),
        1
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.url.path().ends_with("/web/"))
            .count(),
        1
    );
}

#[tokio::test]
async fn factory_login_requires_denied_baseline_and_makes_only_one_authentication_attempt() {
    let options = Options::default();
    let fixture = Fixture {
        factory: true,
        ..Fixture::default()
    };
    let result = scan_with(&fixture, TARGET, &options).await.unwrap();
    assert_eq!(check(&result, "GS-MISC-001").status, "matches");
    assert_eq!(
        fixture
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.factory_login)
            .count(),
        1
    );
    assert!(
        result.findings[0].reproduction[1]
            .command
            .contains("--user admin")
    );
    let public = Fixture {
        public_config: true,
        factory: true,
        ..Fixture::default()
    };
    let result = scan_with(&public, TARGET, &options).await.unwrap();
    assert_eq!(check(&result, "GS-MISC-001").status, "inconclusive");
    assert_eq!(check(&result, "GS-MISC-002").status, "matches");
    assert!(
        !public
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|request| request.factory_login)
    );
}

#[tokio::test]
async fn exposures_are_evidenced_and_raw_configuration_cookie_and_feature_values_are_redacted() {
    let fixture = Fixture {
        public_config: true,
        leaks: true,
        cors: true,
        weak_web: true,
        ..Fixture::default()
    };
    let options = Options {
        deployment: Deployment::Production,
        private_layers: vec!["demo:private".into()],
        ..Options::default()
    };
    let result = scan_with(&fixture, TARGET, &options).await.unwrap();
    for number in 2..=11 {
        assert_eq!(
            check(&result, &format!("GS-MISC-{number:03}")).status,
            "matches",
            "check {number}"
        );
    }
    let serialized = serde_json::to_string(&result.findings).unwrap();
    for secret in [
        "database-password-secret",
        "private-feature-secret",
        "cookie-secret",
        "private-path-secret",
        "private-error-secret",
    ] {
        assert!(!serialized.contains(secret));
    }
    for finding in &result.findings {
        assert_eq!(finding.kind, CheckKind::Misconfiguration);
        assert_eq!(finding.cve_id, None);
        assert!(finding.cvss.is_empty());
        assert!(!finding.reproduction.is_empty());
        let saved = restore_finding(
            TARGET,
            finding.id(),
            finding.matched_at.clone(),
            serde_json::to_string(finding).unwrap(),
        )
        .unwrap();
        assert_eq!(
            saved.reproduction[0].command,
            finding.reproduction[0].command
        );
    }
}

#[tokio::test]
async fn private_layer_failures_keep_the_accessible_layer_finding_and_partial_status() {
    let fixture = Fixture {
        leaks: true,
        failed_private: true,
        ..Fixture::default()
    };
    let options = Options {
        private_layers: vec!["demo:private".into(), "demo:missing".into()],
        ..Options::default()
    };
    let result = scan_with(&fixture, TARGET, &options).await.unwrap();
    assert_eq!(check(&result, "GS-MISC-007").status, "partial");
    assert_eq!(check(&result, "GS-MISC-007").matches, 1);
    let requests = fixture.requests.lock().unwrap();
    for request in requests
        .iter()
        .filter(|request| request.url.path().ends_with("/wfs"))
    {
        assert!(
            request
                .url
                .query_pairs()
                .any(|(key, value)| key == "maxFeatures" && value == "1")
        );
    }
}

#[test]
fn validates_metadata_options_and_reproduction_scope() {
    let definitions = catalog().unwrap();
    assert_eq!(definitions.len(), 11);
    let mut ids = HashSet::new();
    for definition in definitions {
        assert!(ids.insert(definition.id));
        assert!(!definition.remediation.is_empty());
        assert!(definition.reference_url.starts_with("https://"));
    }
    for options in [
        Options {
            private_layers: vec!["bad;layer".into()],
            ..Options::default()
        },
        Options {
            private_layers: vec!["a:b".into(); 6],
            ..Options::default()
        },
        Options {
            private_layers: vec!["a:b".into(); 2],
            ..Options::default()
        },
    ] {
        assert!(options.validate().is_err());
    }
    assert!(serde_json::from_str::<Options>(r#"{"arbitrary_paths":["/etc/passwd"]}"#).is_err());
    for target in [
        "http://elsewhere.invalid/geoserver/rest/workspaces.json",
        "http://admin:secret@127.0.0.1:8080/geoserver/rest/workspaces.json",
        "http://127.0.0.1:8080/geoserver/rest/workspaces.json?extra=1",
    ] {
        assert!(reproduction("GS-MISC-002", TARGET, target).is_err());
    }
    let base = normalize_target(TARGET).unwrap();
    let mut private = probes::private_url(&base, "demo:private");
    private.query_pairs_mut().append_pair("maxFeatures", "1000");
    assert!(reproduction("GS-MISC-007", TARGET, private.as_str()).is_err());
}

#[tokio::test]
async fn wildcard_cors_does_not_prove_credentialed_browser_access() {
    let fixture = Fixture {
        wildcard_cors: true,
        ..Fixture::default()
    };
    let result = scan_with(&fixture, TARGET, &Options::default())
        .await
        .unwrap();
    assert_eq!(check(&result, "GS-MISC-008").status, "no_match");
}

#[tokio::test]
async fn cookie_reproduction_points_at_the_response_that_issued_the_weak_cookie() {
    let fixture = Fixture {
        weak_cookie_redirect: true,
        ..Fixture::default()
    };
    let result = scan_with(&fixture, TARGET, &Options::default())
        .await
        .unwrap();
    let finding = result
        .findings
        .iter()
        .find(|finding| finding.id() == "GS-MISC-010")
        .unwrap();
    assert!(finding.matched_at.ends_with("/web/"));
    assert!(!finding.reproduction[0].command.contains("?0"));
    assert_eq!(check(&result, "GS-MISC-011").status, "no_match");
}

#[tokio::test]
async fn production_https_upgrade_is_not_reported_as_plaintext_access() {
    let fixture = Fixture {
        https_upgrade: true,
        ..Fixture::default()
    };
    let result = scan_with(
        &fixture,
        TARGET,
        &Options {
            deployment: Deployment::Production,
            ..Options::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(check(&result, "GS-MISC-009").status, "no_match");
    let requests = fixture.requests.lock().unwrap();
    assert!(
        requests
            .iter()
            .all(|request| request.url.scheme() == "http")
    );
}

#[tokio::test]
async fn report_only_csp_is_not_counted_as_enforced_browser_protection() {
    let fixture = Fixture {
        report_only_csp: true,
        ..Fixture::default()
    };
    let result = scan_with(&fixture, TARGET, &Options::default())
        .await
        .unwrap();
    let finding = result
        .findings
        .iter()
        .find(|finding| finding.id() == "GS-MISC-011")
        .unwrap();
    assert!(finding.evidence.contains("enforced script/default CSP"));
    assert!(!finding.evidence.contains("lacked effective framing"));
}

#[tokio::test]
async fn https_hsts_assessment_uses_a_low_risk_rating_and_accepts_valid_policy() {
    let options = Options {
        deployment: Deployment::Production,
        ..Options::default()
    };
    let fixture = Fixture::default();
    let result = scan_with(&fixture, "https://127.0.0.1:8080/geoserver/", &options)
        .await
        .unwrap();
    let finding = result
        .findings
        .iter()
        .find(|finding| finding.id() == "GS-MISC-009")
        .unwrap();
    assert_eq!(finding.severity, Severity::Low);
    assert_eq!(check(&result, "GS-MISC-009").severity, Some(Severity::Low));
    let fixture = Fixture {
        valid_hsts: true,
        ..Fixture::default()
    };
    let result = scan_with(&fixture, "https://127.0.0.1:8080/geoserver/", &options)
        .await
        .unwrap();
    assert_eq!(check(&result, "GS-MISC-009").status, "no_match");
    assert_eq!(check(&result, "GS-MISC-010").status, "no_match");
}

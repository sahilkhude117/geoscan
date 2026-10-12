//! Context-aware, bounded configuration probes. Response bodies/cookie values
//! exist only in memory; saved evidence describes markers without their values.

mod http;
mod probes;

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    time::Duration,
};

use reqwest::Url;
use serde::{Deserialize, Serialize};
use tokio::time::Instant;

use crate::{
    catalog::Severity,
    detect::normalize_target,
    scan::{CheckKind, CheckResult, Finding, ReproductionStep, SqliTarget},
};
use http::{Fetch, Network, Request, Response};

pub const ORIGIN: &str = "https://geoscan-untrusted.invalid";
pub const SECOND_ORIGIN: &str = "https://geoscan-other-untrusted.invalid";

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Deployment {
    #[default]
    Unspecified,
    Lab,
    Production,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Options {
    pub only_misconfigurations: bool,
    pub private_layers: Vec<String>,
    pub deployment: Deployment,
}
pub type MisconfigurationOptions = Options;

impl Options {
    pub fn validate(&self) -> Result<(), String> {
        if self.private_layers.len() > 5 {
            return Err("At most five declared private layers may be checked per scan".into());
        }
        let mut names = HashSet::new();
        for layer in &self.private_layers {
            SqliTarget::new(layer, "id")?;
            if !names.insert(layer) {
                return Err("Private layer names must not be repeated".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Definition {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub remediation: String,
    pub reference_url: String,
    pub activation: String,
}

pub fn catalog() -> Result<Vec<Definition>, String> {
    serde_json::from_str(include_str!("../../data/misconfigurations.json"))
        .map_err(|error| error.to_string())
}

pub struct Results {
    pub checks: Vec<CheckResult>,
    pub findings: Vec<Finding>,
}

pub async fn scan(target: &str, options: &Options) -> Result<Results, String> {
    options.validate()?;
    scan_with(&Network::new()?, target, options).await
}

struct Context<'a, F> {
    fetch: &'a F,
    base: Url,
    cache: HashMap<String, Result<Response, String>>,
    landing: Option<Result<Landing, String>>,
    next_request: Instant,
}
type Landing = (Url, Response, Vec<(Url, String)>);

impl<F: Fetch> Context<'_, F> {
    fn url(&self, path: &str) -> Result<Url, String> {
        self.base.join(path).map_err(|error| error.to_string())
    }

    async fn request(
        &mut self,
        url: Url,
        origin: Option<&'static str>,
        factory_login: bool,
    ) -> Result<Response, String> {
        if !in_scope(&self.base, &url) {
            return Err("Probe URL was outside the selected application".into());
        }
        let key = format!("{url}|{origin:?}|{factory_login}");
        if let Some(response) = self.cache.get(&key) {
            return response.clone();
        }
        tokio::time::sleep_until(self.next_request).await;
        self.next_request = Instant::now() + Duration::from_millis(200);
        let response = self
            .fetch
            .get(Request {
                url,
                origin,
                factory_login,
            })
            .await;
        self.cache.insert(key, response.clone());
        response
    }

    async fn get(&mut self, path: &str) -> Result<Response, String> {
        let url = self.url(path)?;
        self.request(url, None, false).await
    }

    async fn web(&mut self) -> Result<Landing, String> {
        if let Some(landing) = &self.landing {
            return landing.clone();
        }
        let result =
            async {
                let mut url = self.url("web/")?;
                let mut cookies = Vec::new();
                for _ in 0..3 {
                    let response = self.request(url.clone(), None, false).await?;
                    cookies.extend(response.headers.get_all("set-cookie").iter().filter_map(
                        |value| {
                            value
                                .to_str()
                                .ok()
                                .map(|cookie| (url.clone(), cookie.to_owned()))
                        },
                    ));
                    if !matches!(response.status, 301 | 302 | 303 | 307 | 308) {
                        return Ok((url, response, cookies));
                    }
                    let location = response
                        .headers
                        .get("location")
                        .and_then(|value| value.to_str().ok())
                        .ok_or("Redirect had no usable Location")?;
                    let next = url
                        .join(location)
                        .map_err(|_| "Invalid redirect Location")?;
                    // Do not follow service endpoints, external hosts or credential URLs.
                    if !in_scope(&self.base, &next) || next.path() != self.url("web/")?.path() {
                        return Err(
                            "Admin page redirects outside the selected administration page".into(),
                        );
                    }
                    url = next;
                }
                Err("Admin page exceeded the two-redirect limit".into())
            }
            .await;
        self.landing = Some(result.clone());
        result
    }
}

async fn scan_with<F: Fetch>(
    fetch: &F,
    target: &str,
    options: &Options,
) -> Result<Results, String> {
    let definitions = catalog()?;
    let mut context = Context {
        fetch,
        base: normalize_target(target)?,
        cache: HashMap::new(),
        landing: None,
        next_request: Instant::now(),
    };
    let deadline = Instant::now() + Duration::from_secs(40);
    let mut results = Results {
        checks: Vec::new(),
        findings: Vec::new(),
    };
    for definition in &definitions {
        let mut check = CheckResult {
            check_id: definition.id.clone(),
            kind: CheckKind::Misconfiguration,
            cve_id: None,
            severity: Some(definition.severity),
            status: "no_match".into(),
            ran: false,
            reported_events: 0,
            matches: 0,
            note: String::new(),
            diagnostics: String::new(),
            error: None,
        };
        let activation = match definition.activation.as_str() {
            "private_layers" if options.private_layers.is_empty() => {
                Some("No layers were declared private; public WFS access is not a finding")
            }
            "production" if options.deployment != Deployment::Production => Some(
                "Transport assessment requires an explicitly declared production deployment; localhost labs are not assumed production",
            ),
            _ => None,
        };
        if let Some(note) = activation {
            check.status = "not_applicable".into();
            check.note = note.into();
            results.checks.push(check);
            continue;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            check.status = "inconclusive".into();
            check.note = "Configuration probe budget was exhausted".into();
        } else {
            check.ran = true;
            if tokio::time::timeout(
                remaining,
                probes::run(
                    definition,
                    &mut context,
                    options,
                    &mut check,
                    &mut results.findings,
                ),
            )
            .await
            .is_err()
            {
                check.error =
                    Some("Configuration checks reached their 40-second overall budget".into());
            }
        }
        if check.error.is_some() {
            check.status = if check.matches > 0 {
                "partial"
            } else {
                "inconclusive"
            }
            .into();
        } else if check.matches > 0 {
            check.status = "matches".into();
        }
        if check.note.is_empty() {
            check.note="Bounded configuration assessment; no matching evidence observed in the responses examined".into();
        }
        results.checks.push(check);
    }
    Ok(results)
}

fn in_scope(base: &Url, url: &Url) -> bool {
    base.origin() == url.origin()
        && url.path().starts_with(base.path())
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
}

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn command(url: &Url, origin: Option<&str>, factory_login: bool) -> String {
    let mut command = format!(
        "curl --noproxy '*' --max-time 5 -sS -i {}",
        quote(url.as_str())
    );
    if let Some(origin) = origin {
        command.push_str(&format!(" -H {}", quote(&format!("Origin: {origin}"))));
    }
    if factory_login {
        command.push_str(" --user admin");
    }
    command
}

fn reproduction(id: &str, target: &str, matched_at: &str) -> Result<Vec<ReproductionStep>, String> {
    let base = normalize_target(target)?;
    let url = Url::parse(matched_at).map_err(|_| "Invalid saved configuration finding URL")?;
    if !in_scope(&base, &url) {
        return Err("Saved configuration finding is outside the selected application".into());
    }
    probes::validate_saved_url(id, &base, &url)?;
    let mut steps=vec![ReproductionStep{title:"Repeat the bounded read-only request".into(),command:command(&url,None,false),expected:"Compare the returned status, headers and response markers with the saved evidence; 401/403 or absent markers do not reproduce an exposure.".into()}];
    match id {
        "GS-MISC-001"=>{
            steps[0].expected="Anonymous baseline must be denied (HTTP 401/403).".into();
            steps.push(ReproductionStep{title:"Try the factory login once".into(),command:command(&url,None,true),expected:"At the curl password prompt enter the factory password geoserver. A match requires HTTP 200 with a workspaces configuration response after the denied anonymous baseline.".into()});
        },
        "GS-MISC-007"=>steps[0].expected="An anonymous HTTP 200 GeoJSON FeatureCollection for the layer you declared private; at most one feature is requested. Public layers should not be labelled private.".into(),
        "GS-MISC-008"=>steps=vec![ORIGIN,SECOND_ORIGIN].into_iter().map(|origin|ReproductionStep{title:"Inspect credentialed CORS policy for an untrusted origin".into(),command:command(&url,Some(origin),false),expected:format!("Access-Control-Allow-Origin echoes {origin} and Access-Control-Allow-Credentials is true. This proves the header policy, not authenticated data access.")}).collect(),
        "GS-MISC-010"=>steps[0].expected="Inspect session-cookie attributes without sharing cookie values. Look for missing HttpOnly, missing Secure on HTTPS, or SameSite=None without Secure. A redirect may set the cookie before the final page.".into(),
        _=>{},
    }
    Ok(steps)
}

fn record(
    definition: &Definition,
    context: &impl BaseUrl,
    url: &Url,
    evidence: String,
    severity: Option<Severity>,
    check: &mut CheckResult,
    findings: &mut Vec<Finding>,
) {
    match reproduction(&definition.id, context.base_url(), url.as_str()) {
        Ok(reproduction) => {
            let level = severity.unwrap_or(definition.severity);
            let rank = |level: Severity| match level {
                Severity::Low => 0,
                Severity::Medium => 1,
                Severity::High => 2,
                Severity::Critical => 3,
            };
            if check.matches == 0
                || check
                    .severity
                    .is_none_or(|current| rank(level) > rank(current))
            {
                check.severity = Some(level);
            }
            check.matches += 1;
            findings.push(Finding {
                check_id: definition.id.clone(),
                kind: CheckKind::Misconfiguration,
                cve_id: None,
                name: definition.name.clone(),
                severity: severity.unwrap_or(definition.severity),
                matched_at: url.to_string(),
                description: definition.description.clone(),
                cvss: vec![],
                remediation: definition.remediation.clone(),
                advisory_url: definition.reference_url.clone(),
                evidence,
                reproduction,
            });
        }
        Err(error) => check.error = Some(error),
    }
}

trait BaseUrl {
    fn base_url(&self) -> &str;
}
impl<F> BaseUrl for Context<'_, F> {
    fn base_url(&self) -> &str {
        self.base.as_str()
    }
}

pub(crate) fn restore_finding(
    target: &str,
    id: &str,
    matched_at: String,
    details: String,
) -> Result<Finding, String> {
    let mut finding: Finding =
        serde_json::from_str(&details).map_err(|_| "Invalid saved configuration finding")?;
    if finding.kind != CheckKind::Misconfiguration
        || finding.id() != id
        || finding.cve_id.is_some()
        || finding.matched_at != matched_at
        || !finding.cvss.is_empty()
    {
        return Err("Saved configuration finding metadata is inconsistent".into());
    }
    let definition = catalog()?
        .into_iter()
        .find(|entry| entry.id == id)
        .ok_or("Unknown configuration check ID")?;
    finding.reproduction = reproduction(id, target, &matched_at)?;
    finding.name = definition.name;
    finding.description = definition.description;
    finding.remediation = definition.remediation;
    finding.advisory_url = definition.reference_url;
    Ok(finding)
}

fn local(base: &Url) -> bool {
    base.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .trim_matches(['[', ']'])
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    })
}

#[cfg(test)]
mod tests;

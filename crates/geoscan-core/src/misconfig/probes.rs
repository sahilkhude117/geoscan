use reqwest::Url;
use roxmltree::Document;
use serde_json::Value;

use super::{Context, Definition, Fetch, ORIGIN, Options, Response, SECOND_ORIGIN, local, record};
use crate::{
    catalog::Severity,
    scan::{CheckResult, Finding, SqliTarget},
};

const FILES: [&str; 4] = [
    "data/security/users.xml",
    "WEB-INF/web.xml",
    "web.xml.bak",
    "data/",
];

fn json(body: &str) -> Option<Value> {
    serde_json::from_str(body).ok()
}
fn root(body: &str) -> Option<String> {
    Document::parse(body)
        .ok()
        .map(|doc| doc.root_element().tag_name().name().to_owned())
}
fn denied(response: &Response) -> bool {
    matches!(response.status, 401 | 403)
}
fn header(response: &Response, name: &str) -> String {
    response
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_owned()
}
fn workspaces(response: &Response) -> bool {
    response.status == 200
        && (json(&response.body).is_some_and(|data| data.get("workspaces").is_some())
            || root(&response.body).as_deref() == Some("workspaces"))
}
fn diagnostics(response: &Response) -> bool {
    response.status == 200
        && (json(&response.body).is_some_and(|data| {
            ["status", "metrics", "systemStatus"].iter().any(|key| {
                data.get(key)
                    .is_some_and(|value| value.is_object() || value.is_array())
            })
        }) || root(&response.body)
            .is_some_and(|name| ["status", "metrics", "systemStatus"].contains(&name.as_str())))
}
fn geojson(response: &Response) -> bool {
    response.status == 200
        && json(&response.body)
            .is_some_and(|data| data["type"] == "FeatureCollection" && data["features"].is_array())
}
fn administration_html(response: &Response) -> bool {
    let body = response.body.to_ascii_lowercase();
    response.status == 200
        && header(response, "content-type")
            .to_ascii_lowercase()
            .contains("text/html")
        && body.contains("<html")
        && (body.contains("geoserver") || body.contains("wicket"))
}

async fn response<F: Fetch>(
    context: &mut Context<'_, F>,
    path: &str,
    check: &mut CheckResult,
) -> Option<Response> {
    check.reported_events += 1;
    match context.get(path).await {
        Ok(response) => Some(response),
        Err(error) => {
            check.error = Some(error);
            None
        }
    }
}

fn inconclusive(check: &mut CheckResult, note: &str) {
    check.error = Some(note.into());
}

pub(super) async fn run<F: Fetch>(
    definition: &Definition,
    context: &mut Context<'_, F>,
    options: &Options,
    check: &mut CheckResult,
    findings: &mut Vec<Finding>,
) {
    match definition.id.as_str() {
        "GS-MISC-001" => {
            let Some(baseline) = response(context, "rest/workspaces.json", check).await else {
                return;
            };
            if !denied(&baseline) {
                inconclusive(
                    check,
                    "Anonymous baseline was not denied; accepting the same response with a login would not prove the factory credentials work",
                );
                return;
            }
            let url = context
                .url("rest/workspaces.json")
                .expect("fixed relative path");
            check.reported_events += 1;
            match context.request(url.clone(),None,true).await {
                Ok(authenticated) if workspaces(&authenticated)=>record(definition,context,&url,"Anonymous request was denied; one factory admin/geoserver authentication attempt returned a workspace configuration response. No administration changes were made.".into(),None,check,findings),
                Ok(authenticated) if denied(&authenticated)=>check.note="Factory login was not accepted".into(),
                Ok(_)=>inconclusive(check,"Factory-login response did not establish authenticated configuration access"),
                Err(error)=>check.error=Some(error),
            }
        }
        "GS-MISC-002" => {
            let path = "rest/workspaces.json";
            let Some(observed) = response(context, path, check).await else {
                return;
            };
            if workspaces(&observed) {
                record(definition,context,&context.url(path).unwrap(),"HTTP 200 with the workspace configuration response structure, without credentials; configuration values were not retained.".into(),None,check,findings);
            } else if !denied(&observed) && observed.status != 404 {
                inconclusive(
                    check,
                    "REST response was neither a protected endpoint nor recognizable configuration",
                );
            } else if observed.status == 404 {
                check.status = "not_applicable".into();
                check.note = "Workspace configuration endpoint was not present".into();
            }
        }
        "GS-MISC-003" => {
            let Some(list) = response(context, "gwc/rest/layers.json", check).await else {
                return;
            };
            if denied(&list) {
                return;
            }
            if list.status == 404 {
                check.status = "not_applicable".into();
                check.note = "GeoWebCache REST endpoint was not present".into();
                return;
            }
            let layer = json(&list.body).and_then(|value| {
                value
                    .get("layers")
                    .and_then(Value::as_array)
                    .and_then(|names| {
                        names
                            .iter()
                            .find_map(|name| name.as_str().map(str::to_owned))
                    })
            });
            let Some(layer) = layer else {
                if json(&list.body).is_some_and(|value| {
                    value
                        .get("layers")
                        .and_then(Value::as_array)
                        .is_some_and(Vec::is_empty)
                }) {
                    check.status = "not_applicable".into();
                    check.note = "No cache layers were listed".into();
                } else {
                    inconclusive(
                        check,
                        "Could not identify a cache layer for the bounded configuration read",
                    );
                }
                return;
            };
            if SqliTarget::new(&layer, "id").is_err() {
                inconclusive(
                    check,
                    "Returned cache layer name was outside the supported identifier format",
                );
                return;
            }
            let path = format!("gwc/rest/layers/{layer}.json");
            let Some(config) = response(context, &path, check).await else {
                return;
            };
            let recognized = json(&config.body).is_some_and(|value| {
                value.as_object().is_some_and(|object| {
                    object.keys().any(|key| {
                        ["geoserverlayer", "wmslayer"].contains(&key.to_ascii_lowercase().as_str())
                    })
                })
            }) || root(&config.body).is_some_and(|name| {
                ["geoserverlayer", "wmslayer"].contains(&name.to_ascii_lowercase().as_str())
            });
            if config.status == 200 && recognized {
                record(definition,context,&context.url(&path).unwrap(),"A named cache layer's configuration structure was returned without authentication. Public tile access alone was not treated as a finding.".into(),None,check,findings);
            } else if !denied(&config) && config.status != 404 {
                inconclusive(check, "Cache configuration response was not recognizable");
            }
        }
        "GS-MISC-004" => {
            for path in ["rest/about/status.json", "rest/about/system-status.json"] {
                let Some(observed) = response(context, path, check).await else {
                    continue;
                };
                if diagnostics(&observed) {
                    record(definition,context,&context.url(path).unwrap(),"An unauthenticated request returned structured administrative server diagnostics; metric values, paths and environment values were not retained.".into(),None,check,findings);
                } else if !denied(&observed) && observed.status != 404 {
                    inconclusive(check, "Diagnostic response was not recognizable");
                }
            }
        }
        "GS-MISC-005" => {
            let url = error_url(&context.base);
            check.reported_events += 1;
            match context.request(url.clone(), None, false).await {
                Ok(observed) => {
                    let text = observed.body.to_ascii_lowercase();
                    let error_document = root(&observed.body).is_some_and(|name| {
                        ["ExceptionReport", "ServiceExceptionReport"].contains(&name.as_str())
                    });
                    if !error_document && observed.status < 400 {
                        inconclusive(
                            check,
                            "Invalid WFS request did not produce a recognizable service error",
                        );
                        return;
                    }
                    let reason = if text.contains("java.lang.")
                        || text.contains(" at org.geoserver.")
                        || text.contains(".java:")
                    {
                        Some("Java exception implementation or stack-trace markers")
                    } else if text.contains("select ") && text.contains(" from ") {
                        Some("SQL statement markers")
                    } else if ["/home/", "/opt/", "/var/", "c:\\", "d:\\"]
                        .iter()
                        .any(|path| text.contains(path))
                    {
                        Some("internal filesystem-path markers")
                    } else {
                        None
                    };
                    if let Some(reason) = reason {
                        record(
                            definition,
                            context,
                            &url,
                            format!(
                                "A bounded request for a nonexistent layer returned {reason}; raw error content was not retained."
                            ),
                            None,
                            check,
                            findings,
                        );
                    }
                }
                Err(error) => check.error = Some(error),
            }
        }
        "GS-MISC-006" => {
            for path in FILES {
                let Some(observed) = response(context, path, check).await else {
                    continue;
                };
                if observed.status != 200 {
                    if observed.status >= 500 {
                        inconclusive(check, "A configuration-path probe returned a server error");
                    }
                    continue;
                }
                let name = root(&observed.body);
                let lower = observed.body.to_ascii_lowercase();
                let recognized = if path == "data/" {
                    directory_index(&lower)
                } else if path == "data/security/users.xml" {
                    name.as_deref() == Some("userRegistry")
                } else {
                    name.as_deref() == Some("web-app")
                };
                if recognized {
                    record(
                        definition,
                        context,
                        &context.url(path).unwrap(),
                        format!(
                            "Known private path {path} returned recognizable configuration or directory-index markers. Response contents and secrets were not retained."
                        ),
                        None,
                        check,
                        findings,
                    );
                }
            }
            check.note="Checked four known application-relative paths; absence does not rule out other exposed files".into();
        }
        "GS-MISC-007" => {
            for layer in &options.private_layers {
                let url = private_url(&context.base, layer);
                check.reported_events += 1;
                match context.request(url.clone(), None, false).await {
                    Ok(observed) if geojson(&observed) => record(
                        definition,
                        context,
                        &url,
                        format!(
                            "Operator-declared private layer {layer} returned an anonymous GeoJSON FeatureCollection with a one-feature request limit. Feature values were not retained."
                        ),
                        None,
                        check,
                        findings,
                    ),
                    Ok(observed) if denied(&observed) => {}
                    Ok(observed) if observed.status == 404 => {
                        check.note="A declared layer endpoint was not found; private access could not be assessed".into();
                        inconclusive(check, "Verify that all declared private layers exist");
                    }
                    Ok(_) => inconclusive(
                        check,
                        "A declared private layer did not return a recognizable feature collection or authentication denial; an OGC error does not establish protection",
                    ),
                    Err(error) => check.error = Some(error),
                }
            }
        }
        "GS-MISC-008" => {
            let url = context.url("rest/workspaces.json").unwrap();
            let mut reflected = 0;
            for origin in [ORIGIN, SECOND_ORIGIN] {
                check.reported_events += 1;
                match context.request(url.clone(), Some(origin), false).await {
                    Ok(observed) if matches!(observed.status, 200 | 401 | 403) => {
                        if header(&observed, "access-control-allow-origin") == origin
                            && header(&observed, "access-control-allow-credentials")
                                .eq_ignore_ascii_case("true")
                        {
                            reflected += 1;
                        }
                    }
                    Ok(_) => inconclusive(
                        check,
                        "Could not assess CORS policy on the administrative configuration route",
                    ),
                    Err(error) => check.error = Some(error),
                }
            }
            if reflected == 2 {
                record(definition,context,&url,"Two unrelated untrusted Origin values were reflected with Access-Control-Allow-Credentials: true on a configuration route. Authenticated data access was not attempted; wildcard CORS on public maps is not this finding.".into(),None,check,findings);
            }
        }
        "GS-MISC-009" => {
            let url = context.url("web/").unwrap();
            let Some(observed) = response(context, "web/", check).await else {
                return;
            };
            if context.base.scheme() == "http" {
                let upgrade = header(&observed, "location");
                let secured = matches!(observed.status, 301 | 302 | 303 | 307 | 308)
                    && url.join(&upgrade).is_ok_and(|next| {
                        next.scheme() == "https"
                            && next.host_str() == url.host_str()
                            && next.username().is_empty()
                            && next.password().is_none()
                            && next.path().starts_with(context.base.path())
                    });
                if !secured && matches!(observed.status, 200 | 401 | 403) {
                    let note = if local(&context.base) {
                        "The operator explicitly marked this loopback target production; ordinary localhost labs are skipped."
                    } else {
                        "Production context was explicitly selected."
                    };
                    record(
                        definition,
                        context,
                        &url,
                        format!(
                            "Administration route returned HTTP {} over cleartext HTTP without a same-host HTTPS upgrade. {note}",
                            observed.status
                        ),
                        None,
                        check,
                        findings,
                    );
                } else if !secured {
                    inconclusive(
                        check,
                        "Transport response did not establish either an accessible administration route or a same-host HTTPS upgrade",
                    );
                }
            } else {
                if !matches!(observed.status, 200 | 301 | 302 | 303 | 401 | 403) {
                    inconclusive(
                        check,
                        "HTTPS administration route did not return an assessable response",
                    );
                    return;
                }
                let hsts = header(&observed, "strict-transport-security");
                let positive_age = hsts.split(';').any(|part| {
                    part.trim().split_once('=').is_some_and(|(key, value)| {
                        key.trim().eq_ignore_ascii_case("max-age")
                            && value.trim().parse::<u64>().is_ok_and(|age| age > 0)
                    })
                });
                if !positive_age {
                    record(definition,context,&url,"Production HTTPS administration response lacked a usable positive HSTS max-age. HTTPS itself was not reported missing.".into(),Some(Severity::Low),check,findings);
                }
            }
        }
        "GS-MISC-010" => {
            check.reported_events += 1;
            let (mut url, _page, cookies) = match context.web().await {
                Ok(value) => value,
                Err(error) => {
                    check.error = Some(error);
                    return;
                }
            };
            let mut weaknesses = Vec::new();
            let mut sessions = 0;
            for (issued_at, cookie) in cookies {
                let Some((name, value)) = cookie
                    .split(';')
                    .next()
                    .and_then(|part| part.split_once('='))
                else {
                    continue;
                };
                if value.trim().is_empty() {
                    continue;
                }
                if !["jsessionid", "jsessionidsso", "session"]
                    .contains(&name.trim().to_ascii_lowercase().as_str())
                {
                    continue;
                }
                let attributes: Vec<_> = cookie
                    .split(';')
                    .skip(1)
                    .map(|part| part.trim().to_ascii_lowercase())
                    .collect();
                if attributes.iter().any(|part| {
                    part.split_once('=').is_some_and(|(key, value)| {
                        key.trim() == "max-age"
                            && value.trim().parse::<i64>().is_ok_and(|age| age <= 0)
                    })
                }) {
                    continue;
                }
                sessions += 1;
                let before = weaknesses.len();
                let secure = attributes.iter().any(|part| part == "secure");
                if !attributes.iter().any(|part| part == "httponly") {
                    weaknesses.push("missing HttpOnly");
                }
                if context.base.scheme() == "https" && !secure {
                    weaknesses.push("missing Secure on HTTPS");
                }
                if attributes.iter().any(|part| {
                    part.split_once('=').is_some_and(|(key, value)| {
                        key.trim() == "samesite" && value.trim() == "none"
                    })
                }) && !secure
                {
                    weaknesses.push("SameSite=None without Secure");
                }
                if before == 0 && !weaknesses.is_empty() {
                    url = issued_at;
                }
            }
            weaknesses.sort_unstable();
            weaknesses.dedup();
            if !weaknesses.is_empty() {
                record(
                    definition,
                    context,
                    &url,
                    format!(
                        "Session-cookie attributes showed {}. Cookie values were redacted; missing SameSite alone was not treated as a vulnerability.",
                        weaknesses.join(", ")
                    ),
                    None,
                    check,
                    findings,
                );
            } else if sessions == 0 {
                check.status = "not_applicable".into();
                check.note="No recognized session cookie was issued during the bounded anonymous page requests".into();
            }
        }
        "GS-MISC-011" => {
            check.reported_events += 1;
            let (url, page, _) = match context.web().await {
                Ok(value) => value,
                Err(error) => {
                    check.error = Some(error);
                    return;
                }
            };
            if !administration_html(&page) {
                check.status = "not_applicable".into();
                check.note="No successful GeoServer administration HTML page was available for browser-header assessment".into();
                return;
            }
            let policies: Vec<_> = page
                .headers
                .get_all("content-security-policy")
                .iter()
                .filter_map(|value| value.to_str().ok())
                .collect();
            let script_policy = policies.iter().any(|policy| {
                directive(policy, "script-src")
                    .or_else(|| directive(policy, "default-src"))
                    .is_some_and(|sources| {
                        !sources.is_empty()
                            && !sources.split_whitespace().any(|source| source == "*")
                    })
            });
            let frame_sources: Vec<_> = policies
                .iter()
                .filter_map(|policy| directive(policy, "frame-ancestors"))
                .collect();
            let framed = if frame_sources.is_empty() {
                ["DENY", "SAMEORIGIN"]
                    .iter()
                    .any(|value| header(&page, "x-frame-options").eq_ignore_ascii_case(value))
            } else {
                frame_sources.iter().any(|sources| {
                    !sources.is_empty()
                        && !sources.split_whitespace().any(|source| {
                            ["*", "http:", "https:", "http://*", "https://*"].contains(&source)
                        })
                })
            };
            let mut missing = Vec::new();
            if !script_policy {
                missing.push("an enforced script/default CSP");
            }
            if !framed {
                missing.push("effective framing restrictions");
            }
            if !header(&page, "x-content-type-options").eq_ignore_ascii_case("nosniff") {
                missing.push("X-Content-Type-Options: nosniff");
            }
            if !missing.is_empty() {
                record(
                    definition,
                    context,
                    &url,
                    format!(
                        "Administration HTML lacked {}. Report-only CSP was not counted as enforcement; valid CSP frame-ancestors can replace X-Frame-Options.",
                        missing.join(", ")
                    ),
                    None,
                    check,
                    findings,
                );
            }
        }
        _ => inconclusive(check, "Configuration check has no implemented probe"),
    }
}

fn directory_index(body: &str) -> bool {
    [
        "<title>index of /",
        "<title>directory listing for /",
        "<title>directory: /",
    ]
    .iter()
    .any(|title| body.contains(title))
        && body.contains("href=")
        && ["parent directory", "<ul", "<table"]
            .iter()
            .any(|marker| body.contains(marker))
}

fn directive<'a>(policy: &'a str, name: &str) -> Option<&'a str> {
    policy.split(';').find_map(|part| {
        let part = part.trim();
        let split = part.find(char::is_whitespace).unwrap_or(part.len());
        part[..split]
            .eq_ignore_ascii_case(name)
            .then(|| part[split..].trim())
    })
}

fn error_url(base: &Url) -> Url {
    let mut url = base.join("wfs").unwrap();
    url.query_pairs_mut()
        .append_pair("service", "WFS")
        .append_pair("version", "1.0.0")
        .append_pair("request", "GetFeature")
        .append_pair("typeName", "geoscan_missing_probe_4c:missing")
        .append_pair("maxFeatures", "1");
    url
}

pub(super) fn private_url(base: &Url, layer: &str) -> Url {
    let mut url = base.join("wfs").unwrap();
    url.query_pairs_mut()
        .append_pair("service", "WFS")
        .append_pair("version", "1.0.0")
        .append_pair("request", "GetFeature")
        .append_pair("typeName", layer)
        .append_pair("maxFeatures", "1")
        .append_pair("outputFormat", "application/json");
    url
}

pub(super) fn validate_saved_url(id: &str, base: &Url, url: &Url) -> Result<(), String> {
    let path = url
        .path()
        .strip_prefix(base.path())
        .ok_or("Invalid saved application path")?;
    let valid = match id {
        "GS-MISC-001" | "GS-MISC-002" | "GS-MISC-008" => {
            path == "rest/workspaces.json" && url.query().is_none()
        }
        "GS-MISC-003" => {
            path.strip_prefix("gwc/rest/layers/")
                .and_then(|path| path.strip_suffix(".json"))
                .is_some_and(|layer| SqliTarget::new(layer, "id").is_ok())
                && url.query().is_none()
        }
        "GS-MISC-004" => {
            ["rest/about/status.json", "rest/about/system-status.json"].contains(&path)
                && url.query().is_none()
        }
        "GS-MISC-005" => url == &error_url(base),
        "GS-MISC-006" => FILES.contains(&path) && url.query().is_none(),
        "GS-MISC-007" => url
            .query_pairs()
            .find(|(key, _)| key == "typeName")
            .is_some_and(|(_, layer)| {
                SqliTarget::new(&layer, "id").is_ok() && url == &private_url(base, &layer)
            }),
        "GS-MISC-009" | "GS-MISC-010" | "GS-MISC-011" => path == "web/",
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err("Saved URL is not a supported bounded reproduction endpoint".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn directory_indexes_require_a_title_and_structured_links() {
        assert!(directory_index(
            "<title>index of /geoserver/data/</title><table><a href='../'>parent directory</a></table>"
        ));
        assert!(directory_index(
            "<title>directory listing for /geoserver/data/</title><ul><a href='users.xml'>users.xml</a></ul>"
        ));
        assert!(!directory_index(
            "<title>geoserver</title><p>index of /geoserver/data/</p><a href='login'>login</a>"
        ));
    }
}

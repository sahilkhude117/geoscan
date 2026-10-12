use reqwest::Url;
use serde::{Deserialize, Serialize};

use super::{REST_CHECK, SQLI_CHECK, SqliTarget, same_endpoint};
use crate::detect::normalize_target;

#[derive(Debug, Deserialize, Serialize)]
pub struct ReproductionStep {
    pub title: String,
    pub command: String,
    pub expected: String,
}

fn shell_quote(value: &str) -> String {
    if value.contains('\'') {
        format!(
            "\"{}\"",
            value
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('$', "\\$")
                .replace('`', "\\`")
        )
    } else {
        format!("'{value}'")
    }
}

fn curl(url: &Url, query_parameters: bool) -> String {
    let mut endpoint = url.clone();
    if query_parameters {
        endpoint.set_query(None);
    }
    let mut command = format!(
        "curl --noproxy '*' --max-time 15 -sS -i{} \\\n  {}",
        if query_parameters { " -G" } else { "" },
        shell_quote(endpoint.as_str())
    );
    if query_parameters {
        for (key, value) in url.query_pairs() {
            command.push_str(&format!(
                " \\\n  --data-urlencode {}",
                shell_quote(&format!("{key}={value}"))
            ));
        }
    }
    command
}

pub(super) fn steps(
    cve_id: &str,
    target: &str,
    matched_at: &str,
) -> Result<(String, Vec<ReproductionStep>), String> {
    let target = normalize_target(target)?;
    let matched = Url::parse(matched_at).map_err(|error| error.to_string())?;
    match cve_id {
        REST_CHECK => {
            let expected = target
                .join("rest.html")
                .map_err(|error| error.to_string())?;
            if !same_endpoint(&matched, &expected) {
                return Err("Saved REST finding is outside the selected endpoint".into());
            }
            Ok((
                "The REST index was accessible without login and contained the configuration API markers.".into(),
                vec![ReproductionStep {
                    title: "Request the REST index without logging in".into(),
                    command: curl(&expected, false),
                    expected: "HTTP 200 with Geoserver Configuration API and about/status in the page. HTTP 401 or 403 does not match this check.".into(),
                }],
            ))
        }
        SQLI_CHECK => {
            let pairs = matched.query_pairs().collect::<Vec<_>>();
            let layer = pairs
                .iter()
                .find(|(key, _)| key == "typeName")
                .map(|(_, value)| value.as_ref())
                .ok_or("Saved SQLi finding has no layer")?;
            let filter = pairs
                .iter()
                .find(|(key, _)| key == "CQL_FILTER")
                .map(|(_, value)| value.as_ref())
                .ok_or("Saved SQLi finding has no filter")?;
            let property = filter
                .strip_prefix("jsonArrayContains(\"")
                .and_then(|filter| filter.strip_suffix("\",'/a','x''') = true"))
                .ok_or("Saved SQLi finding has an unsupported filter")?;
            let selected = SqliTarget::new(layer, property)?;
            let probe = selected.filter_url(target.as_str(), true)?;
            if !same_endpoint(&matched, &probe) {
                return Err(
                    "Saved SQLi finding is outside the selected layer/filter endpoint".into(),
                );
            }
            let baseline = selected.filter_url(target.as_str(), false)?;
            Ok((
                "A valid JSON filter returned GeoJSON; adding an apostrophe produced PostgreSQL/JDBC quoting-error evidence. This does not prove arbitrary SQL execution.".into(),
                vec![
                    ReproductionStep {
                        title: format!("Baseline: query {layer}.{property} with the ordinary value x"),
                        command: curl(&baseline, true),
                        expected: "HTTP 200 with a GeoJSON FeatureCollection. An exception or login page is an invalid baseline.".into(),
                    },
                    ReproductionStep {
                        title: "Probe: repeat the filter with an apostrophe in the value".into(),
                        command: curl(&probe, true),
                        expected: "An OGC XML exception with a PostgreSQL quote/syntax error, or Unterminated identifier ... in SQL SELECT ... jsonb_path_exists(...) ... Expected quote char. HTTP 200 can still contain this error XML.".into(),
                    },
                ],
            ))
        }
        _ => Err("Reproduction is unavailable for this unimplemented check".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reproduction_uses_the_saved_custom_layer_property_and_context() {
        let selected = SqliTarget::new("my_workspace:my_layer", "my_json").unwrap();
        let target = "http://127.0.0.1:8080/custom/";
        let url = selected.filter_url(target, true).unwrap();
        let (evidence, steps) = steps(SQLI_CHECK, target, url.as_str()).unwrap();
        assert_eq!(steps.len(), 2);
        for step in &steps {
            assert!(step.command.contains("/custom/wfs"));
            assert!(step.command.contains("typeName=my_workspace:my_layer"));
            assert!(step.command.contains("my_json"));
            assert!(!step.command.contains("admin"));
        }
        assert!(evidence.contains("does not prove arbitrary SQL execution"));
        assert_ne!(steps[0].command, steps[1].command);
    }

    #[test]
    fn saved_findings_cannot_generate_commands_for_other_endpoints_or_credentials() {
        let target = "http://127.0.0.1:8080/geoserver/";
        for url in [
            "http://evil.invalid/geoserver/rest.html",
            "http://admin:secret@127.0.0.1:8080/geoserver/rest.html",
            "http://127.0.0.1:8080/geoserver/rest.html?extra=1",
        ] {
            assert!(steps(REST_CHECK, target, url).is_err());
        }
        let url = SqliTarget::default().filter_url(target, true).unwrap();
        assert!(
            steps(
                SQLI_CHECK,
                target,
                &url.to_string().replace("maxFeatures=1", "maxFeatures=20")
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn shell_quoting_preserves_quotes_and_shell_metacharacters_literally() {
        let input = "workspace'$(printf injected)`printf injected`\"; test";
        let result = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("printf '%s' {}", shell_quote(input)))
            .output()
            .unwrap();
        assert!(result.status.success());
        assert_eq!(String::from_utf8(result.stdout).unwrap(), input);
        assert!(result.stderr.is_empty());
    }
}

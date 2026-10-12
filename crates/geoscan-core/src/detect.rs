use std::time::Duration;

use reqwest::{Client, StatusCode, Url};
use roxmltree::Document;
use serde_json::Value;

#[derive(Debug)]
pub struct Detection {
    pub target: String,
    pub reachable: bool,
    pub likely_geoserver: bool,
    pub evidence: Vec<String>,
    pub version: Option<String>,
    pub version_note: String,
    pub wms: String,
    pub wfs: String,
}

#[derive(Clone)]
struct EndpointResponse {
    status: StatusCode,
    body: Result<String, String>,
}

// Keep HTTP transport separate so detection can be tested without network access.
trait HttpClient {
    async fn fetch(&self, url: Url, auth: Option<(&str, &str)>)
    -> Result<EndpointResponse, String>;
}

impl HttpClient for Client {
    async fn fetch(
        &self,
        url: Url,
        auth: Option<(&str, &str)>,
    ) -> Result<EndpointResponse, String> {
        let mut request = self.get(url);

        if let Some((username, password)) = auth {
            request = request.basic_auth(username, Some(password));
        }

        let mut response = request.send().await.map_err(|e| e.to_string())?;
        let status = response.status();
        let body = read_body(&mut response).await;

        // Preserve reachability even when a response body is too large or unreadable.
        Ok(EndpointResponse { status, body })
    }
}

pub(crate) async fn read_body(response: &mut reqwest::Response) -> Result<String, String> {
    let mut body = Vec::new();

    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        if body.len() + chunk.len() > 2 * 1024 * 1024 {
            return Err("Response exceeded the 2 MiB limit".to_owned());
        }

        body.extend_from_slice(&chunk);
    }

    String::from_utf8(body).map_err(|e| e.to_string())
}

async fn probe_service(
    client: &impl HttpClient,
    url: Url,
    expected_root: &str,
) -> (bool, String, Vec<String>) {
    match client.fetch(url, None).await {
        Ok(response) => {
            let (description, evidence) = inspect_service(&response, expected_root);
            (true, description, evidence)
        }
        Err(error) => (false, format!("Inconclusive: {error}"), Vec::new()),
    }
}

fn inspect_service(response: &EndpointResponse, expected_root: &str) -> (String, Vec<String>) {
    if matches!(
        response.status,
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ) {
        return (
            "Authentication required or access forbidden".to_owned(),
            Vec::new(),
        );
    }

    if !response.status.is_success() {
        return (
            format!("Inconclusive: HTTP {}", response.status),
            Vec::new(),
        );
    }

    let body = match &response.body {
        Ok(body) => body,
        Err(error) => return (format!("Inconclusive: {error}"), Vec::new()),
    };

    let document = match Document::parse(body) {
        Ok(document) => document,
        Err(_) => {
            return (
                "Inconclusive: response was not valid XML".to_owned(),
                Vec::new(),
            );
        }
    };

    let root = document.root_element();
    if root.tag_name().name() != expected_root {
        return (
            "No matching capabilities document returned".to_owned(),
            Vec::new(),
        );
    }

    let service = if expected_root == "WMS_Capabilities" {
        "WMS"
    } else {
        "WFS"
    };
    let mut evidence = Vec::new();

    // Read service metadata only. A layer name or XML comment mentioning
    // GeoServer does not identify the software serving the capabilities.
    for metadata in root.children().filter(|node| {
        node.is_element() && matches!(node.tag_name().name(), "Service" | "ServiceIdentification")
    }) {
        for field in metadata.children().filter(|node| {
            node.is_element() && matches!(node.tag_name().name(), "Title" | "Abstract")
        }) {
            let text = field.text().unwrap_or_default();
            if text
                .split(|c: char| !c.is_ascii_alphanumeric())
                .any(|word| word.eq_ignore_ascii_case("geoserver"))
            {
                evidence.push(format!(
                    "GeoServer branding in {service} service {}",
                    field.tag_name().name()
                ));
            }
        }
    }

    ("Available".to_owned(), evidence)
}

fn web_evidence(response: &EndpointResponse) -> Vec<String> {
    if !response.status.is_success() {
        return Vec::new();
    }
    let Ok(body) = &response.body else {
        return Vec::new();
    };

    let page = body.to_ascii_lowercase();
    let mut evidence = Vec::new();
    if let Some((_, rest)) = page.split_once("<title>")
        && let Some((title, _)) = rest.split_once("</title>")
    {
        let title = title.trim();
        if title == "geoserver"
            || title.starts_with("geoserver:")
            || title.starts_with("geoserver -")
        {
            evidence.push("GeoServer web page title".to_owned());
        }
    }

    if page.contains("wicket/resource/org.geoserver.web.") {
        evidence.push("GeoServer web interface resource path".to_owned());
    }

    evidence
}

fn extract_version(body: &str) -> Result<Option<String>, String> {
    let data: Value = serde_json::from_str(body).map_err(|e| e.to_string())?;

    let version = data["about"]["resource"]
        .as_array()
        .and_then(|resources| {
            resources
                .iter()
                .find(|resource| resource["@name"].as_str() == Some("GeoServer"))
        })
        .and_then(|resource| resource["Version"].as_str())
        .map(str::trim)
        .filter(|version| !version.is_empty())
        .map(str::to_owned);

    Ok(version)
}

pub async fn detect_geoserver(
    target: &str,
    auth: Option<(&str, &str)>,
) -> Result<Detection, String> {
    let base = normalize_target(target)?;
    let client = Client::builder()
        .user_agent("GeoScan/0.1")
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| e.to_string())?;

    detect_with_client(&client, base, auth).await
}

/// Validate an application URL and preserve its context path with a trailing slash.
pub fn normalize_target(target: &str) -> Result<Url, String> {
    let mut base = Url::parse(target.trim()).map_err(|e| e.to_string())?;

    if !matches!(base.scheme(), "http" | "https") || base.host_str().is_none() {
        return Err("Target must be a complete HTTP or HTTPS URL".to_owned());
    }

    if base.query().is_some()
        || base.fragment().is_some()
        || !base.username().is_empty()
        || base.password().is_some()
    {
        return Err(
            "Provide the application URL without query parameters, fragments, or credentials"
                .to_owned(),
        );
    }

    let path = format!("{}/", base.path().trim_end_matches('/'));
    base.set_path(&path);
    Ok(base)
}

async fn detect_with_client(
    client: &impl HttpClient,
    base: Url,
    auth: Option<(&str, &str)>,
) -> Result<Detection, String> {
    let web_url = base.join("web/").map_err(|e| e.to_string())?;
    let wms_url = base
        .join("wms?service=WMS&version=1.3.0&request=GetCapabilities")
        .map_err(|e| e.to_string())?;
    let wfs_url = base
        .join("wfs?service=WFS&version=2.0.0&request=GetCapabilities")
        .map_err(|e| e.to_string())?;
    let version_url = base
        .join("rest/about/version.json")
        .map_err(|e| e.to_string())?;

    let mut reachable = false;
    let mut evidence = Vec::new();

    // Some deployments expose their welcome page at the application root.
    for url in [web_url, base.clone()] {
        if let Ok(response) = client.fetch(url, None).await {
            reachable = true;
            evidence.extend(web_evidence(&response));
            if !evidence.is_empty() {
                break;
            }
        }
    }

    let (wms_reachable, wms, wms_evidence) =
        probe_service(client, wms_url, "WMS_Capabilities").await;

    let (wfs_reachable, wfs, wfs_evidence) =
        probe_service(client, wfs_url, "WFS_Capabilities").await;

    reachable |= wms_reachable || wfs_reachable;
    evidence.extend(wms_evidence);
    evidence.extend(wfs_evidence);

    let mut version = None;

    let version_note = match client.fetch(version_url, auth).await {
        Ok(response) => {
            reachable = true;

            match response.status {
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                    "Authentication required or access forbidden".to_owned()
                }

                status if status.is_success() => match response
                    .body
                    .as_ref()
                    .map_err(Clone::clone)
                    .and_then(|body| extract_version(body))
                {
                    Ok(found) => {
                        version = found;

                        if version.is_some() {
                            evidence.push("GeoServer version reported by the REST API".to_owned());
                            "Reported by the REST API".to_owned()
                        } else {
                            "GeoServer version was not present in the response".to_owned()
                        }
                    }

                    Err(error) => format!("Inconclusive: {error}"),
                },

                status => format!("Inconclusive: HTTP {status}"),
            }
        }

        Err(error) => format!("Inconclusive: {error}"),
    };

    Ok(Detection {
        target: base.to_string(),
        reachable,
        likely_geoserver: !evidence.is_empty(),
        evidence,
        version,
        version_note,
        wms,
        wfs,
    })
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::BTreeMap};

    use super::*;

    const GENERIC_PAGE: &str = "<html><head><title>City maps</title></head></html>";
    const GENERIC_WMS: &str = r#"<WMS_Capabilities xmlns="http://www.opengis.net/wms">
        <Service><Title>City maps</Title></Service></WMS_Capabilities>"#;
    const GENERIC_WFS: &str = r#"<wfs:WFS_Capabilities xmlns:wfs="http://www.opengis.net/wfs/2.0"
        xmlns:ows="http://www.opengis.net/ows/1.1">
        <ows:ServiceIdentification><ows:Title>City features</ows:Title>
        </ows:ServiceIdentification></wfs:WFS_Capabilities>"#;
    const GEOSERVER_WMS: &str = r#"<WMS_Capabilities xmlns="http://www.opengis.net/wms">
        <Service><Title>GeoServer Web Map Service</Title></Service></WMS_Capabilities>"#;
    const GEOSERVER_WFS: &str = r#"<wfs:WFS_Capabilities xmlns:wfs="http://www.opengis.net/wfs/2.0"
        xmlns:ows="http://www.opengis.net/ows/1.1">
        <ows:ServiceIdentification><ows:Title>GeoServer Web Feature Service</ows:Title>
        </ows:ServiceIdentification></wfs:WFS_Capabilities>"#;

    struct MockClient {
        responses: BTreeMap<String, EndpointResponse>,
        requests: RefCell<Vec<(Url, bool)>>,
    }

    impl HttpClient for MockClient {
        async fn fetch(
            &self,
            url: Url,
            auth: Option<(&str, &str)>,
        ) -> Result<EndpointResponse, String> {
            self.requests
                .borrow_mut()
                .push((url.clone(), auth.is_some()));
            self.responses
                .get(url.path())
                .cloned()
                .ok_or_else(|| "No HTTP response received".to_owned())
        }
    }

    fn response(status: StatusCode, body: &str) -> EndpointResponse {
        EndpointResponse {
            status,
            body: Ok(body.to_owned()),
        }
    }

    fn mock_server(page: &str, wms: &str, wfs: &str) -> MockClient {
        MockClient {
            responses: BTreeMap::from([
                ("/geoserver/web/".to_owned(), response(StatusCode::OK, page)),
                (
                    "/geoserver/".to_owned(),
                    response(StatusCode::NOT_FOUND, ""),
                ),
                ("/geoserver/wms".to_owned(), response(StatusCode::OK, wms)),
                ("/geoserver/wfs".to_owned(), response(StatusCode::OK, wfs)),
                (
                    "/geoserver/rest/about/version.json".to_owned(),
                    response(StatusCode::UNAUTHORIZED, "Authentication required"),
                ),
            ]),
            requests: RefCell::new(Vec::new()),
        }
    }

    async fn detect_mock(client: &MockClient) -> Detection {
        detect_with_client(
            client,
            normalize_target("http://localhost/geoserver").unwrap(),
            None,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn branded_services_identify_geoserver_when_admin_endpoints_are_protected() {
        let mut client = mock_server(GENERIC_PAGE, GEOSERVER_WMS, GEOSERVER_WFS);
        client.responses.insert(
            "/geoserver/web/".to_owned(),
            response(StatusCode::FORBIDDEN, "Access forbidden"),
        );
        let report = detect_mock(&client).await;

        assert!(report.reachable);
        assert!(report.likely_geoserver);
        assert_eq!(report.version, None);
        assert_eq!(
            report.version_note,
            "Authentication required or access forbidden"
        );
        assert_eq!(report.wms, "Available");
        assert_eq!(report.wfs, "Available");
        assert_eq!(
            report.evidence,
            vec![
                "GeoServer branding in WMS service Title",
                "GeoServer branding in WFS service Title",
            ]
        );
    }

    #[tokio::test]
    async fn geoserver_page_title_does_not_require_a_documentation_link() {
        let client = mock_server(
            "<html><title>GeoServer: Welcome</title></html>",
            GENERIC_WMS,
            GENERIC_WFS,
        );
        let report = detect_mock(&client).await;

        assert!(report.likely_geoserver);
        assert_eq!(report.evidence, vec!["GeoServer web page title"]);
    }

    #[tokio::test]
    async fn wicket_resources_identify_a_customized_web_page() {
        let page = r#"<html><title>City maps</title><link rel="stylesheet"
            href="wicket/resource/org.geoserver.web.GeoServerBasePage/css/geoserver.css"/></html>"#;
        let report = detect_mock(&mock_server(page, GENERIC_WMS, GENERIC_WFS)).await;

        assert!(report.likely_geoserver);
        assert_eq!(
            report.evidence,
            vec!["GeoServer web interface resource path"]
        );
    }

    #[tokio::test]
    async fn application_root_is_checked_when_the_web_page_has_no_clues() {
        let mut client = mock_server(GENERIC_PAGE, GENERIC_WMS, GENERIC_WFS);
        client.responses.insert(
            "/geoserver/".to_owned(),
            response(StatusCode::OK, "<title>GeoServer - Welcome</title>"),
        );
        let report = detect_mock(&client).await;

        assert!(report.likely_geoserver);
        assert!(
            client
                .requests
                .borrow()
                .iter()
                .any(|(url, _)| url.path() == "/geoserver/")
        );
    }

    #[tokio::test]
    async fn generic_ogc_services_do_not_identify_geoserver() {
        let page = "<html><title>City maps</title><p>Works with GeoServer.</p>
            <a href='https://geoserver.org'>Documentation</a></html>";
        let report = detect_mock(&mock_server(page, GENERIC_WMS, GENERIC_WFS)).await;

        assert!(report.reachable);
        assert!(!report.likely_geoserver);
        assert!(report.evidence.is_empty());
        assert_eq!(report.wms, "Available");
        assert_eq!(report.wfs, "Available");
    }

    #[tokio::test]
    async fn xml_comments_layer_names_and_partial_words_are_not_product_evidence() {
        let wms = "<WMS_Capabilities><Service><Title>City maps</Title>
            <Abstract>NotGeoServer GIS</Abstract></Service><!-- GeoServer -->
            <Capability><Layer><Title>GeoServer datasets</Title></Layer></Capability>
            </WMS_Capabilities>";
        let report = detect_mock(&mock_server(GENERIC_PAGE, wms, GENERIC_WFS)).await;

        assert_eq!(report.wms, "Available");
        assert!(!report.likely_geoserver);
    }

    #[tokio::test]
    async fn malformed_xml_and_wrong_document_roots_are_inconclusive() {
        let wfs = "<page><ServiceIdentification><Title>GeoServer</Title>
            </ServiceIdentification></page>";
        let report = detect_mock(&mock_server(GENERIC_PAGE, "<WMS_Capabilities>", wfs)).await;

        assert!(report.reachable);
        assert!(!report.likely_geoserver);
        assert_eq!(report.wms, "Inconclusive: response was not valid XML");
        assert_eq!(report.wfs, "No matching capabilities document returned");
    }

    #[tokio::test]
    async fn authenticated_version_identifies_geoserver_and_auth_is_only_sent_to_rest() {
        let mut client = mock_server(GENERIC_PAGE, GENERIC_WMS, GENERIC_WFS);
        client.responses.insert(
            "/geoserver/rest/about/version.json".to_owned(),
            response(
                StatusCode::OK,
                r#"{"about":{"resource":[
                {"@name":"GeoTools","Version":"34.2"},
                {"@name":"GeoServer","Version":"2.28.2"}]}}"#,
            ),
        );
        let report = detect_with_client(
            &client,
            normalize_target("http://localhost/geoserver").unwrap(),
            Some(("owner", "fixture-password")),
        )
        .await
        .unwrap();

        assert!(report.likely_geoserver);
        assert_eq!(report.version.as_deref(), Some("2.28.2"));
        assert_eq!(
            report.evidence,
            vec!["GeoServer version reported by the REST API"]
        );
        for (url, authenticated) in client.requests.borrow().iter() {
            assert_eq!(
                *authenticated,
                url.path() == "/geoserver/rest/about/version.json"
            );
        }
    }

    #[tokio::test]
    async fn custom_application_paths_are_preserved() {
        let mut client = mock_server(GENERIC_PAGE, GEOSERVER_WMS, GEOSERVER_WFS);
        client.responses = client
            .responses
            .into_iter()
            .map(|(path, response)| (path.replacen("/geoserver", "/custom/maps", 1), response))
            .collect();
        let report = detect_with_client(
            &client,
            normalize_target("http://localhost/custom/maps/").unwrap(),
            None,
        )
        .await
        .unwrap();

        assert_eq!(report.target, "http://localhost/custom/maps/");
        assert!(report.likely_geoserver);
        for (url, _) in client.requests.borrow().iter() {
            assert!(url.path().starts_with("/custom/maps/"));
            if url.path().ends_with("/wms") || url.path().ends_with("/wfs") {
                assert!(
                    url.query_pairs()
                        .any(|(key, value)| key == "request" && value == "GetCapabilities")
                );
            }
        }
    }

    #[tokio::test]
    async fn unreadable_bodies_do_not_hide_http_reachability() {
        let mut client = mock_server(GENERIC_PAGE, GENERIC_WMS, GENERIC_WFS);
        for response in client.responses.values_mut() {
            response.body = Err("Response exceeded the 2 MiB limit".to_owned());
        }
        let report = detect_mock(&client).await;

        assert!(report.reachable);
        assert!(!report.likely_geoserver);
        assert!(report.wms.contains("Response exceeded"));
        assert!(report.wfs.contains("Response exceeded"));
    }

    #[tokio::test]
    async fn unreachable_endpoints_are_reported_without_inventing_evidence() {
        let client = MockClient {
            responses: BTreeMap::new(),
            requests: RefCell::new(Vec::new()),
        };
        let report = detect_mock(&client).await;

        assert!(!report.reachable);
        assert!(!report.likely_geoserver);
        assert!(report.evidence.is_empty());
        assert!(report.version.is_none());
    }

    #[test]
    fn invalid_target_forms_are_rejected_before_any_http_request() {
        for target in [
            "localhost/geoserver",
            "file:///tmp/maps",
            "ftp://localhost/maps",
            "http://localhost/geoserver?x=1",
            "http://localhost/geoserver#web",
            "http://owner:secret@localhost/geoserver",
        ] {
            assert!(
                normalize_target(target).is_err(),
                "Unexpectedly accepted {target}"
            );
        }
    }

    #[test]
    fn blank_version_is_not_treated_as_a_release_number() {
        assert_eq!(
            extract_version(
                r#"{"about":{"resource":[
            {"@name":"GeoServer","Version":"   "}]}}"#
            )
            .unwrap(),
            None
        );
    }
}

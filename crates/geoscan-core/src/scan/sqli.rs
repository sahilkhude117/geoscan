use std::time::Duration;

use reqwest::{Client, StatusCode, Url};
use roxmltree::Document;

use crate::detect::read_body;

pub const DEFAULT_LAYER: &str = "geoscan_sqli_demo:items";
pub const DEFAULT_PROPERTY: &str = "json_data";

#[derive(Debug)]
pub struct SqliTarget {
    pub(super) layer: String,
    pub(super) property: String,
}

impl Default for SqliTarget {
    fn default() -> Self {
        Self {
            layer: DEFAULT_LAYER.into(),
            property: DEFAULT_PROPERTY.into(),
        }
    }
}

impl SqliTarget {
    pub fn new(layer: &str, property: &str) -> Result<Self, String> {
        fn name(value: &str) -> bool {
            let mut characters = value.chars();
            value.len() <= 128
                && characters
                    .next()
                    .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
                && characters.all(|ch| ch.is_ascii_alphanumeric() || "_.-".contains(ch))
        }

        if layer.split(':').count() > 2 || !layer.split(':').all(name) || !name(property) {
            return Err("SQLi layer must be a layer name or workspace:layer; property must be an attribute name (letters, digits, underscore, dot, or hyphen)".into());
        }
        Ok(Self {
            layer: layer.into(),
            property: property.into(),
        })
    }

    pub(super) fn filter_url(&self, target: &str, apostrophe: bool) -> Result<Url, String> {
        let mut url = Url::parse(target)
            .map_err(|error| error.to_string())?
            .join("wfs")
            .map_err(|error| error.to_string())?;
        let value = if apostrophe { "x'''" } else { "x'" };
        let filter = format!(
            "jsonArrayContains(\"{}\",'/a','{value}) = true",
            self.property
        );
        url.query_pairs_mut()
            .append_pair("service", "WFS")
            .append_pair("version", "1.0.0")
            .append_pair("request", "GetFeature")
            .append_pair("typeName", &self.layer)
            .append_pair("maxFeatures", "1")
            .append_pair("outputFormat", "application/json")
            .append_pair("CQL_FILTER", &filter);
        Ok(url)
    }
}

pub(super) enum Eligibility {
    Ready,
    NotApplicable(String),
    Inconclusive(String),
}

pub(super) async fn preflight(target: &str, selected: &SqliTarget) -> Eligibility {
    let request = async {
        let mut url = Url::parse(target)
            .map_err(|error| error.to_string())?
            .join("wfs")
            .map_err(|error| error.to_string())?;
        url.query_pairs_mut()
            .append_pair("service", "WFS")
            .append_pair("version", "1.0.0")
            .append_pair("request", "DescribeFeatureType")
            .append_pair("typeName", &selected.layer);
        let client = Client::builder()
            .user_agent("GeoScan/0.1")
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| error.to_string())?;
        // Both the preflight and Nuclei requests remain unauthenticated.
        let mut response = client
            .get(url)
            .send()
            .await
            .map_err(|error| error.to_string())?;
        let status = response.status();
        let body = read_body(&mut response).await?;
        Ok::<_, String>(inspect_schema(status, &body, selected))
    }
    .await;
    request.unwrap_or_else(Eligibility::Inconclusive)
}

fn inspect_schema(status: StatusCode, body: &str, selected: &SqliTarget) -> Eligibility {
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        return Eligibility::Inconclusive(
            "WFS requires authentication; this check tests public layer access".into(),
        );
    }
    let document = match Document::parse(body) {
        Ok(document) => document,
        Err(_) => {
            return Eligibility::Inconclusive(
                "DescribeFeatureType did not return valid XML".into(),
            );
        }
    };
    let root = document.root_element();
    if matches!(
        root.tag_name().name(),
        "ExceptionReport" | "ServiceExceptionReport"
    ) {
        let message = document
            .descendants()
            .filter(|node| matches!(node.tag_name().name(), "ExceptionText" | "ServiceException"))
            .filter_map(|node| node.text())
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase();
        if [
            "not found",
            "does not exist",
            "unknown feature type",
            "could not find",
        ]
        .iter()
        .any(|phrase| message.contains(phrase))
        {
            return Eligibility::NotApplicable(format!(
                "Layer {} is unavailable; publish the PostGIS demo or select --sqli-layer",
                selected.layer
            ));
        }
        return Eligibility::Inconclusive(
            "GeoServer rejected DescribeFeatureType for the selected layer".into(),
        );
    }
    const XSD: &str = "http://www.w3.org/2001/XMLSchema";
    if !status.is_success()
        || root.tag_name().name() != "schema"
        || root.tag_name().namespace() != Some(XSD)
    {
        return Eligibility::Inconclusive(format!(
            "DescribeFeatureType returned an unexpected response (HTTP {status})"
        ));
    }
    let field = document.descendants().find(|node| {
        node.tag_name().name() == "element"
            && node.tag_name().namespace() == Some(XSD)
            && node.attribute("name") == Some(selected.property.as_str())
    });
    let Some(field) = field else {
        return Eligibility::NotApplicable(format!(
            "Attribute {} is absent from {}; select --sqli-property",
            selected.property, selected.layer
        ));
    };
    let is_string = field.attribute("type").is_some_and(|kind| {
        kind.split_once(':').is_some_and(|(prefix, name)| {
            name == "string" && field.lookup_namespace_uri(Some(prefix)) == Some(XSD)
        })
    });
    if !is_string {
        return Eligibility::NotApplicable("The selected attribute is not advertised as an XML Schema String; this probe supports String-mapped JSON data".into());
    }
    Eligibility::Ready
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_layer_names_and_rejects_template_or_cql_injection_in_parameters() {
        assert!(SqliTarget::new("workspace:items", "json_data").is_ok());
        for (layer, property) in [
            ("a:b:c", "data"),
            ("items&extra=true", "data"),
            ("items", "\"),true)"),
            ("{{Hostname}}", "data"),
            ("items", "1field"),
        ] {
            assert!(SqliTarget::new(layer, property).is_err());
        }
    }

    #[test]
    fn builds_valid_cql_literals_and_keeps_custom_context_paths() {
        let selected = SqliTarget::default();
        for (apostrophe, expected) in [
            (false, "jsonArrayContains(\"json_data\",'/a','x') = true"),
            (true, "jsonArrayContains(\"json_data\",'/a','x''') = true"),
        ] {
            let url = selected
                .filter_url("http://localhost/maps/", apostrophe)
                .unwrap();
            assert_eq!(url.path(), "/maps/wfs");
            assert!(
                url.query_pairs()
                    .any(|(key, value)| key == "CQL_FILTER" && value == expected)
            );
        }
    }

    #[test]
    fn schema_preflight_distinguishes_supported_missing_and_protected_layers() {
        let selected = SqliTarget::default();
        let schema = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"><xs:complexType><xs:sequence><xs:element name="json_data" type="xs:string"/></xs:sequence></xs:complexType></xs:schema>"#;
        assert!(matches!(
            inspect_schema(StatusCode::OK, schema, &selected),
            Eligibility::Ready
        ));
        assert!(matches!(
            inspect_schema(
                StatusCode::OK,
                &schema.replace("xs:string", "xs:int"),
                &selected
            ),
            Eligibility::NotApplicable(_)
        ));
        assert!(matches!(
            inspect_schema(
                StatusCode::OK,
                &schema.replace("json_data", "other"),
                &selected
            ),
            Eligibility::NotApplicable(_)
        ));
        assert!(matches!(
            inspect_schema(StatusCode::UNAUTHORIZED, "", &selected),
            Eligibility::Inconclusive(_)
        ));
        let missing = "<ServiceExceptionReport><ServiceException>Feature type geoscan_sqli_demo:items not found</ServiceException></ServiceExceptionReport>";
        assert!(matches!(
            inspect_schema(StatusCode::BAD_REQUEST, missing, &selected),
            Eligibility::NotApplicable(_)
        ));
        assert!(matches!(
            inspect_schema(StatusCode::OK, "<html/>", &selected),
            Eligibility::Inconclusive(_)
        ));
    }
}

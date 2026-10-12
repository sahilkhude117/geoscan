//! Embedded CVE metadata shared by the CLI and a future web API.
//! Version matches indicate possible exposure, not a confirmed vulnerability.

use std::collections::HashSet;

use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Review labels for a future scanning runner; this module executes no probes.
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProbePolicy {
    ReadOnly,
    LabOnly,
    Unreviewed,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VersionScope {
    GeoServer,
    GeoWebCache,
    Uncertain,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DateKind {
    CvePublication,
    NvdPublication,
    AdvisoryPublication,
    CveModified,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourcedDate {
    pub kind: DateKind,
    pub date: String,
    pub source: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CvssRating {
    pub score: f64,
    pub severity: Severity,
    pub version: String,
    pub vector: Option<String>,
    pub source: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KnownExploited {
    pub date_added: String,
    pub source: String,
}

/// Preserve the user's input separately from researched, sourced metadata.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReportedMetadata {
    pub cvss_score: f64,
    pub severity: Severity,
    pub published: String,
    pub publication_note: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CveCheck {
    pub id: String,
    pub name: String,
    pub vulnerability_type: String,
    pub description: String,
    pub component: String,
    pub authentication: String,
    pub severity: Severity,
    /// The first rating determines the displayed severity; alternatives retain provenance.
    pub cvss: Vec<CvssRating>,
    pub dates: Vec<SourcedDate>,
    pub cwes: Vec<String>,
    /// None means no KEV entry is recorded here, not a live check of CISA's catalogue.
    pub kev: Option<KnownExploited>,
    pub affected: Vec<String>,
    pub fixed_versions: Vec<String>,
    pub version_scope: VersionScope,
    pub version_notes: String,
    pub prerequisites: Vec<String>,
    pub remediation: String,
    pub advisory_url: String,
    pub references: Vec<String>,
    pub template: Option<String>,
    pub probe_policy: ProbePolicy,
    pub template_notes: String,
    pub researched_at: String,
    pub reported_metadata: Option<ReportedMetadata>,
}

impl CveCheck {
    /// Prefer a verified CVE/NVD publication date; never use modification dates.
    pub fn publication_date(&self) -> Option<&SourcedDate> {
        [
            DateKind::CvePublication,
            DateKind::NvdPublication,
            DateKind::AdvisoryPublication,
        ]
        .into_iter()
        .find_map(|kind| self.dates.iter().find(|date| date.kind == kind))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum VersionStatus {
    Unknown,
    PotentiallyAffected,
    OutsideAffectedRanges,
}

/// Embed the catalogue so installed binaries work outside the project directory.
pub fn load_catalog() -> Result<Vec<CveCheck>, String> {
    parse_catalog(include_str!("../data/cves.json"))
}

fn parse_catalog(json: &str) -> Result<Vec<CveCheck>, String> {
    let checks: Vec<CveCheck> =
        serde_json::from_str(json).map_err(|error| format!("Invalid catalogue JSON: {error}"))?;
    if checks.is_empty() {
        return Err("The catalogue must contain at least one check".to_owned());
    }

    let mut ids = HashSet::new();
    for check in &checks {
        if !ids.insert(&check.id) {
            return Err(format!("Duplicate catalogue entry: {}", check.id));
        }
        validate_metadata(check)?;
        if check.affected.is_empty() {
            return Err(format!("{} has no affected version ranges", check.id));
        }
        for range in &check.affected {
            VersionReq::parse(range)
                .map_err(|error| format!("{}: invalid range '{range}': {error}", check.id))?;
        }
        for fixed in &check.fixed_versions {
            Version::parse(fixed).map_err(|error| {
                format!("{}: invalid fixed version '{fixed}': {error}", check.id)
            })?;
        }
        if check.probe_policy != ProbePolicy::Unreviewed
            && check
                .template
                .as_deref()
                .is_none_or(|template| template.trim().is_empty())
        {
            return Err(format!("{} requires a template mapping", check.id));
        }
    }
    Ok(checks)
}

fn validate_metadata(check: &CveCheck) -> Result<(), String> {
    let invalid = |detail: &str| format!("{}: {detail}", check.id);
    for value in [
        &check.name,
        &check.vulnerability_type,
        &check.description,
        &check.component,
        &check.authentication,
        &check.version_notes,
        &check.remediation,
    ] {
        if value.trim().is_empty() {
            return Err(invalid("metadata contains an empty required field"));
        }
    }
    if check.prerequisites.is_empty() || check.prerequisites.iter().any(|s| s.trim().is_empty()) {
        return Err(invalid("configuration requirements must be provided"));
    }
    if check.cvss.is_empty() {
        return Err(invalid("at least one sourced CVSS rating is required"));
    }
    for rating in &check.cvss {
        let expected = score_severity(rating.score).ok_or_else(|| invalid("invalid CVSS score"))?;
        if rating.severity != expected || rating.version != "3.1" {
            return Err(invalid("invalid CVSS severity or version"));
        }
        if rating
            .vector
            .as_deref()
            .is_some_and(|v| !v.starts_with("CVSS:3.1/"))
        {
            return Err(invalid("invalid CVSS vector prefix"));
        }
        validate_source(&rating.source).map_err(|e| invalid(&e))?;
    }
    if check.severity != check.cvss[0].severity {
        return Err(invalid(
            "displayed severity must match the primary CVSS rating",
        ));
    }
    if check.publication_date().is_none() {
        return Err(invalid("at least one sourced publication date is required"));
    }
    for date in &check.dates {
        validate_date(&date.date).map_err(|e| invalid(&e))?;
        validate_source(&date.source).map_err(|e| invalid(&e))?;
    }
    validate_date(&check.researched_at).map_err(|e| invalid(&e))?;
    if let Some(kev) = &check.kev {
        validate_date(&kev.date_added).map_err(|e| invalid(&e))?;
        validate_source(&kev.source).map_err(|e| invalid(&e))?;
        let url = reqwest::Url::parse(&kev.source).map_err(|e| invalid(&e.to_string()))?;
        if url.host_str() != Some("www.cisa.gov") {
            return Err(invalid("KEV metadata must reference CISA"));
        }
    }
    if let Some(reported) = &check.reported_metadata {
        if score_severity(reported.cvss_score) != Some(reported.severity) {
            return Err(invalid("invalid reported CVSS score or severity"));
        }
        validate_date(&reported.published).map_err(|e| invalid(&e))?;
    }
    validate_source(&check.advisory_url).map_err(|e| invalid(&e))?;
    if check.references.is_empty() {
        return Err(invalid("research references are required"));
    }
    for reference in &check.references {
        validate_source(reference).map_err(|e| invalid(&e))?;
    }
    Ok(())
}

fn score_severity(score: f64) -> Option<Severity> {
    if !score.is_finite() || !(0.1..=10.0).contains(&score) {
        return None;
    }
    Some(if score >= 9.0 {
        Severity::Critical
    } else if score >= 7.0 {
        Severity::High
    } else if score >= 4.0 {
        Severity::Medium
    } else {
        Severity::Low
    })
}

fn validate_source(source: &str) -> Result<(), String> {
    let url = reqwest::Url::parse(source).map_err(|_| "invalid research source URL".to_owned())?;
    if url.scheme() != "https" || url.host_str().is_none() {
        return Err("research sources must use HTTPS URLs".to_owned());
    }
    Ok(())
}

fn validate_date(date: &str) -> Result<(), String> {
    let invalid = || format!("invalid date '{date}'; expected YYYY-MM-DD");
    if date.len() != 10
        || date.as_bytes()[4] != b'-'
        || date.as_bytes()[7] != b'-'
        || !date
            .bytes()
            .enumerate()
            .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit())
    {
        return Err(invalid());
    }
    let year: u32 = date[0..4].parse().map_err(|_| invalid())?;
    let month: usize = date[5..7].parse().map_err(|_| invalid())?;
    let day: u32 = date[8..10].parse().map_err(|_| invalid())?;
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if year == 0 || !(1..=12).contains(&month) || day == 0 || day > days[month - 1] {
        return Err(invalid());
    }
    Ok(())
}

/// Compare a release version with the union of the advisory's affected ranges.
/// Missing, unparseable, and prerelease versions remain unknown: a snapshot's
/// patch state cannot be inferred reliably from its version string.
pub fn assess_version(
    check: &CveCheck,
    reported_version: Option<&str>,
) -> Result<VersionStatus, String> {
    // Never compare a GeoServer release with dependency versions or disputed ranges.
    if check.version_scope != VersionScope::GeoServer {
        return Ok(VersionStatus::Unknown);
    }
    let Some(text) = reported_version else {
        return Ok(VersionStatus::Unknown);
    };
    let version = match Version::parse(text.trim()) {
        Ok(version) if version.pre.is_empty() => version,
        _ => return Ok(VersionStatus::Unknown),
    };

    for range in &check.affected {
        let requirement = VersionReq::parse(range)
            .map_err(|error| format!("{}: invalid range '{range}': {error}", check.id))?;
        if requirement.matches(&version) {
            return Ok(VersionStatus::PotentiallyAffected);
        }
    }
    Ok(VersionStatus::OutsideAffectedRanges)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(id: &str) -> CveCheck {
        load_catalog()
            .unwrap()
            .into_iter()
            .find(|check| check.id == id)
            .unwrap()
    }

    #[test]
    fn catalogue_contains_every_requested_cve_and_the_existing_2026_entry() {
        let expected: HashSet<_> = [
            "CVE-2025-58175",
            "CVE-2025-52465",
            "CVE-2025-27511",
            "CVE-2025-21621",
            "CVE-2025-58360",
            "CVE-2025-30220",
            "CVE-2025-30145",
            "CVE-2025-27505",
            "CVE-2024-40625",
            "CVE-2024-38524",
            "CVE-2024-34711",
            "CVE-2024-29198",
            "CVE-2024-35230",
            "CVE-2024-36401",
            "CVE-2024-34696",
            "CVE-2024-24749",
            "CVE-2024-23821",
            "CVE-2024-23819",
            "CVE-2024-23818",
            "CVE-2024-23643",
            "CVE-2024-23642",
            "CVE-2024-23640",
            "CVE-2024-23634",
            "CVE-2023-51445",
            "CVE-2023-51444",
            "CVE-2023-41877",
            "CVE-2023-5786",
            "CVE-2023-43795",
            "CVE-2023-41339",
            "CVE-2023-25157",
            "CVE-2022-24847",
            "CVE-2026-76904",
        ]
        .into_iter()
        .collect();
        let checks = load_catalog().unwrap();
        let actual: HashSet<_> = checks.iter().map(|check| check.id.as_str()).collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn new_advisories_match_affected_releases() {
        for (id, version) in [
            ("CVE-2025-58175", "2.26.3"),
            ("CVE-2025-52465", "2.27.2"),
            ("CVE-2025-27511", "2.26.4"),
            ("CVE-2025-21621", "2.24.4"),
            ("CVE-2025-58360", "2.26.1"),
            ("CVE-2025-30145", "2.26.2"),
            ("CVE-2024-40625", "2.25.7"),
            ("CVE-2024-38524", "2.26.1"),
            ("CVE-2024-34711", "2.24.9"),
            ("CVE-2024-29198", "2.25.0"),
            ("CVE-2024-34696", "2.10.0"),
            ("CVE-2024-24749", "2.24.2"),
            ("CVE-2024-23821", "2.24.0"),
            ("CVE-2024-23819", "2.24.0"),
            ("CVE-2024-23818", "2.23.2"),
            ("CVE-2024-23643", "2.23.1"),
            ("CVE-2024-23642", "2.23.3"),
            ("CVE-2024-23640", "2.23.2"),
            ("CVE-2024-23634", "2.24.1"),
            ("CVE-2023-51445", "2.23.2"),
            ("CVE-2023-51444", "2.24.0"),
            ("CVE-2023-41877", "2.28.2"),
            ("CVE-2023-43795", "2.23.1"),
            ("CVE-2023-41339", "2.22.4"),
            ("CVE-2023-25157", "2.20.6"),
            ("CVE-2022-24847", "2.20.3"),
        ] {
            assert_eq!(
                assess_version(&check(id), Some(version)).unwrap(),
                VersionStatus::PotentiallyAffected,
                "{id} on {version}"
            );
        }
    }

    #[test]
    fn disputed_ranges_and_dependency_versions_do_not_use_a_geoserver_version() {
        for id in ["CVE-2024-35230", "CVE-2023-5786"] {
            for version in ["1.15.0", "2.28.2", "3.0.1"] {
                assert_eq!(
                    assess_version(&check(id), Some(version)).unwrap(),
                    VersionStatus::Unknown
                );
            }
        }
    }

    #[test]
    fn conflicting_scores_keep_both_sources_and_the_original_input() {
        let check = check("CVE-2025-30220");
        assert_eq!(check.severity, Severity::Critical);
        assert_eq!(check.cvss[0].score, 9.9);
        assert!(
            check
                .cvss
                .iter()
                .any(|rating| rating.score == 8.2 && rating.severity == Severity::High)
        );
        assert_eq!(check.reported_metadata.unwrap().cvss_score, 9.9);
        let check = super::tests::check("CVE-2024-24749");
        assert_eq!(check.cvss[0].score, 7.5);
        assert!(check.cvss.iter().any(|rating| rating.score == 5.9));
    }

    #[test]
    fn publication_selection_excludes_modification_and_user_reported_dates() {
        let check = check("CVE-2025-52465");
        let published = check.publication_date().unwrap();
        assert_eq!(published.kind, DateKind::CvePublication);
        assert_eq!(published.date, "2026-06-18");
        assert!(
            check
                .dates
                .iter()
                .any(|date| date.kind == DateKind::CveModified && date.date != published.date)
        );
        let check = super::tests::check("CVE-2025-58175");
        assert_eq!(
            check.publication_date().unwrap().kind,
            DateKind::AdvisoryPublication
        );
        assert_eq!(check.publication_date().unwrap().date, "2026-06-11");
        assert_eq!(check.reported_metadata.unwrap().published, "2026-06-18");
    }

    #[test]
    fn kev_entries_retain_cisa_sources_and_added_dates() {
        for (id, added) in [
            ("CVE-2024-36401", "2024-07-15"),
            ("CVE-2025-58360", "2025-12-11"),
        ] {
            let kev = check(id).kev.unwrap();
            assert_eq!(kev.date_added, added);
            assert!(kev.source.starts_with("https://www.cisa.gov/"));
        }
    }

    #[test]
    fn invalid_research_metadata_is_rejected() {
        for (field, value, expected) in [
            ("cvss", serde_json::json!([]), "sourced CVSS"),
            ("dates", serde_json::json!([]), "publication date"),
            (
                "researched_at",
                serde_json::json!("2026-02-30"),
                "invalid date",
            ),
            (
                "advisory_url",
                serde_json::json!("javascript:alert(1)"),
                "HTTPS",
            ),
        ] {
            let mut json = catalog_json();
            json[0][field] = value;
            assert!(
                parse_catalog(&json.to_string())
                    .unwrap_err()
                    .contains(expected)
            );
        }
        let mut json = catalog_json();
        json[0]["cvss"][0]["score"] = serde_json::json!(11.0);
        assert!(
            parse_catalog(&json.to_string())
                .unwrap_err()
                .contains("invalid CVSS score")
        );
    }

    #[test]
    fn research_dates_validate_calendar_and_utf8_input() {
        assert!(validate_date("2024-02-29").is_ok());
        for invalid in [
            "2025-02-29",
            "2026-04-31",
            "2026-13-01",
            "2026-00-01",
            "2026-01-00",
            "2026-1-01",
            "💡-01-01",
            "0000-01-01",
        ] {
            assert!(validate_date(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn affected_releases_match_advisory_boundaries() {
        let cases = [
            (
                "CVE-2024-36401",
                vec![
                    "2.21.5", "2.22.5", "2.23.0", "2.23.5", "2.24.0", "2.24.3", "2.25.0", "2.25.1",
                ],
            ),
            (
                "CVE-2025-27505",
                vec!["2.24.4", "2.25.5", "2.26.0", "2.26.2"],
            ),
            (
                "CVE-2025-30220",
                vec!["2.25.6", "2.26.0", "2.26.2", "2.27.0"],
            ),
            (
                "CVE-2026-76904",
                vec!["2.23.6", "2.27.5", "2.28.0", "2.28.2", "2.28.4", "3.0.0"],
            ),
        ];
        for (id, versions) in cases {
            let check = check(id);
            for version in versions {
                assert_eq!(
                    assess_version(&check, Some(version)).unwrap(),
                    VersionStatus::PotentiallyAffected,
                    "{id} on {version}"
                );
            }
        }
    }

    #[test]
    fn every_documented_fixed_release_is_outside_affected_ranges() {
        for check in load_catalog().unwrap() {
            if check.version_scope != VersionScope::GeoServer {
                continue;
            }
            for fixed in &check.fixed_versions {
                assert_eq!(
                    assess_version(&check, Some(fixed)).unwrap(),
                    VersionStatus::OutsideAffectedRanges,
                    "{} on {fixed}",
                    check.id
                );
            }
        }
    }

    #[test]
    fn later_branch_does_not_reintroduce_an_earlier_branch_match() {
        let cases = [
            (
                "CVE-2024-36401",
                vec!["2.22.7", "2.23.7", "2.24.5", "2.25.3", "2.28.2"],
            ),
            (
                "CVE-2025-27505",
                vec!["2.25.7", "2.26.4", "2.27.0", "2.28.2"],
            ),
            (
                "CVE-2025-30220",
                vec!["2.25.8", "2.26.4", "2.27.2", "2.28.2"],
            ),
            (
                "CVE-2026-76904",
                vec!["2.23.5", "2.27.7", "2.28.6", "3.0.2"],
            ),
        ];
        for (id, versions) in cases {
            let check = check(id);
            for version in versions {
                assert_eq!(
                    assess_version(&check, Some(version)).unwrap(),
                    VersionStatus::OutsideAffectedRanges,
                    "{id} on {version}"
                );
            }
        }
    }

    #[test]
    fn missing_invalid_and_prerelease_versions_are_unknown() {
        for check in load_catalog().unwrap() {
            for version in [
                None,
                Some(""),
                Some("Unknown"),
                Some("2.28"),
                Some("2.28.2-SNAPSHOT"),
                Some("3.0.0-rc.1"),
            ] {
                assert_eq!(
                    assess_version(&check, version).unwrap(),
                    VersionStatus::Unknown
                );
            }
        }
    }

    #[test]
    fn whitespace_and_build_metadata_preserve_release_comparison() {
        let check = check("CVE-2026-76904");
        assert_eq!(
            assess_version(&check, Some(" 2.28.2+build.1 ")).unwrap(),
            VersionStatus::PotentiallyAffected
        );
    }

    fn catalog_json() -> serde_json::Value {
        serde_json::from_str(include_str!("../data/cves.json")).unwrap()
    }

    #[test]
    fn duplicate_checks_are_rejected() {
        let mut json = catalog_json();
        let duplicate = json[0].clone();
        json.as_array_mut().unwrap().push(duplicate);
        assert!(
            parse_catalog(&json.to_string())
                .unwrap_err()
                .contains("Duplicate catalogue entry")
        );
    }

    #[test]
    fn malformed_or_empty_catalogue_is_rejected() {
        assert!(parse_catalog("not json").is_err());
        assert!(parse_catalog("[]").is_err());
        let mut json = catalog_json();
        json[0]["affected"] = serde_json::json!([]);
        assert!(
            parse_catalog(&json.to_string())
                .unwrap_err()
                .contains("no affected version ranges")
        );
    }

    #[test]
    fn invalid_version_ranges_and_fixes_are_rejected() {
        let mut json = catalog_json();
        json[0]["affected"][0] = serde_json::json!("not a range");
        assert!(
            parse_catalog(&json.to_string())
                .unwrap_err()
                .contains("invalid range")
        );

        let mut json = catalog_json();
        json[0]["fixed_versions"][0] = serde_json::json!("not a version");
        assert!(
            parse_catalog(&json.to_string())
                .unwrap_err()
                .contains("invalid fixed version")
        );
    }

    #[test]
    fn reviewed_checks_require_a_nonempty_template_mapping() {
        for template in [serde_json::Value::Null, serde_json::json!("   ")] {
            let mut json = catalog_json();
            json[0]["probe_policy"] = serde_json::json!("lab_only");
            json[0]["template"] = template;
            assert!(
                parse_catalog(&json.to_string())
                    .unwrap_err()
                    .contains("requires a template mapping")
            );
        }
    }

    #[test]
    fn unknown_catalogue_fields_are_rejected() {
        let mut json = catalog_json();
        json[0]["affected_versions"] = serde_json::json!(["<2.22.6"]);
        assert!(
            parse_catalog(&json.to_string())
                .unwrap_err()
                .contains("unknown field")
        );
    }
}

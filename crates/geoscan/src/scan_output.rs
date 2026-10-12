use std::{fmt::Write, io::IsTerminal, path::Path};

use console::{Alignment, Style, Term, measure_text_width, pad_str};
use geoscan_core::{
    catalog::{Severity, load_catalog},
    scan::ScanReport,
};

fn clean(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect()
}

fn wrapped(value: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in clean(value).split_whitespace() {
        if !line.is_empty() && measure_text_width(&line) + measure_text_width(word) + 1 > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        for ch in word.chars() {
            if measure_text_width(&line) + measure_text_width(&ch.to_string()) > width {
                lines.push(std::mem::take(&mut line));
            }
            line.push(ch);
        }
    }
    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    lines
}

fn severity(value: Severity) -> &'static str {
    match value {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
    }
}

fn status(value: &str) -> &str {
    match value {
        "matches" => "MATCHED",
        "no_match" => "NO MATCH",
        "not_applicable" => "SKIPPED",
        "inconclusive" => "INCONCLUSIVE",
        "partial" => "PARTIAL",
        "failed" => "FAILED",
        "running" => "RUNNING",
        _ => "UNKNOWN",
    }
}

struct Output {
    text: String,
    width: usize,
    color: bool,
}

impl Output {
    fn paint(&self, text: &str, tone: &str) -> String {
        let style = match tone {
            "CRITICAL" | "HIGH" | "MATCHED" | "FAILED" => Style::new().red().bold(),
            "MEDIUM" | "PARTIAL" | "INCONCLUSIVE" => Style::new().yellow().bold(),
            "NO MATCH" | "SKIPPED" => Style::new().dim(),
            _ => Style::new().cyan().bold(),
        };
        style.force_styling(self.color).apply_to(text).to_string()
    }

    fn open(&mut self, title: &str, tone: &str) {
        let title = clean(title);
        let titles = wrapped(&title, self.width - 5);
        let title = &titles[0];
        let line = format!(
            "╭─ {title} {}╮",
            "─".repeat(self.width.saturating_sub(measure_text_width(title) + 5))
        );
        writeln!(self.text, "{}", self.paint(&line, tone)).unwrap();
        for title in titles.iter().skip(1) {
            writeln!(
                self.text,
                "│ {} │",
                pad_str(title, self.width - 4, Alignment::Left, None)
            )
            .unwrap();
        }
    }

    fn field(&mut self, label: &str, value: &str) {
        let prefix = format!("{label:<11}");
        for (index, line) in wrapped(value, self.width - 4 - prefix.len())
            .iter()
            .enumerate()
        {
            let content = format!(
                "{}{line}",
                if index == 0 {
                    prefix.as_str()
                } else {
                    "           "
                }
            );
            writeln!(
                self.text,
                "│ {} │",
                pad_str(&content, self.width - 4, Alignment::Left, None)
            )
            .unwrap();
        }
    }

    fn close(&mut self) {
        writeln!(self.text, "╰{}╯\n", "─".repeat(self.width - 2)).unwrap();
    }

    fn paragraph(&mut self, value: &str, indent: &str) {
        for line in wrapped(value, self.width - indent.len()) {
            writeln!(self.text, "{indent}{line}").unwrap();
        }
    }
}

pub fn render(report: &ScanReport, db: &Path, width: usize, color: bool) -> String {
    let mut output = Output {
        text: String::new(),
        width: width.clamp(48, 104),
        color,
    };
    let catalog = load_catalog().expect("validated bundled catalogue");
    let ran = report.checks.iter().filter(|check| check.ran).count();
    let completed = report
        .checks
        .iter()
        .filter(|check| matches!(check.status.as_str(), "matches" | "no_match"))
        .count();
    output.open(&format!("GeoScan · Scan #{}", report.id), "brand");
    output.field("Target", &report.target);
    output.field(
        "GeoServer",
        report.geoserver_version.as_deref().unwrap_or("Unknown"),
    );
    output.field("Detection", &report.version_note);
    output.field("Outcome", status(&report.status));
    output.field(
        "Checks",
        &format!(
            "{completed} completed · {ran} attempted · {} recorded",
            report.checks.len()
        ),
    );
    output.field("Findings", &report.findings.len().to_string());
    let counts = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
    ]
    .map(|level| {
        format!(
            "{} {}",
            report
                .findings
                .iter()
                .filter(|finding| finding.severity == level)
                .count(),
            severity(level)
        )
    });
    output.field("Severity", &counts.join(" · "));
    output.field(
        "Coverage",
        &format!("{} catalogue entries not run", report.not_run),
    );
    output.field("Saved to", &db.display().to_string());
    output.close();

    writeln!(output.text, "  {}", output.paint("CHECK RESULTS", "brand")).unwrap();
    if report.checks.is_empty() {
        output.paragraph(
            "Per-check outcomes were not stored for this older or unfinished scan.",
            "  ",
        );
    } else {
        let wide = output.width >= 76;
        if wide {
            writeln!(
                output.text,
                "  {:<19} {:<15} {:<10} MATCHES",
                "CVE", "RESULT", "SEVERITY"
            )
            .unwrap();
        }
        for check in &report.checks {
            let rating = catalog
                .iter()
                .find(|entry| entry.id == check.cve_id)
                .map(|entry| severity(entry.severity))
                .unwrap_or("UNKNOWN");
            let result = status(&check.status);
            if wide {
                let row = format!(
                    "  {:<19} {:<15} {:<10} {}",
                    clean(&check.cve_id),
                    result,
                    rating,
                    check.matches
                );
                writeln!(output.text, "{}", output.paint(&row, result)).unwrap();
            } else {
                output.paragraph(
                    &format!(
                        "{} · {result} · {rating} · {} matches",
                        check.cve_id, check.matches
                    ),
                    "  ",
                );
            }
            if !matches!(check.status.as_str(), "matches" | "no_match") && !check.note.is_empty() {
                output.paragraph(&check.note, "    ");
            }
            if let Some(error) = &check.error {
                output.paragraph(error, "    ");
            }
        }
    }
    output.text.push('\n');

    for (index, finding) in report.findings.iter().enumerate() {
        let level = severity(finding.severity);
        output.open(
            &format!("Finding {} · {level} · {}", index + 1, finding.cve_id),
            level,
        );
        output.field("Issue", &finding.name);
        output.field("What", &finding.description);
        let scores = finding
            .cvss
            .iter()
            .map(|score| {
                let source = if score.source.contains("CVEProject") {
                    "CVE record"
                } else if score.source.contains("geoserver/security/advisories") {
                    "GeoServer advisory"
                } else if score.source.contains("nvd.nist.gov") {
                    "NVD"
                } else {
                    "Advisory"
                };
                format!("{:.1} ({source}, v{})", score.score, score.version)
            })
            .collect::<Vec<_>>()
            .join(" · ");
        output.field("CVSS", &scores);
        output.field("Evidence", &finding.evidence);
        output.field("Fix", &finding.remediation);
        output.field("Advisory", &finding.advisory_url);
        output.close();
        writeln!(
            output.text,
            "  {}",
            output.paint("REPRODUCE THIS FINDING", "brand")
        )
        .unwrap();
        output.paragraph(
            "Run these read-only requests without credentials against the same target.",
            "  ",
        );
        for (step_index, step) in finding.reproduction.iter().enumerate() {
            output.text.push('\n');
            output.paragraph(&format!("{}. {}", step_index + 1, step.title), "  ");
            output.text.push('\n');
            for line in step.command.lines() {
                writeln!(output.text, "    {line}").unwrap();
            }
            output.text.push('\n');
            output.paragraph(&format!("Expect: {}", step.expected), "    ");
        }
        output.text.push('\n');
    }
    if report.findings.is_empty() {
        output.paragraph(
            "No findings recorded. This does not establish that the deployment is secure.",
            "  ",
        );
    }
    output.paragraph("Coverage is limited to the checks and layer tested. Matched evidence requires verification.", "  ");
    if matches!(
        report.status.as_str(),
        "partial" | "inconclusive" | "failed"
    ) {
        output.paragraph("Some checks did not complete. Review their messages above and scan_checks.details_json.", "  ");
    }
    output.text
}

pub fn print(report: &ScanReport, db: &Path, json: bool) -> Result<(), String> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(report).map_err(|error| error.to_string())?
        );
    } else {
        let term = Term::stdout();
        let width = term
            .size_checked()
            .map_or(88, |(_, width)| usize::from(width));
        let color = std::io::stdout().is_terminal()
            && std::env::var_os("NO_COLOR").is_none()
            && console::colors_enabled();
        print!("{}", render(report, db, width, color));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use geoscan_core::scan::CheckResult;

    #[test]
    fn narrow_reports_keep_unicode_alignment_and_incomplete_results_visible() {
        let report = ScanReport {
            id: 1,
            target: "http://localhost/maps/".into(),
            geoserver_version: None,
            version_note: "Authentication required".into(),
            status: "inconclusive".into(),
            reported_events: 0,
            not_run: 31,
            findings: vec![],
            checks: vec![CheckResult {
                cve_id: "CVE-2026-76904".into(),
                status: "inconclusive".into(),
                ran: true,
                reported_events: 0,
                matches: 0,
                note: "图层 café · requires access\u{1b}[2J".into(),
                diagnostics: String::new(),
                error: None,
            }],
        };
        for width in [48, 76, 104] {
            let text = render(&report, Path::new("scan.db"), width, false);
            assert!(!text.contains('\u{1b}'));
            assert!(text.contains("INCONCLUSIVE"));
            assert!(text.contains("Some checks did not complete"));
            for line in text.lines() {
                assert!(
                    measure_text_width(line) <= width,
                    "line exceeds {width}: {line}"
                );
                if line.starts_with(['╭', '│', '╰']) {
                    assert_eq!(measure_text_width(line), width, "unaligned border: {line}");
                }
            }
        }
    }
}

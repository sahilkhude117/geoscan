/** Wire contracts for /api/v1. Field names match Rust's JSON exactly. */
export type Severity = "critical" | "high" | "medium" | "low";
export type ScanStatus =
  | "running"
  | "matches"
  | "no_match"
  | "partial"
  | "failed"
  | "inconclusive"
  | "not_applicable";
export type JobState = "queued" | "running" | "completed" | "failed" | "interrupted";
export type CheckKind = "cve" | "misconfiguration";
export type Deployment = "unspecified" | "lab" | "production";

export interface MisconfigurationOptions {
  only_misconfigurations?: boolean;
  private_layers?: string[];
  deployment?: Deployment;
}

export interface ScanInput {
  target: string;
  username?: string;
  password?: string;
  sqli_layer?: string;
  sqli_property?: string;
  misconfigurations?: MisconfigurationOptions;
}

export interface Job {
  id: number;
  state: JobState;
  target: string;
  sqli_layer: string;
  sqli_property: string;
  misconfigurations: MisconfigurationOptions;
  scan_id: number | null;
  outcome: ScanStatus | null;
  error: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface CvssRating {
  score: number;
  severity: Severity;
  version: string;
  vector: string | null;
  source: string;
}

export interface ReproductionStep {
  title: string;
  command: string;
  expected: string;
}

export interface Finding {
  check_id: string;
  kind: CheckKind;
  cve_id: string | null;
  name: string;
  severity: Severity;
  matched_at: string;
  description: string;
  cvss: CvssRating[];
  remediation: string;
  advisory_url: string;
  evidence: string;
  reproduction: ReproductionStep[];
}

export interface CheckResult {
  check_id: string;
  kind: CheckKind;
  cve_id: string | null;
  severity: Severity | null;
  status: ScanStatus;
  ran: boolean;
  reported_events: number;
  matches: number;
  note: string;
  diagnostics: string;
  error: string | null;
}

export interface ScanReport {
  id: number;
  target: string;
  geoserver_version: string | null;
  version_note: string;
  status: ScanStatus;
  reported_events: number;
  not_run: number;
  checks: CheckResult[];
  findings: Finding[];
}

export interface ScanSummary {
  id: number;
  target: string;
  geoserver_version: string | null;
  status: ScanStatus;
  /** Legacy SQLite timestamps are UTC without a timezone suffix. */
  started_at: string;
  finished_at: string | null;
  finding_count: number;
}

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface Health {
  status: "ok";
  api_version: "v1";
  scanner: { available: boolean; version: string | null; error: string | null };
  allowed_targets: string[];
  supported_checks: string[];
  supported_misconfiguration_checks: string[];
  catalog_entries: number;
  max_active_scans: number;
  scan_timeout_seconds: number;
  defaults: { sqli_layer: string; sqli_property: string };
}

export interface Detection {
  target: string;
  reachable: boolean;
  likely_geoserver: boolean;
  evidence: string[];
  version: string | null;
  version_note: string;
  wms: string;
  wfs: string;
}

export interface CveCheck {
  id: string;
  name: string;
  vulnerability_type: string;
  description: string;
  component: string;
  authentication: string;
  severity: Severity;
  cvss: CvssRating[];
  dates: { kind: "cve_publication" | "nvd_publication" | "advisory_publication" | "cve_modified"; date: string; source: string }[];
  cwes: string[];
  kev: { date_added: string; source: string } | null;
  affected: string[];
  fixed_versions: string[];
  version_scope: "geo_server" | "geo_web_cache" | "uncertain";
  version_notes: string;
  prerequisites: string[];
  remediation: string;
  advisory_url: string;
  references: string[];
  template: string | null;
  probe_policy: "read_only" | "lab_only" | "unreviewed";
  template_notes: string;
  researched_at: string;
  reported_metadata: { cvss_score: number; severity: Severity; published: string; publication_note: string | null } | null;
}

export interface Catalog {
  items: CveCheck[];
  supported_checks: string[];
  misconfigurations: MisconfigurationDefinition[];
}

export interface MisconfigurationDefinition {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  remediation: string;
  reference_url: string;
  activation: "always" | "private_layers" | "production";
}

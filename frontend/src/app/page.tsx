"use client";

import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { useScan } from "@/hooks/use-scan";
import { api } from "@/lib/api";
import type { Health, ScanReport, ScanSummary } from "@/lib/api-types";

/** Working integration starter. The frontend teammate can replace its layout. */
export default function Home() {
  const scan = useScan();
  const [health, setHealth] = useState<Health | null>(null);
  const [connectionError, setConnectionError] = useState<string | null>(null);
  const [target, setTarget] = useState("http://127.0.0.1:8080/geoserver");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [history, setHistory] = useState<ScanSummary[]>([]);
  const [savedReport, setSavedReport] = useState<ScanReport | null>(null);

  useEffect(() => {
    const active = new AbortController();
    Promise.all([api.health(active.signal), api.scans(25, 0, active.signal)])
      .then(([status, scans]) => { setHealth(status); setHistory(scans.items); })
      .catch((error) => { if (!active.signal.aborted) setConnectionError(error.message); });
    return () => active.abort();
  }, []);

  useEffect(() => {
    if (!scan.report) return;
    const active = new AbortController();
    api.scans(25, 0, active.signal)
      .then((page) => setHistory(page.items))
      .catch((error) => { if (!active.signal.aborted) setConnectionError(error.message); });
    return () => active.abort();
  }, [scan.report]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSavedReport(null);
    const input = {
      target,
      ...(username.trim() ? { username: username.trim(), password } : {}),
      ...(health?.defaults ?? {}),
    };
    setPassword("");
    await scan.start(input);
  }

  async function openReport(id: number) {
    try { setSavedReport(await api.report(id)); }
    catch (error) { setConnectionError(error instanceof Error ? error.message : "Could not load report"); }
  }

  const report = savedReport ?? scan.report;
  const field = "w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 text-zinc-950";

  return (
    <main className="mx-auto w-full max-w-4xl space-y-8 p-6 sm:p-10">
      <header className="space-y-2">
        <p className="text-sm font-semibold text-teal-700">GEOSCAN</p>
        <h1 className="text-3xl font-semibold">GeoServer security scans</h1>
        <p className="text-zinc-500">{health ? `${health.supported_checks.length} supported checks · ${health.catalog_entries} researched CVEs` : "Connecting to the scanner…"}</p>
      </header>
      {connectionError && <p role="alert" className="rounded-lg border border-red-300 p-4">{connectionError}</p>}
      {health && !health.scanner.available && <p role="alert">Scanner unavailable. Start or configure the scanner engine in the backend, then restart the API.</p>}

      <form onSubmit={submit} className="space-y-4 rounded-xl border border-zinc-300 p-6">
        <label className="block space-y-1">
          <span>GeoServer URL</span>
          <input className={field} type="url" value={target} onChange={(event) => setTarget(event.target.value)} required disabled={scan.busy} list="allowed-targets" />
          <datalist id="allowed-targets">{health?.allowed_targets.map((url) => <option key={url} value={url} />)}</datalist>
        </label>
        <div className="grid gap-4 sm:grid-cols-2">
          <label className="block space-y-1"><span>Username (optional)</span><input className={field} value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" disabled={scan.busy} /></label>
          <label className="block space-y-1"><span>Password</span><input className={field} type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" required={Boolean(username.trim())} disabled={scan.busy} /></label>
        </div>
        <p className="text-sm text-zinc-500">Login helps identify the version. Exposure checks use anonymous requests.</p>
        <button className="rounded-lg bg-teal-700 px-5 py-2 font-medium text-white disabled:opacity-50" disabled={scan.busy || !health?.scanner.available}>{scan.busy ? "Scanning…" : "Start scan"}</button>
        {scan.job && <p role="status">Job #{scan.job.id}: {scan.job.state}{scan.job.outcome ? ` · ${scan.job.outcome}` : ""}</p>}
        {scan.error && <p role="alert">{scan.error}</p>}
        {!scan.busy && scan.job && !["completed", "failed", "interrupted"].includes(scan.job.state) && <button type="button" className="underline" onClick={() => scan.resume(scan.job!.id)}>Resume waiting for job #{scan.job.id}</button>}
      </form>

      {report && <section className="space-y-4" aria-label="Scan report">
        <h2 className="text-xl font-semibold">Scan #{report.id} · {report.status}</h2>
        <p>{report.target} · Version {report.geoserver_version ?? "unknown"}</p>
        <p>{report.findings.length} findings · {report.not_run} catalogue entries not run</p>
        <ul className="space-y-2">{report.checks.map((check) => <li key={check.cve_id} className="rounded-lg border border-zinc-300 p-3">{check.cve_id}: {check.status}<p className="text-sm text-zinc-500">{check.error ?? check.note}</p></li>)}</ul>
        {report.findings.map((finding, index) => <article key={`${finding.cve_id}-${index}`} className="space-y-3 rounded-xl border border-red-300 p-5">
          <p className="font-semibold">{finding.severity.toUpperCase()} · {finding.cve_id} · CVSS {finding.cvss[0]?.score ?? "unknown"}</p>
          <h3>{finding.name}</h3><p>{finding.evidence}</p><p>{finding.remediation}</p>
          {finding.reproduction.map((step, stepIndex) => <div key={stepIndex} className="space-y-2"><p>{stepIndex + 1}. {step.title}</p><pre className="overflow-x-auto rounded-lg bg-zinc-900 p-4 text-xs text-zinc-100">{step.command}</pre><p className="text-sm">Expected: {step.expected}</p></div>)}
          <a href={finding.advisory_url} target="_blank" rel="noopener noreferrer" className="underline">Vendor advisory</a>
        </article>)}
        <p className="text-sm text-zinc-500">Results cover the checks run. Matches require verification.</p>
      </section>}

      <section className="space-y-3" aria-label="Saved scans">
        <h2 className="text-xl font-semibold">Saved scans</h2>
        {history.length === 0 ? <p>No saved scans yet.</p> : <ul className="space-y-2">{history.map((entry) => <li key={entry.id}><button type="button" className="text-left underline" onClick={() => openReport(entry.id)}>#{entry.id} · {entry.status} · {entry.finding_count} findings · {entry.target}</button></li>)}</ul>}
      </section>
    </main>
  );
}

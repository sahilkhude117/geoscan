"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { api, waitForJob } from "@/lib/api";
import type { Job, ScanInput, ScanReport } from "@/lib/api-types";

/** Owns browser polling only. Unmounting does not cancel a backend scan. */
export function useScan() {
  const [job, setJob] = useState<Job | null>(null);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const controller = useRef<AbortController | null>(null);
  useEffect(() => () => controller.current?.abort(), []);

  const follow = useCallback(async (id: number, signal: AbortSignal) => {
    const finished = await waitForJob(id, { signal, onUpdate: setJob });
    if (finished.state !== "completed" || finished.scan_id === null) {
      throw new Error(finished.error ?? "The scan did not finish. Submit a new scan when ready.");
    }
    setReport(await api.report(finished.scan_id, signal));
  }, []);

  const execute = useCallback(async (input: ScanInput | number) => {
    if (controller.current) return;
    const active = new AbortController();
    controller.current = active;
    setBusy(true);
    setError(null);
    setReport(null);
    if (typeof input !== "number") setJob(null);
    try {
      const id = typeof input === "number" ? input : (await api.startScan(input, active.signal)).id;
      await follow(id, active.signal);
    } catch (error) {
      if (!active.signal.aborted) setError(error instanceof Error ? error.message : "Could not finish this scan");
    } finally {
      if (!active.signal.aborted) setBusy(false);
      controller.current = null;
    }
  }, [follow]);

  return {
    job, report, error, busy,
    start: (input: ScanInput) => execute(input),
    resume: (id: number) => execute(id),
  };
}

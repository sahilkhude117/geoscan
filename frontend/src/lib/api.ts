import type { Catalog, Detection, Health, Job, Page, ScanInput, ScanReport, ScanSummary } from "./api-types";

/** Errors always expose an HTTP status and stable code to the UI. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  let response: Response;
  try {
    const deadline = AbortSignal.timeout(60_000);
    response = await fetch(`/api/v1${path}`, {
      ...options,
      cache: "no-store",
      signal: options.signal ? AbortSignal.any([options.signal, deadline]) : deadline,
      headers: { Accept: "application/json", ...options.headers },
    });
  } catch (error) {
    if (options.signal?.aborted) throw error;
    throw new ApiError(0, "api_unreachable", "Could not reach the GeoScan API. Check that the backend is running.");
  }
  const data: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const envelope = data as { error?: { code?: string; message?: string } } | null;
    throw new ApiError(response.status, envelope?.error?.code ?? "api_error", envelope?.error?.message ?? `API request failed (HTTP ${response.status}).`);
  }
  if (data === null) throw new ApiError(response.status, "invalid_response", "The API returned an unreadable response.");
  return data as T;
}

function positiveId(id: number): number {
  if (!Number.isSafeInteger(id) || id < 1) throw new Error("ID must be a positive integer");
  return id;
}

function pageQuery(limit: number, offset: number): string {
  if (!Number.isInteger(limit) || limit < 1 || limit > 100 || !Number.isSafeInteger(offset) || offset < 0) {
    throw new Error("limit must be 1–100 and offset must be nonnegative");
  }
  return `?limit=${limit}&offset=${offset}`;
}

function post<T>(path: string, input: ScanInput, signal?: AbortSignal): Promise<T> {
  return request<T>(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(input), signal });
}

export const api = {
  health: (signal?: AbortSignal) => request<Health>("/health", { signal }),
  checks: (signal?: AbortSignal) => request<Catalog>("/checks", { signal }),
  detect: (input: ScanInput, signal?: AbortSignal) => post<Detection>("/detect", input, signal),
  startScan: (input: ScanInput, signal?: AbortSignal) => post<Job>("/scans", input, signal),
  job: (id: number, signal?: AbortSignal) => request<Job>(`/jobs/${positiveId(id)}`, { signal }),
  jobs: (limit = 25, offset = 0, signal?: AbortSignal) => request<Page<Job>>(`/jobs${pageQuery(limit, offset)}`, { signal }),
  scans: (limit = 25, offset = 0, signal?: AbortSignal) => request<Page<ScanSummary>>(`/scans${pageQuery(limit, offset)}`, { signal }),
  report: (id: number, signal?: AbortSignal) => request<ScanReport>(`/scans/${positiveId(id)}`, { signal }),
};

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    signal?.throwIfAborted();
    const abort = () => { clearTimeout(timer); reject(signal?.reason); };
    const timer = setTimeout(() => { signal?.removeEventListener("abort", abort); resolve(); }, ms);
    signal?.addEventListener("abort", abort, { once: true });
  });
}

/** Stop polling at every terminal state, including completed/partial reports. */
export async function waitForJob(
  id: number,
  options: { signal?: AbortSignal; onUpdate?: (job: Job) => void; intervalMs?: number; timeoutMs?: number } = {},
): Promise<Job> {
  const deadline = Date.now() + (options.timeoutMs ?? 300_000);
  while (Date.now() < deadline) {
    const job = await api.job(id, options.signal);
    options.onUpdate?.(job);
    if (["completed", "failed", "interrupted"].includes(job.state)) return job;
    await sleep(options.intervalMs ?? 1500, options.signal);
  }
  throw new ApiError(0, "poll_timeout", "Stopped waiting for this job. Resume polling its ID; the backend may still be scanning.");
}

import { test } from "node:test";
import assert from "node:assert/strict";
import { api, ApiError, waitForJob } from "../src/lib/api.ts";

const realFetch = globalThis.fetch;

test("submits JSON once and preserves optional layer selection", async () => {
  let calls = 0;
  globalThis.fetch = async (url, options) => {
    calls++;
    assert.equal(url, "/api/v1/scans");
    assert.equal(options?.method, "POST");
    assert.equal(options?.cache, "no-store");
    assert.deepEqual(JSON.parse(options?.body as string), { target: "http://127.0.0.1:8080/geoserver", sqli_layer: "demo:items", sqli_property: "payload" });
    return Response.json({ id: 12, state: "queued" }, { status: 202 });
  };
  try { assert.equal((await api.startScan({ target: "http://127.0.0.1:8080/geoserver", sqli_layer: "demo:items", sqli_property: "payload" })).id, 12); assert.equal(calls, 1); }
  finally { globalThis.fetch = realFetch; }
});

test("keeps backend error status and code and handles a non-JSON proxy error", async () => {
  globalThis.fetch = async () => Response.json({ error: { code: "scanner_busy", message: "A scan is already running" } }, { status: 409 });
  try {
    await assert.rejects(api.startScan({ target: "http://localhost" }), (error) => error instanceof ApiError && error.status === 409 && error.code === "scanner_busy");
    globalThis.fetch = async () => new Response("Bad gateway", { status: 502 });
    await assert.rejects(api.health(), (error) => error instanceof ApiError && error.status === 502 && error.code === "api_error");
  } finally { globalThis.fetch = realFetch; }
});

test("polling stops for a completed partial report and never resubmits", async () => {
  let calls = 0;
  globalThis.fetch = async (url, options) => {
    assert.equal(url, "/api/v1/jobs/8");
    assert.notEqual(options?.method, "POST");
    return Response.json(calls++ === 0 ? { id: 8, state: "running" } : { id: 8, state: "completed", outcome: "partial", scan_id: 19 });
  };
  try { const job = await waitForJob(8, { intervalMs: 0 }); assert.equal(job.scan_id, 19); assert.equal(calls, 2); }
  finally { globalThis.fetch = realFetch; }
});

test("failed and interrupted jobs stop polling; abort does not start another scan", async () => {
  try {
    for (const state of ["failed", "interrupted"]) {
      let calls = 0;
      globalThis.fetch = async () => { calls++; return Response.json({ id: 1, state }); };
      assert.equal((await waitForJob(1)).state, state); assert.equal(calls, 1);
    }
    const controller = new AbortController();
    globalThis.fetch = async () => { controller.abort(); return Response.json({ id: 1, state: "running" }); };
    await assert.rejects(waitForJob(1, { signal: controller.signal }));
  } finally { globalThis.fetch = realFetch; }
});

test("pagination and IDs cannot inject a different API path", () => {
  assert.throws(() => api.report(-1), /positive integer/);
  assert.throws(() => api.jobs(101), /limit/);
});

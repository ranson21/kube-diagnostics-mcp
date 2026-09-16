import { describe, expect, it, vi } from "vitest";
import { DatadogProvider, getPath } from "../src/providers/datadog/index.js";
import { SplunkProvider, splQuote } from "../src/providers/splunk/index.js";
import { loadConfig } from "../src/config.js";
import type { DatadogConfig, SplunkConfig } from "../src/config.js";

type Call = { url: string; init: RequestInit };

/** A fetch double that records calls and answers from a routing table. */
function fakeFetch(routes: Array<{ match: (c: Call) => boolean; status?: number; body: unknown }>) {
  const calls: Call[] = [];
  const f = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const c = { url: String(input), init: init ?? {} };
    calls.push(c);
    const r = routes.find((x) => x.match(c));
    const body = r ? JSON.stringify(r.body) : JSON.stringify({ errors: ["no route"] });
    return new Response(body, { status: r ? (r.status ?? 200) : 404, headers: { "content-type": "application/json" } });
  });
  return { fetch: f as unknown as typeof fetch, calls };
}

const dd: DatadogConfig = { site: "datadoghq.eu", apiKey: "FAKE_API_KEY", appKey: "FAKE_APP_KEY", scope: "env:prod", apmOperation: "servlet.request", serviceTag: "service", namespaceTag: "kube_namespace", logIndexes: [], timeoutMs: 5000 };
const ctx = { namespace: "shop", service: "checkout", pods: ["checkout-abc", "checkout-def"], windowSeconds: 900 };

const series = (pts: Array<[number, number | null]>, tags?: string[]) => ({ series: [{ metric: "m", scope: (tags ?? []).join(","), tag_set: tags, pointlist: pts }] });

describe("DatadogProvider", () => {
  it("golden signals: hits/errors/percentiles/per-resource, with scope and auth headers, and never leaks keys", async () => {
    const q = (c: Call) => new URL(c.url).searchParams.get("query") ?? "";
    const { fetch, calls } = fakeFetch([
      { match: (c) => q(c).startsWith("sum:trace.servlet.request.hits{service:checkout,env:prod}.as_count()"), body: series([[1, 300], [2, 600]]) },
      { match: (c) => q(c).startsWith("sum:trace.servlet.request.errors{service:checkout,env:prod}.as_count()"), body: series([[1, 9]]) },
      { match: (c) => q(c).includes("hits.by_http_status"), body: series([[1, 4]]) },
      { match: (c) => q(c).startsWith("p50:"), body: series([[1, 0.05], [2, 0.07]]) },
      { match: (c) => q(c).startsWith("p95:"), body: series([[1, 0.4]]) },
      { match: (c) => q(c).startsWith("p99:"), body: series([[1, 1.2]]) },
      { match: (c) => q(c).includes("hits{service:checkout,env:prod} by {resource_name}"), body: { series: [{ pointlist: [[1, 800]], tag_set: ["resource_name:POST /checkout"] }, { pointlist: [[1, 100]], tag_set: ["resource_name:GET /cart"] }] } },
      { match: (c) => q(c).includes("errors{service:checkout,env:prod} by {resource_name}"), body: { series: [{ pointlist: [[1, 8]], tag_set: ["resource_name:POST /checkout"] }] } },
    ]);
    const p = new DatadogProvider(dd, fetch);
    const g = await p.goldenSignals(ctx);
    expect(g?.requestRate).toBeCloseTo(1);
    expect(g?.errorRate).toBeCloseTo(0.01);
    expect(g?.errorRate5xx).toBeCloseTo(4 / 900);
    expect(g?.latencyMs).toEqual({ p50: 60, p95: 400, p99: 1200 });
    expect(g?.byEndpoint?.[0]).toEqual({ endpoint: "/checkout", method: "POST", requestRate: 800 / 900, errorRate: 0.01 });
    expect(g?.source).toBe("datadog:trace.servlet.request");
    const headers = calls[0].init.headers as Record<string, string>;
    expect(headers["DD-API-KEY"]).toBe("FAKE_API_KEY");
    expect(headers["DD-APPLICATION-KEY"]).toBe("FAKE_APP_KEY");
    expect(calls[0].url.startsWith("https://api.datadoghq.eu/api/v1/query?")).toBe(true);
    expect(JSON.stringify(g)).not.toContain("FAKE_");
  });

  it("returns undefined (not zeros) when there are no hits", async () => {
    const { fetch } = fakeFetch([{ match: () => true, body: { series: [] } }]);
    expect(await new DatadogProvider(dd, fetch).goldenSignals(ctx)).toBeUndefined();
  });

  it("resource usage converts nanocores and maps pod/container tags", async () => {
    const q = (c: Call) => new URL(c.url).searchParams.get("query") ?? "";
    const { fetch, calls } = fakeFetch([
      { match: (c) => q(c).startsWith("avg:kubernetes.cpu.usage.total"), body: { series: [{ pointlist: [[1, 250e6], [2, 350e6]], tag_set: ["pod_name:checkout-abc", "kube_container_name:app"] }] } },
      { match: (c) => q(c).startsWith("avg:kubernetes.memory.working_set"), body: { series: [{ pointlist: [[1, 100e6], [2, 120e6]], tag_set: ["pod_name:checkout-abc", "kube_container_name:app"] }] } },
      { match: (c) => q(c).includes("throttled"), body: { series: [{ pointlist: [[1, 0.5], [2, 0.3]], tag_set: ["pod_name:checkout-abc", "kube_container_name:app"] }] } },
    ]);
    const u = await new DatadogProvider(dd, fetch).resourceUsage(ctx);
    expect(u).toEqual([{ pod: "checkout-abc", container: "app", cpuMillicores: 350, memoryBytes: 120e6, cpuThrottledRatio: 0.4, source: "datadog:kubernetes.*" }]);
    expect(q(calls[0])).toContain("kube_namespace:shop,pod_name IN (checkout-abc,checkout-def),env:prod");
  });

  it("slow traces: dedupes by trace, sorts by @duration (ns), builds the spans search envelope", async () => {
    const { fetch, calls } = fakeFetch([
      {
        match: (c) => c.url.endsWith("/api/v2/spans/events/search"),
        body: {
          data: [
            { attributes: { trace_id: "t1", span_id: "a", service: "checkout", resource_name: "POST /checkout", start_timestamp: "2026-09-16T10:00:00Z", attributes: { duration: 2_500_000_000 }, tags: ["error:1"] } },
            { attributes: { trace_id: "t1", span_id: "b", service: "checkout", resource_name: "db.query", attributes: { duration: 900_000_000 } } },
            { attributes: { trace_id: "t2", span_id: "c", service: "checkout", resource_name: "GET /cart", attributes: { duration: 1_100_000_000 } } },
          ],
        },
      },
    ]);
    const p = new DatadogProvider(dd, fetch);
    const t = await p.slowTraces(ctx, 1000, 10);
    expect(t?.map((x) => [x.traceId, x.durationMs, x.error])).toEqual([["t1", 2500, true], ["t2", 1100, false]]);
    const body = JSON.parse(String(calls[0].init.body));
    expect(body.data.type).toBe("search_request");
    expect(body.data.attributes.filter.query).toBe("service:checkout env:prod @_top_level:1 @duration:>=1000000000");
    expect(body.data.attributes.filter.from).toBe("now-900s");
    expect(body.data.attributes.sort).toBe("-timestamp");
  });

  it("trace: critical path with self time and depth", async () => {
    const { fetch } = fakeFetch([
      {
        match: (c) => c.url.endsWith("/api/v2/spans/events/search"),
        body: {
          data: [
            { attributes: { trace_id: "t1", span_id: "root", service: "checkout", resource_name: "POST /checkout", start_timestamp: "2026-09-16T10:00:00.000Z", end_timestamp: "2026-09-16T10:00:03.000Z" } },
            { attributes: { trace_id: "t1", span_id: "db", parent_id: "root", service: "postgres", resource_name: "SELECT pg_sleep", start_timestamp: "2026-09-16T10:00:00.100Z", end_timestamp: "2026-09-16T10:00:02.600Z" } },
            { attributes: { trace_id: "t1", span_id: "tiny", parent_id: "root", service: "checkout", resource_name: "serialize", start_timestamp: "2026-09-16T10:00:02.900Z", end_timestamp: "2026-09-16T10:00:02.910Z" } },
          ],
        },
      },
    ]);
    const t = await new DatadogProvider(dd, fetch).trace("t1");
    expect(t?.durationMs).toBe(3000);
    expect(t?.spans.map((s) => [s.operation, s.durationMs, s.selfMs, s.depth])).toEqual([["POST /checkout", 3000, 490, 0], ["SELECT pg_sleep", 2500, 2500, 1]]);
    expect(t?.services).toEqual(["checkout", "postgres"]);
  });

  it("log search builds the scoped query and formats lines", async () => {
    const { fetch, calls } = fakeFetch([
      { match: (c) => c.url.endsWith("/api/v2/logs/events/search"), body: { data: [{ attributes: { timestamp: "2026-09-16T10:00:00Z", status: "error", message: "Connection is not available" } }], meta: { page: { after: "x" } } } },
    ]);
    const r = await new DatadogProvider({ ...dd, logIndexes: ["main"] }, fetch).logSearch(ctx, "Hikari", 50);
    expect(r?.lines).toEqual(["2026-09-16T10:00:00Z [error] Connection is not available"]);
    expect(r?.truncated).toBe(true);
    const body = JSON.parse(String(calls[0].init.body));
    expect(body.filter.query).toBe("kube_namespace:shop service:checkout env:prod Hikari");
    expect(body.filter.indexes).toEqual(["main"]);
  });

  it("web vitals: converts ns to ms, groups by url_path_group, computes p75", async () => {
    const view = (route: string, lcp: number, cls: number, sid: string) => ({ attributes: { attributes: { view: { url_path_group: route, largest_contentful_paint: lcp * 1e6, first_contentful_paint: 800e6, cumulative_layout_shift: cls, first_byte: 70e6 }, session: { id: sid }, device: { type: "desktop" } } } });
    const { fetch, calls } = fakeFetch([
      { match: (c) => c.url.endsWith("/api/v2/rum/events/search") && String(c.init.body).includes("@type:view"), body: { data: [view("/products/?", 4200, 0.3, "s1"), view("/products/?", 4600, 0.32, "s2"), view("/", 900, 0.01, "s1")] } },
      { match: (c) => c.url.endsWith("/api/v2/rum/events/search") && String(c.init.body).includes("@type:error"), body: { data: [{ attributes: { timestamp: "2026-09-16T10:00:00Z", attributes: { error: { message: "Cannot read properties of undefined" }, view: { url_path_group: "/admin" } } } }] } },
    ]);
    const s = await new DatadogProvider({ ...dd, rumApplication: "storefront" }, fetch).webVitals(ctx);
    expect(s?.vitals["/products/?"].LCP.count).toBe(2);
    expect(s?.vitals["/products/?"].LCP.p75).toBe(4600);
    expect(s?.vitals["/products/?"].CLS.p75).toBe(0.32);
    expect(s?.vitals["/"].TTFB.p50).toBe(70);
    expect(s?.sessions).toBe(2);
    expect(s?.errors[0].routes).toEqual(["/admin"]);
    expect(JSON.parse(String(calls[0].init.body)).filter.query).toContain('@application.name:"storefront"');
  });

  it("surfaces API errors without the keys", async () => {
    const { fetch } = fakeFetch([{ match: () => true, status: 403, body: { errors: ["Forbidden"] } }]);
    await expect(new DatadogProvider(dd, fetch).logSearch(ctx, "", 10)).rejects.toThrow(/HTTP 403 - Forbidden/);
    const st = await new DatadogProvider(dd, fetch).status();
    expect(st.reachable).toBe(false);
    expect(JSON.stringify(st)).not.toContain("FAKE_");
  });

  it("getPath handles nested and dotted keys", () => {
    expect(getPath({ view: { url_path: "/x" } }, "view.url_path")).toBe("/x");
    expect(getPath({ "view.url_path": "/y" }, "view.url_path")).toBe("/y");
  });
});

const sp: SplunkConfig = { url: "https://splunk.internal:8089", token: "FAKE_SPLUNK_TOKEN", authScheme: "Bearer", index: "k8s", namespaceField: "namespace", serviceField: "container_name", requestLogSearch: 'sourcetype="nginx:json"', requestFields: { status: "status", durationSeconds: "request_time", path: "uri", method: "request_method" }, verifyTls: true, timeoutMs: 5000 };

describe("SplunkProvider", () => {
  it("log search: oneshot form body, scoped SPL, bearer auth", async () => {
    const { fetch, calls } = fakeFetch([{ match: (c) => c.url.endsWith("/services/search/jobs"), body: { results: [{ _time: "2026-09-16T10:00:00.000+00:00", _raw: '{"level":"ERROR","message":"pool exhausted"}' }] } }]);
    const r = await new SplunkProvider(sp, fetch).logSearch(ctx, "exhausted", 100);
    expect(r?.lines[0]).toContain("pool exhausted");
    const body = calls[0].init.body as URLSearchParams;
    expect(body.get("exec_mode")).toBe("oneshot");
    expect(body.get("output_mode")).toBe("json");
    expect(body.get("earliest_time")).toBe("-900s");
    expect(body.get("search")).toBe('search index="k8s" namespace="shop" (container_name="checkout" OR container_name="checkout*") exhausted | head 100');
    expect((calls[0].init.headers as Record<string, string>).authorization).toBe("Bearer FAKE_SPLUNK_TOKEN");
  });

  it("golden signals from request logs via stats", async () => {
    const { fetch, calls } = fakeFetch([
      { match: (c) => String((c.init.body as URLSearchParams).get("search")).includes("by request_method, uri"), body: { results: [{ request_method: "POST", uri: "/api/checkout", hits: "40", err5: "12", p95: "2.001" }] } },
      { match: (c) => c.url.endsWith("/services/search/jobs"), body: { results: [{ hits: "900", err5: "39", err: "49", p50: "0.05", p95: "0.8", p99: "2.0" }] } },
    ]);
    const g = await new SplunkProvider(sp, fetch).goldenSignals(ctx);
    expect(g?.requestRate).toBe(1);
    expect(g?.errorRate5xx).toBeCloseTo(39 / 900);
    expect(g?.latencyMs).toEqual({ p50: 50, p95: 800, p99: 2000 });
    expect(g?.byEndpoint?.[0]).toEqual({ endpoint: "/api/checkout", method: "POST", requestRate: 40 / 900, errorRate: 0.3, p95Ms: 2001 });
    expect(String((calls[0].init.body as URLSearchParams).get("search"))).toContain('sourcetype="nginx:json" namespace="shop" | stats count as hits');
  });

  it("without a request-log search it only claims logSearch", () => {
    expect(new SplunkProvider({ ...sp, requestLogSearch: undefined }, fakeFetch([]).fetch).capabilities).toEqual(["logSearch"]);
  });

  it("fails loudly on FATAL search messages and HTTP errors, without the token", async () => {
    const { fetch } = fakeFetch([{ match: () => true, body: { messages: [{ type: "FATAL", text: "Unknown search command 'stat'." }] } }]);
    await expect(new SplunkProvider(sp, fetch).logSearch(ctx, "", 10)).rejects.toThrow(/Unknown search command/);
    const bad = fakeFetch([{ match: () => true, status: 401, body: { messages: [{ type: "WARN", text: "call not properly authenticated" }] } }]);
    const err = await new SplunkProvider(sp, bad.fetch).logSearch(ctx, "", 10).catch((e: Error) => e.message);
    expect(err).toMatch(/HTTP 401/);
    expect(err).not.toContain("FAKE_SPLUNK_TOKEN");
  });

  it("splQuote escapes", () => {
    expect(splQuote('a"b\\c')).toBe('"a\\"b\\\\c"');
  });
});

describe("provider config", () => {
  it("parses datadog and splunk knobs with defaults", () => {
    const c = loadConfig({ DIAG_DATADOG_API_KEY: "a", DIAG_DATADOG_APP_KEY: "b", DIAG_DATADOG_SITE: "us5.datadoghq.com", DIAG_DATADOG_SCOPE: "env:prod", DIAG_SPLUNK_URL: "https://s:8089/", DIAG_SPLUNK_TOKEN: "t", DIAG_SPLUNK_REQUEST_LOG_SEARCH: 'sourcetype="nginx:json"' });
    if (c.mode !== "hub") throw new Error("hub expected");
    expect(c.providers.datadog?.site).toBe("us5.datadoghq.com");
    expect(c.providers.datadog?.apmOperation).toBe("servlet.request");
    expect(c.providers.datadog?.scope).toBe("env:prod");
    expect(c.providers.splunk?.url).toBe("https://s:8089");
    expect(c.providers.splunk?.authScheme).toBe("Bearer");
    expect(c.providers.splunk?.namespaceField).toBe("namespace");
    expect(c.providers.splunk?.requestLogSearch).toBe('sourcetype="nginx:json"');
  });
});

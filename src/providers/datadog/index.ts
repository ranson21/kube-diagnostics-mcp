/**
 * Datadog provider.
 *
 * Uses Datadog's public REST API directly (never the model): metrics query v1
 * for golden signals and Kubernetes resource usage, spans search v2 for slow
 * traces and a trace's critical path, logs search v2 for log search, RUM
 * events search v2 for web vitals. Keys live in the hub only.
 *
 * Enable with DIAG_DATADOG_API_KEY + DIAG_DATADOG_APP_KEY (+ DIAG_DATADOG_SITE,
 * DIAG_DATADOG_SCOPE=env:prod, DIAG_DATADOG_APM_OPERATION=servlet.request ...).
 *
 * Built against the documented request/response shapes without a live account;
 * the unit tests pin those shapes. If your tracer names spans differently
 * (e.g. "http.request" for Node), set DIAG_DATADOG_APM_OPERATION.
 */
import type { DatadogConfig } from "../../config.js";
import type { RumSummary, Percentiles } from "../../probe/protocol.js";
import { percentile } from "../../hub/model.js";
import type { Capability, GoldenSignals, LogSearchResult, ProviderContext, RawMetricResult, ResourceUsageSample, SignalProvider, SlowTrace, TraceCriticalPath } from "../types.js";

interface MetricsQueryResponse {
  status?: string;
  error?: string;
  series?: Array<{ metric?: string; scope?: string; tag_set?: string[]; pointlist?: Array<[number, number | null]> }>;
}

interface SpanEvent {
  id?: string;
  attributes?: {
    trace_id?: string;
    span_id?: string;
    parent_id?: string;
    service?: string;
    resource_name?: string;
    start_timestamp?: string;
    end_timestamp?: string;
    type?: string;
    tags?: string[];
    attributes?: Record<string, unknown>;
    custom?: Record<string, unknown>;
  };
}

interface EventsPage<T> {
  data?: T[];
  meta?: { page?: { after?: string } };
  errors?: Array<{ title?: string; detail?: string }>;
}

interface LogEvent {
  attributes?: { timestamp?: string; message?: string; service?: string; host?: string; status?: string; attributes?: Record<string, unknown> };
}

interface RumEvent {
  attributes?: { timestamp?: string; service?: string; attributes?: Record<string, unknown> };
}

/** Reads "view.largest_contentful_paint" from either nested objects or dotted keys. */
export function getPath(obj: Record<string, unknown> | undefined, path: string): unknown {
  if (!obj) return undefined;
  if (path in obj) return obj[path];
  let cur: unknown = obj;
  for (const part of path.split(".")) {
    if (!cur || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[part];
  }
  return cur;
}

function pcts(values: number[]): Percentiles {
  const sorted = [...values].sort((a, b) => a - b);
  const r = (x: number) => Math.round(x * 1000) / 1000;
  return { count: sorted.length, p50: r(percentile(sorted, 50)), p75: r(percentile(sorted, 75)), p95: r(percentile(sorted, 95)), max: r(sorted[sorted.length - 1] ?? 0) };
}

export class DatadogProvider implements SignalProvider {
  readonly name = "datadog";
  readonly capabilities: Capability[] = ["goldenSignals", "resourceUsage", "slowTraces", "trace", "logSearch", "webVitals", "rawMetricQuery"];
  private readonly base: string;

  constructor(
    private readonly cfg: DatadogConfig,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {
    this.base = `https://api.${cfg.site}`;
  }

  // ---- transport ---------------------------------------------------------

  private async request<T>(method: "GET" | "POST", path: string, body?: unknown, query?: Record<string, string>): Promise<T> {
    const url = new URL(`${this.base}${path}`);
    for (const [k, v] of Object.entries(query ?? {})) url.searchParams.set(k, v);
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), this.cfg.timeoutMs);
    try {
      const r = await this.fetchImpl(url, {
        method,
        headers: { "DD-API-KEY": this.cfg.apiKey, "DD-APPLICATION-KEY": this.cfg.appKey, accept: "application/json", ...(body ? { "content-type": "application/json" } : {}) },
        body: body ? JSON.stringify(body) : undefined,
        signal: ctl.signal,
      });
      const text = await r.text();
      let json: unknown;
      try {
        json = text ? JSON.parse(text) : {};
      } catch {
        throw new Error(`datadog ${path}: HTTP ${r.status}, non-JSON body`);
      }
      if (!r.ok) {
        const errs = (json as { errors?: Array<string | { detail?: string; title?: string }> })?.errors;
        const msg = Array.isArray(errs) ? errs.map((e) => (typeof e === "string" ? e : e.detail ?? e.title ?? "")).join("; ") : "";
        throw new Error(`datadog ${path}: HTTP ${r.status}${msg ? ` - ${msg}` : ""}`);
      }
      return json as T;
    } finally {
      clearTimeout(t);
    }
  }

  private scopeTags(extra: string[]): string {
    const tags = [...extra, ...(this.cfg.scope ? this.cfg.scope.split(",").map((s) => s.trim()).filter(Boolean) : [])];
    return tags.join(",");
  }

  private async series(query: string, from: number, to: number) {
    const r = await this.request<MetricsQueryResponse>("GET", "/api/v1/query", undefined, { from: String(from), to: String(to), query });
    if (r.status && r.status !== "ok") throw new Error(`datadog query failed: ${r.error ?? r.status}`);
    return r.series ?? [];
  }

  /** Sum of all points across all series (for .as_count() queries). */
  private static sum(series: MetricsQueryResponse["series"]): number {
    let s = 0;
    for (const ser of series ?? []) for (const [, v] of ser.pointlist ?? []) if (v !== null && Number.isFinite(v)) s += v;
    return s;
  }

  /** Time-weighted mean of a gauge series (for avg/pXX queries). */
  private static mean(series: MetricsQueryResponse["series"]): number | undefined {
    const vals: number[] = [];
    for (const ser of series ?? []) for (const [, v] of ser.pointlist ?? []) if (v !== null && Number.isFinite(v)) vals.push(v);
    return vals.length ? vals.reduce((a, b) => a + b, 0) / vals.length : undefined;
  }

  private static last(series: MetricsQueryResponse["series"]): number | undefined {
    const ser = series?.[0];
    const pts = (ser?.pointlist ?? []).filter(([, v]) => v !== null);
    return pts.length ? (pts[pts.length - 1][1] as number) : undefined;
  }

  private static tag(ser: { scope?: string; tag_set?: string[] }, key: string): string | undefined {
    const from = ser.tag_set ?? ser.scope?.split(",") ?? [];
    return from.find((t) => t.startsWith(`${key}:`))?.slice(key.length + 1);
  }

  // ---- capabilities ------------------------------------------------------

  async status() {
    try {
      const r = await this.request<{ valid?: boolean }>("GET", "/api/v1/validate");
      return { configured: true, reachable: true, detail: `site=${this.cfg.site} apiKeyValid=${r.valid !== false} apm=trace.${this.cfg.apmOperation}${this.cfg.scope ? ` scope=${this.cfg.scope}` : ""}` };
    } catch (err) {
      return { configured: true, reachable: false, detail: `site=${this.cfg.site}: ${err instanceof Error ? err.message : String(err)}` };
    }
  }

  async goldenSignals(ctx: ProviderContext): Promise<GoldenSignals | undefined> {
    const to = Math.floor(Date.now() / 1000);
    const from = to - ctx.windowSeconds;
    const op = this.cfg.apmOperation;
    const scope = this.scopeTags([`${this.cfg.serviceTag}:${ctx.service}`]);
    const hits = DatadogProvider.sum(await this.series(`sum:trace.${op}.hits{${scope}}.as_count()`, from, to));
    if (!hits) return undefined;
    const errors = DatadogProvider.sum(await this.series(`sum:trace.${op}.errors{${scope}}.as_count()`, from, to));
    const err5 = DatadogProvider.sum(await this.series(`sum:trace.${op}.hits.by_http_status{${scope},http.status_class:5xx}.as_count()`, from, to).catch(() => []));
    // trace.<op> is a DISTRIBUTION metric: percentiles are supported directly.
    const pq = async (p: string) => {
      const v = DatadogProvider.mean(await this.series(`${p}:trace.${op}{${scope}}`, from, to).catch(() => []));
      return v === undefined ? undefined : Math.round(v * 1000);
    };
    const byRes = await this.series(`sum:trace.${op}.hits{${scope}} by {resource_name}.as_count()`, from, to).catch(() => []);
    const byResErr = await this.series(`sum:trace.${op}.errors{${scope}} by {resource_name}.as_count()`, from, to).catch(() => []);
    const errMap = new Map(byResErr.map((s) => [DatadogProvider.tag(s, "resource_name") ?? "", DatadogProvider.sum([s])]));
    const byEndpoint = byRes
      .map((s) => {
        const name = DatadogProvider.tag(s, "resource_name") ?? "?";
        const count = DatadogProvider.sum([s]);
        const [method, ...rest] = name.split(" ");
        return { endpoint: rest.length ? rest.join(" ") : name, method: rest.length ? method : undefined, requestRate: count / ctx.windowSeconds, errorRate: count ? (errMap.get(name) ?? 0) / count : 0 };
      })
      .sort((a, b) => b.requestRate - a.requestRate)
      .slice(0, 25);
    return {
      service: ctx.service,
      namespace: ctx.namespace,
      windowSeconds: ctx.windowSeconds,
      requestRate: hits / ctx.windowSeconds,
      errorRate: hits ? errors / hits : 0,
      errorRate5xx: hits ? err5 / hits : 0,
      latencyMs: { p50: await pq("p50"), p95: await pq("p95"), p99: await pq("p99") },
      byEndpoint,
      source: `datadog:trace.${op}`,
    };
  }

  async resourceUsage(ctx: ProviderContext): Promise<ResourceUsageSample[] | undefined> {
    const to = Math.floor(Date.now() / 1000);
    const from = to - Math.max(ctx.windowSeconds, 300);
    const podFilter = ctx.pods?.length ? `pod_name IN (${ctx.pods.join(",")})` : `pod_name:${ctx.service}*`;
    const scope = this.scopeTags([`${this.cfg.namespaceTag}:${ctx.namespace}`, podFilter]);
    const by = " by {pod_name,kube_container_name}";
    const cpu = await this.series(`avg:kubernetes.cpu.usage.total{${scope}}${by}`, from, to);
    if (!cpu.length) return undefined;
    const mem = await this.series(`avg:kubernetes.memory.working_set{${scope}}${by}`, from, to).catch(() => []);
    const thr = await this.series(`sum:kubernetes.cpu.cfs.throttled.periods{${scope}}${by}.as_count() / sum:kubernetes.cpu.cfs.periods{${scope}}${by}.as_count()`, from, to).catch(() => []);
    const key = (s: { scope?: string; tag_set?: string[] }) => `${DatadogProvider.tag(s, "pod_name")}/${DatadogProvider.tag(s, "kube_container_name")}`;
    const memMap = new Map(mem.map((s) => [key(s), DatadogProvider.last([s])]));
    const thrMap = new Map(thr.map((s) => [key(s), DatadogProvider.mean([s])]));
    return cpu.map((s) => ({
      pod: DatadogProvider.tag(s, "pod_name") ?? "?",
      container: DatadogProvider.tag(s, "kube_container_name") ?? "?",
      // kubernetes.cpu.usage.total is nanocores
      cpuMillicores: Math.round((DatadogProvider.last([s]) ?? 0) / 1e6),
      memoryBytes: memMap.get(key(s)),
      cpuThrottledRatio: thrMap.get(key(s)),
      source: "datadog:kubernetes.*",
    }));
  }

  async rawMetricQuery(query: string, windowSeconds: number): Promise<RawMetricResult | undefined> {
    const to = Math.floor(Date.now() / 1000);
    const series = await this.series(query, to - windowSeconds, to);
    return {
      query,
      series: series.slice(0, 50).map((s) => ({
        labels: Object.fromEntries((s.tag_set ?? s.scope?.split(",") ?? []).map((t) => [t.split(":")[0], t.split(":").slice(1).join(":")])),
        values: (s.pointlist ?? []).filter(([, v]) => v !== null).map(([t, v]) => [Math.round(t / 1000), v as number] as [number, number]),
      })),
      truncated: series.length > 50,
      source: "datadog",
    };
  }

  private async searchSpans(query: string, windowSeconds: number, limit: number): Promise<SpanEvent[]> {
    const r = await this.request<EventsPage<SpanEvent>>("POST", "/api/v2/spans/events/search", {
      data: { type: "search_request", attributes: { filter: { query, from: `now-${windowSeconds}s`, to: "now" }, page: { limit: Math.min(limit, 1000) }, sort: "-timestamp" } },
    });
    return r.data ?? [];
  }

  private static spanDurationMs(s: SpanEvent): number {
    const a = s.attributes;
    const d = Number(getPath(a?.attributes, "duration"));
    if (Number.isFinite(d) && d > 0) return d / 1e6; // @duration is nanoseconds
    const st = Date.parse(a?.start_timestamp ?? "");
    const en = Date.parse(a?.end_timestamp ?? "");
    return Number.isFinite(st) && Number.isFinite(en) ? en - st : 0;
  }

  async slowTraces(ctx: ProviderContext, minDurationMs: number, limit: number): Promise<SlowTrace[] | undefined> {
    const scope = this.cfg.scope ? ` ${this.cfg.scope.split(",").map((s) => s.trim()).join(" ")}` : "";
    const spans = await this.searchSpans(`${this.cfg.serviceTag}:${ctx.service}${scope} @_top_level:1 @duration:>=${Math.round(minDurationMs * 1e6)}`, ctx.windowSeconds, Math.max(limit * 5, 100));
    if (!spans.length) return [];
    const byTrace = new Map<string, SpanEvent>();
    for (const s of spans) {
      const id = s.attributes?.trace_id ?? "";
      const prev = byTrace.get(id);
      if (!prev || DatadogProvider.spanDurationMs(s) > DatadogProvider.spanDurationMs(prev)) byTrace.set(id, s);
    }
    return [...byTrace.entries()]
      .map(([traceId, s]) => ({
        traceId,
        durationMs: Math.round(DatadogProvider.spanDurationMs(s)),
        rootOperation: s.attributes?.resource_name,
        rootService: s.attributes?.service,
        startTime: s.attributes?.start_timestamp,
        error: (s.attributes?.tags ?? []).some((t) => t === "error:1" || t === "error:true") || getPath(s.attributes?.attributes, "error") === 1,
      }))
      .sort((a, b) => b.durationMs - a.durationMs)
      .slice(0, limit);
  }

  async trace(traceId: string): Promise<TraceCriticalPath | undefined> {
    const spans = await this.searchSpans(`trace_id:${traceId}`, 7 * 86400, 1000);
    if (!spans.length) return undefined;
    const nodes = spans.map((s) => ({
      id: s.attributes?.span_id ?? "",
      parent: s.attributes?.parent_id || undefined,
      service: s.attributes?.service,
      operation: s.attributes?.resource_name ?? String(getPath(s.attributes?.attributes, "operation_name") ?? "?"),
      durationMs: DatadogProvider.spanDurationMs(s),
      start: Date.parse(s.attributes?.start_timestamp ?? "") || 0,
      error: (s.attributes?.tags ?? []).some((t) => t === "error:1" || t === "error:true"),
    }));
    const byId = new Map(nodes.map((n) => [n.id, n]));
    const children = new Map<string, typeof nodes>();
    for (const n of nodes) if (n.parent && byId.has(n.parent)) children.set(n.parent, [...(children.get(n.parent) ?? []), n]);
    const depth = (n: (typeof nodes)[number]): number => (n.parent && byId.has(n.parent) ? 1 + depth(byId.get(n.parent)!) : 0);
    const root = nodes.find((n) => !n.parent || !byId.has(n.parent)) ?? nodes[0];
    const out = nodes
      .map((n) => ({ service: n.service, operation: n.operation, durationMs: Math.round(n.durationMs), selfMs: Math.round(Math.max(0, n.durationMs - (children.get(n.id) ?? []).reduce((a, c) => a + c.durationMs, 0))), depth: depth(n), error: n.error || undefined, start: n.start }))
      .sort((a, b) => a.start - b.start)
      // critical path: keep spans whose self time is >= 2% of the trace, plus the root
      .filter((s, i) => i === 0 || s.selfMs >= root.durationMs * 0.02 || s.error)
      .slice(0, 60)
      .map(({ start: _s, ...rest }) => rest);
    return { traceId, durationMs: Math.round(root.durationMs), spans: out, services: [...new Set(nodes.map((n) => n.service).filter((x): x is string => Boolean(x)))], source: "datadog:spans" };
  }

  async logSearch(ctx: ProviderContext, query: string, limit: number): Promise<LogSearchResult | undefined> {
    const scope = this.cfg.scope ? ` ${this.cfg.scope.split(",").map((s) => s.trim()).join(" ")}` : "";
    const q = `${this.cfg.namespaceTag}:${ctx.namespace} ${this.cfg.serviceTag}:${ctx.service}${scope}${query ? ` ${query}` : ""}`;
    const r = await this.request<EventsPage<LogEvent>>("POST", "/api/v2/logs/events/search", {
      filter: { query: q, from: `now-${ctx.windowSeconds}s`, to: "now", ...(this.cfg.logIndexes.length ? { indexes: this.cfg.logIndexes } : {}) },
      page: { limit: Math.min(limit, 1000) },
      sort: "-timestamp",
    });
    const lines = (r.data ?? []).map((e) => `${e.attributes?.timestamp ?? ""} [${e.attributes?.status ?? ""}] ${e.attributes?.message ?? ""}`.trim());
    return { lines, truncated: Boolean(r.meta?.page?.after), source: "datadog:logs" };
  }

  async webVitals(ctx: ProviderContext, route?: string): Promise<RumSummary | undefined> {
    const app = this.cfg.rumApplication ? ` (@application.name:"${this.cfg.rumApplication}" OR @application.id:${this.cfg.rumApplication})` : "";
    const routeQ = route ? ` @view.url_path_group:"${route}"` : "";
    const fetchType = async (type: string, limit: number) => {
      const r = await this.request<EventsPage<RumEvent>>("POST", "/api/v2/rum/events/search", {
        filter: { query: `@type:${type}${app}${routeQ}`, from: `now-${ctx.windowSeconds}s`, to: "now" },
        page: { limit },
        sort: "-timestamp",
      });
      return r.data ?? [];
    };
    const views = await fetchType("view", 1000);
    if (!views.length) return undefined;
    const ns = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v / 1e6 : undefined);
    const perRoute = new Map<string, Record<string, number[]>>();
    const viewCounts = new Map<string, { views: number; entries: number }>();
    const sessions = new Set<string>();
    const devices: Record<string, number> = {};
    for (const e of views) {
      const a = e.attributes?.attributes;
      const r = String(getPath(a, "view.url_path_group") ?? getPath(a, "view.url_path") ?? "(unknown)");
      const m = perRoute.get(r) ?? {};
      const push = (k: string, v: number | undefined) => {
        if (v === undefined) return;
        (m[k] ??= []).push(v);
      };
      push("LCP", ns(getPath(a, "view.largest_contentful_paint")));
      push("FCP", ns(getPath(a, "view.first_contentful_paint")));
      push("INP", ns(getPath(a, "view.interaction_to_next_paint")));
      push("TTFB", ns(getPath(a, "view.first_byte")));
      const cls = getPath(a, "view.cumulative_layout_shift");
      if (typeof cls === "number") push("CLS", cls);
      perRoute.set(r, m);
      const vc = viewCounts.get(r) ?? { views: 0, entries: 0 };
      vc.views++;
      if (getPath(a, "session.initial_view") === true || getPath(a, "view.is_initial") === true) vc.entries++;
      viewCounts.set(r, vc);
      const sid = getPath(a, "session.id");
      if (typeof sid === "string") sessions.add(sid);
      const dev = String(getPath(a, "device.type") ?? "unknown");
      devices[dev] = (devices[dev] ?? 0) + 1;
    }
    const vitals: RumSummary["vitals"] = {};
    for (const [r, m] of perRoute) {
      vitals[r] = {};
      for (const [k, vals] of Object.entries(m)) if (vals.length) vitals[r][k] = pcts(vals);
    }
    const errors = await fetchType("error", 500).catch(() => []);
    const errMap = new Map<string, { count: number; first: string; last: string; routes: Set<string>; sample: string }>();
    for (const e of errors) {
      const a = e.attributes?.attributes;
      const msg = String(getPath(a, "error.message") ?? "error").replace(/\d+/g, "N").slice(0, 160);
      const ts = e.attributes?.timestamp ?? "";
      const x = errMap.get(msg) ?? { count: 0, first: ts, last: ts, routes: new Set(), sample: String(getPath(a, "error.message") ?? "").slice(0, 200) };
      x.count++;
      if (ts < x.first) x.first = ts;
      if (ts > x.last) x.last = ts;
      x.routes.add(String(getPath(a, "view.url_path_group") ?? getPath(a, "view.url_path") ?? "?"));
      errMap.set(msg, x);
    }
    return {
      available: true,
      note: "source: Datadog RUM (view events, p-values computed from up to 1000 recent views)",
      since: `now-${ctx.windowSeconds}s`,
      vitals,
      nav: {},
      views: [...viewCounts.entries()].map(([route, c]) => ({ route, ...c })).sort((a, b) => b.views - a.views),
      resources: [],
      errors: [...errMap.entries()].map(([signature, x]) => ({ signature, count: x.count, firstSeen: x.first, lastSeen: x.last, routes: [...x.routes], sample: x.sample })).sort((a, b) => b.count - a.count).slice(0, 50),
      devices,
      sessions: sessions.size,
    };
  }
}

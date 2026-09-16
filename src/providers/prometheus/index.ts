/**
 * Prometheus-compatible provider (Prometheus, Thanos, Mimir, VictoriaMetrics).
 * Default metric names follow Micrometer/Spring Boot and cAdvisor; override
 * via DIAG_PROM_HTTP_METRIC / DIAG_PROM_SERVICE_LABEL if your apps differ.
 */
import type { Capability, GoldenSignals, ProviderContext, RawMetricResult, ResourceUsageSample, SignalProvider } from "../types.js";

export interface PrometheusOptions {
  baseUrl: string;
  /** Histogram base name for HTTP server requests (Micrometer default). */
  httpMetric?: string;
  /** Label that identifies the service in app metrics. */
  serviceLabel?: string;
  timeoutMs?: number;
}

interface PromResponse {
  status: string;
  data?: { resultType: string; result: Array<{ metric: Record<string, string>; value?: [number, string]; values?: Array<[number, string]> }> };
  error?: string;
}

export class PrometheusProvider implements SignalProvider {
  readonly name = "prometheus";
  readonly capabilities: Capability[] = ["goldenSignals", "resourceUsage", "rawMetricQuery"];
  private readonly httpMetric: string;
  private readonly serviceLabel: string;
  private readonly timeoutMs: number;

  constructor(private readonly opts: PrometheusOptions) {
    this.httpMetric = opts.httpMetric ?? "http_server_requests_seconds";
    this.serviceLabel = opts.serviceLabel ?? "service";
    this.timeoutMs = opts.timeoutMs ?? 10000;
  }

  private async query(q: string, time?: number): Promise<PromResponse["data"]> {
    const url = new URL(`${this.opts.baseUrl}/api/v1/query`);
    url.searchParams.set("query", q);
    if (time) url.searchParams.set("time", String(time));
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), this.timeoutMs);
    try {
      const r = await fetch(url, { signal: ctl.signal });
      const body = (await r.json()) as PromResponse;
      if (body.status !== "success") throw new Error(body.error ?? `HTTP ${r.status}`);
      return body.data;
    } finally {
      clearTimeout(t);
    }
  }

  private async queryRange(q: string, start: number, end: number, step: number): Promise<PromResponse["data"]> {
    const url = new URL(`${this.opts.baseUrl}/api/v1/query_range`);
    url.searchParams.set("query", q);
    url.searchParams.set("start", String(start));
    url.searchParams.set("end", String(end));
    url.searchParams.set("step", String(step));
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), this.timeoutMs);
    try {
      const r = await fetch(url, { signal: ctl.signal });
      const body = (await r.json()) as PromResponse;
      if (body.status !== "success") throw new Error(body.error ?? `HTTP ${r.status}`);
      return body.data;
    } finally {
      clearTimeout(t);
    }
  }

  async status() {
    try {
      const r = await fetch(`${this.opts.baseUrl}/-/ready`, { signal: AbortSignal.timeout(3000) });
      return { configured: true, reachable: r.ok, detail: `${this.opts.baseUrl} (${r.status})` };
    } catch (err) {
      return { configured: true, reachable: false, detail: err instanceof Error ? err.message : String(err) };
    }
  }

  private scalar(data: PromResponse["data"]): number | undefined {
    const v = data?.result?.[0]?.value?.[1];
    if (v === undefined) return undefined;
    const n = Number(v);
    return Number.isFinite(n) ? n : undefined;
  }

  async goldenSignals(ctx: ProviderContext): Promise<GoldenSignals | undefined> {
    const w = `${ctx.windowSeconds}s`;
    const sel = `${this.serviceLabel}="${ctx.service}",namespace="${ctx.namespace}"`;
    const selNoNs = `${this.serviceLabel}="${ctx.service}"`;
    const m = this.httpMetric;
    // Try with namespace label first, then without (app metrics often lack it).
    for (const s of [sel, selNoNs]) {
      const rate = this.scalar(await this.query(`sum(rate(${m}_count{${s}}[${w}]))`));
      if (rate === undefined) continue;
      const err5 = this.scalar(await this.query(`sum(rate(${m}_count{${s},status=~"5.."}[${w}]))`)) ?? 0;
      const errAll = this.scalar(await this.query(`sum(rate(${m}_count{${s},status=~"[45].."}[${w}]))`)) ?? 0;
      const p = async (q: number) => {
        const v = this.scalar(await this.query(`histogram_quantile(${q}, sum by (le) (rate(${m}_bucket{${s}}[${w}])))`));
        return v === undefined ? undefined : Math.round(v * 1000);
      };
      const byEp = await this.query(`sum by (uri, method) (rate(${m}_count{${s}}[${w}]))`);
      const byEpErr = await this.query(`sum by (uri, method) (rate(${m}_count{${s},status=~"5.."}[${w}]))`);
      const errMap = new Map((byEpErr?.result ?? []).map((r) => [`${r.metric.method} ${r.metric.uri}`, Number(r.value?.[1] ?? 0)]));
      const byEndpoint = (byEp?.result ?? [])
        .map((r) => {
          const key = `${r.metric.method} ${r.metric.uri}`;
          const rr = Number(r.value?.[1] ?? 0);
          return { endpoint: r.metric.uri ?? "?", method: r.metric.method, requestRate: rr, errorRate: rr ? (errMap.get(key) ?? 0) / rr : 0 };
        })
        .sort((a, b) => b.requestRate - a.requestRate)
        .slice(0, 25);
      return {
        service: ctx.service,
        namespace: ctx.namespace,
        windowSeconds: ctx.windowSeconds,
        requestRate: rate,
        errorRate: rate ? errAll / rate : 0,
        errorRate5xx: rate ? err5 / rate : 0,
        latencyMs: { p50: await p(0.5), p95: await p(0.95), p99: await p(0.99) },
        byEndpoint,
        source: `prometheus:${m}`,
      };
    }
    return undefined;
  }

  async resourceUsage(ctx: ProviderContext): Promise<ResourceUsageSample[] | undefined> {
    const w = `${Math.max(ctx.windowSeconds, 120)}s`;
    const podRe = ctx.pods?.length ? ctx.pods.join("|") : `${ctx.service}.*`;
    const sel = `namespace="${ctx.namespace}",pod=~"${podRe}",container!="",container!="POD"`;
    const cpu = await this.query(`sum by (pod, container) (rate(container_cpu_usage_seconds_total{${sel}}[${w}]))`);
    if (!cpu?.result?.length) return undefined;
    const mem = await this.query(`max by (pod, container) (container_memory_working_set_bytes{${sel}})`);
    const thr = await this.query(
      `sum by (pod, container) (rate(container_cpu_cfs_throttled_periods_total{${sel}}[${w}])) / sum by (pod, container) (rate(container_cpu_cfs_periods_total{${sel}}[${w}]))`,
    );
    const key = (r: { metric: Record<string, string> }) => `${r.metric.pod}/${r.metric.container}`;
    const memMap = new Map((mem?.result ?? []).map((r) => [key(r), Number(r.value?.[1])]));
    const thrMap = new Map((thr?.result ?? []).map((r) => [key(r), Number(r.value?.[1])]));
    return cpu.result.map((r) => ({
      pod: r.metric.pod,
      container: r.metric.container,
      cpuMillicores: Math.round(Number(r.value?.[1]) * 1000),
      memoryBytes: memMap.get(key(r)),
      cpuThrottledRatio: Number.isFinite(thrMap.get(key(r))) ? thrMap.get(key(r)) : undefined,
      source: "prometheus:cadvisor",
    }));
  }

  async rawMetricQuery(query: string, windowSeconds: number, step?: number): Promise<RawMetricResult | undefined> {
    const end = Math.floor(Date.now() / 1000);
    const start = end - windowSeconds;
    const st = step ?? Math.max(15, Math.floor(windowSeconds / 60));
    const data = await this.queryRange(query, start, end, st);
    const series = (data?.result ?? []).slice(0, 50).map((r) => ({
      labels: r.metric,
      values: (r.values ?? (r.value ? [r.value] : [])).map(([t, v]) => [t, Number(v)] as [number, number]),
    }));
    return { query, series, truncated: (data?.result?.length ?? 0) > 50, source: "prometheus" };
  }
}

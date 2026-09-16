/**
 * Signal providers.
 *
 * The runbook tools need a handful of *signals* (golden signals, resource
 * pressure, slow traces, log search, web vitals). Where those come from is a
 * deployment detail: metrics-server + probe today, Prometheus if configured,
 * Datadog/Splunk once their APIs are reachable. Each provider implements the
 * capabilities it can and reports the rest as unsupported, and the registry
 * picks the first provider that supports a capability. Nothing else in the
 * hub knows which vendor answered.
 */

export type Capability = "goldenSignals" | "resourceUsage" | "slowTraces" | "trace" | "logSearch" | "webVitals" | "rawMetricQuery";

export interface GoldenSignals {
  service: string;
  namespace: string;
  windowSeconds: number;
  requestRate?: number; // req/s
  errorRate?: number; // 0..1
  errorRate5xx?: number;
  latencyMs?: { p50?: number; p95?: number; p99?: number };
  byEndpoint?: Array<{ endpoint: string; method?: string; requestRate: number; errorRate: number; p95Ms?: number; p99Ms?: number }>;
  source: string;
  note?: string;
}

export interface ResourceUsageSample {
  pod: string;
  container: string;
  cpuMillicores?: number;
  memoryBytes?: number;
  /** Fraction of CFS periods throttled over the window, if the source knows it. */
  cpuThrottledRatio?: number;
  source: string;
}

export interface SlowTrace {
  traceId: string;
  durationMs: number;
  rootOperation?: string;
  rootService?: string;
  startTime?: string;
  slowestSpan?: { service?: string; operation?: string; durationMs: number };
  error?: boolean;
}

export interface TraceCriticalPath {
  traceId: string;
  durationMs: number;
  spans: Array<{ service?: string; operation: string; durationMs: number; selfMs: number; depth: number; error?: boolean }>;
  services: string[];
  source: string;
}

export interface LogSearchResult {
  lines: string[];
  truncated: boolean;
  source: string;
  note?: string;
}

export interface RawMetricResult {
  query: string;
  series: Array<{ labels: Record<string, string>; values: Array<[number, number]> }>;
  truncated: boolean;
  source: string;
}

export interface ProviderContext {
  namespace: string;
  /** Workload/service name as the user said it. */
  service: string;
  /** Pod names currently backing the service, when the caller already resolved them. */
  pods?: string[];
  windowSeconds: number;
}

export interface SignalProvider {
  readonly name: string;
  /** Static: which capabilities this provider implements at all. */
  readonly capabilities: Capability[];
  /** Cheap liveness/config check, used by list_providers. */
  status(): Promise<{ configured: boolean; reachable?: boolean; detail?: string }>;

  goldenSignals?(ctx: ProviderContext): Promise<GoldenSignals | undefined>;
  resourceUsage?(ctx: ProviderContext): Promise<ResourceUsageSample[] | undefined>;
  slowTraces?(ctx: ProviderContext, minDurationMs: number, limit: number): Promise<SlowTrace[] | undefined>;
  trace?(traceId: string): Promise<TraceCriticalPath | undefined>;
  logSearch?(ctx: ProviderContext, query: string, limit: number): Promise<LogSearchResult | undefined>;
  webVitals?(ctx: ProviderContext, route?: string): Promise<unknown>;
  rawMetricQuery?(query: string, windowSeconds: number, step?: number): Promise<RawMetricResult | undefined>;
}

export class ProviderRegistry {
  constructor(private readonly providers: SignalProvider[]) {}

  all(): SignalProvider[] {
    return this.providers;
  }

  /** Providers that implement a capability, in priority order. */
  forCapability(cap: Capability): SignalProvider[] {
    return this.providers.filter((p) => p.capabilities.includes(cap));
  }

  /** Runs the first provider that returns a defined result; reports which. */
  async first<T>(cap: Capability, fn: (p: SignalProvider) => Promise<T | undefined>): Promise<{ result?: T; provider?: string; tried: string[]; errors: string[] }> {
    const tried: string[] = [];
    const errors: string[] = [];
    for (const p of this.forCapability(cap)) {
      tried.push(p.name);
      try {
        const r = await fn(p);
        if (r !== undefined) return { result: r, provider: p.name, tried, errors };
      } catch (err) {
        errors.push(`${p.name}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
    return { tried, errors };
  }
}

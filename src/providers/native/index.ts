/**
 * Native provider: what the cluster gives us with no external observability
 * stack. Resource usage from metrics.k8s.io (metrics-server); golden signals
 * from Micrometer's http_server_requests via the probe sidecar hitting
 * Actuator on localhost; log search from pod logs.
 */
import type { V1Pod } from "@kubernetes/client-node";
import type { ReadOnlyKubeClient } from "../../k8s/client.js";
import type { ProbeClient } from "../../probe/client.js";
import { hasProbeContainer, appContainerName } from "../../hub/model.js";
import { redactText } from "../../security/sanitize.js";
import type { Capability, GoldenSignals, LogSearchResult, ProviderContext, ResourceUsageSample, SignalProvider } from "../types.js";

interface ActuatorMetric {
  name: string;
  measurements: Array<{ statistic: string; value: number }>;
  availableTags?: Array<{ tag: string; values: string[] }>;
}

export class NativeProvider implements SignalProvider {
  readonly name = "native";
  readonly capabilities: Capability[] = ["resourceUsage", "goldenSignals", "logSearch"];

  constructor(
    private readonly k8s: ReadOnlyKubeClient,
    private readonly probe: ProbeClient,
    private readonly probeContainerName: string,
    private readonly logMax: { lines: number; bytes: number },
  ) {}

  async status() {
    const nm = await this.k8s.nodeMetrics().catch(() => undefined);
    return { configured: true, reachable: true, detail: nm ? "metrics-server available" : "metrics-server not available (resource usage will need Prometheus)" };
  }

  async resourceUsage(ctx: ProviderContext): Promise<ResourceUsageSample[] | undefined> {
    const list = await this.k8s.podMetrics(ctx.namespace);
    if (!list) return undefined;
    const wanted = ctx.pods ? new Set(ctx.pods) : undefined;
    const out: ResourceUsageSample[] = [];
    for (const pm of list.items) {
      const pod = pm.metadata?.name ?? "";
      if (wanted && !wanted.has(pod)) continue;
      for (const c of pm.containers ?? []) {
        out.push({
          pod,
          container: c.name,
          cpuMillicores: cpuToMillicores(c.usage?.cpu),
          memoryBytes: memToBytes(c.usage?.memory),
          source: "metrics-server",
        });
      }
    }
    return out.length ? out : undefined;
  }

  /** Golden signals from Micrometer via a probe: aggregates http.server.requests across pods with a probe. */
  async goldenSignals(ctx: ProviderContext): Promise<GoldenSignals | undefined> {
    const pods = (await this.k8s.listPods(ctx.namespace)).filter(
      (p) => (!ctx.pods || ctx.pods.includes(p.metadata?.name ?? "")) && hasProbeContainer(p, this.probeContainerName),
    );
    if (!pods.length) return undefined;
    let count = 0;
    let totalTime = 0;
    let max = 0;
    let err5 = 0;
    let err4 = 0;
    const byEndpoint = new Map<string, { count: number; totalTime: number; err: number }>();
    let uptimeSeconds: number | undefined;
    let anyProbe = false;
    for (const pod of pods) {
      let m: ActuatorMetric | undefined;
      try {
        const r = await this.probe.actuator(pod, "metrics", "http.server.requests");
        if (!r.available || r.status !== 200) continue;
        m = r.body as ActuatorMetric;
        anyProbe = true;
      } catch {
        continue;
      }
      const stat = (name: string) => m?.measurements.find((x) => x.statistic === name)?.value ?? 0;
      count += stat("COUNT");
      totalTime += stat("TOTAL_TIME");
      max = Math.max(max, stat("MAX"));
      try {
        const up = (await this.probe.actuator(pod, "metrics", "process.uptime")).body as ActuatorMetric | undefined;
        const u = up?.measurements.find((x) => x.statistic === "VALUE")?.value;
        if (u) uptimeSeconds = Math.max(uptimeSeconds ?? 0, u);
      } catch {
        /* ignore */
      }
      // Error counts and per-endpoint breakdown: one call per status class and one per uri (bounded).
      try {
        err5 += ((await this.probe.actuator(pod, "metrics", "http.server.requests", ["outcome:SERVER_ERROR"])).body as ActuatorMetric)?.measurements.find((x) => x.statistic === "COUNT")?.value ?? 0;
        err4 += ((await this.probe.actuator(pod, "metrics", "http.server.requests", ["outcome:CLIENT_ERROR"])).body as ActuatorMetric)?.measurements.find((x) => x.statistic === "COUNT")?.value ?? 0;
      } catch {
        /* ignore */
      }
      const uris = m.availableTags?.find((t) => t.tag === "uri")?.values ?? [];
      for (const uri of uris.slice(0, 25)) {
        try {
          const em = (await this.probe.actuator(pod, "metrics", "http.server.requests", [`uri:${uri}`])).body as ActuatorMetric;
          const ec = em?.measurements.find((x) => x.statistic === "COUNT")?.value ?? 0;
          const et = em?.measurements.find((x) => x.statistic === "TOTAL_TIME")?.value ?? 0;
          let ee = 0;
          try {
            ee = ((await this.probe.actuator(pod, "metrics", "http.server.requests", [`uri:${uri}`, "outcome:SERVER_ERROR"])).body as ActuatorMetric)?.measurements.find((x) => x.statistic === "COUNT")?.value ?? 0;
          } catch {
            /* ignore */
          }
          const e = byEndpoint.get(uri) ?? { count: 0, totalTime: 0, err: 0 };
          e.count += ec;
          e.totalTime += et;
          e.err += ee;
          byEndpoint.set(uri, e);
        } catch {
          /* ignore */
        }
      }
    }
    if (!anyProbe) return undefined;
    // Micrometer's default meter is cumulative since process start, so the "window" is the process uptime.
    const window = uptimeSeconds ?? ctx.windowSeconds;
    return {
      service: ctx.service,
      namespace: ctx.namespace,
      windowSeconds: Math.round(window),
      requestRate: window ? count / window : undefined,
      errorRate: count ? (err5 + err4) / count : 0,
      errorRate5xx: count ? err5 / count : 0,
      latencyMs: { p50: count ? Math.round((totalTime / count) * 1000) : undefined, p99: Math.round(max * 1000) },
      byEndpoint: [...byEndpoint.entries()]
        .map(([endpoint, e]) => ({ endpoint, requestRate: window ? e.count / window : 0, errorRate: e.count ? e.err / e.count : 0, p95Ms: e.count ? Math.round((e.totalTime / e.count) * 1000) : undefined }))
        .sort((a, b) => b.requestRate - a.requestRate),
      source: "actuator:http.server.requests (cumulative since JVM start; p50 is the mean, p99 is the max)",
      note: "Micrometer's default distribution is cumulative. Configure a Prometheus provider for true windowed percentiles.",
    };
  }

  async logSearch(ctx: ProviderContext, query: string, limit: number): Promise<LogSearchResult | undefined> {
    const pods: V1Pod[] = (await this.k8s.listPods(ctx.namespace)).filter((p) => !ctx.pods || ctx.pods.includes(p.metadata?.name ?? ""));
    if (!pods.length) return undefined;
    const re = safeRegex(query);
    const lines: string[] = [];
    let truncated = false;
    for (const pod of pods) {
      const container = appContainerName(pod, this.probeContainerName);
      let text: string;
      try {
        text = await this.k8s.readPodLog(ctx.namespace, pod.metadata?.name ?? "", { container, sinceSeconds: ctx.windowSeconds, tailLines: this.logMax.lines, limitBytes: this.logMax.bytes });
      } catch {
        continue;
      }
      for (const line of text.split("\n")) {
        if (!line) continue;
        if (re ? re.test(line) : line.includes(query)) {
          if (lines.length >= limit) {
            truncated = true;
            break;
          }
          lines.push(`[${pod.metadata?.name}] ${redactText(line)}`);
        }
      }
      if (truncated) break;
    }
    return { lines, truncated, source: "pod logs" };
  }
}

function safeRegex(q: string): RegExp | undefined {
  if (!/^\/.+\/[gimsuy]*$/.test(q)) return undefined;
  const last = q.lastIndexOf("/");
  try {
    return new RegExp(q.slice(1, last), q.slice(last + 1).replace("g", ""));
  } catch {
    return undefined;
  }
}

function cpuToMillicores(q: string | undefined): number | undefined {
  if (!q) return undefined;
  const m = /^([0-9.]+)(n|u|m)?$/.exec(q);
  if (!m) return undefined;
  const n = Number(m[1]);
  return Math.round(m[2] === "n" ? n / 1e6 : m[2] === "u" ? n / 1e3 : m[2] === "m" ? n : n * 1000);
}

function memToBytes(q: string | undefined): number | undefined {
  if (!q) return undefined;
  const m = /^([0-9.]+)(Ki|Mi|Gi|Ti|k|M|G|T)?$/.exec(q);
  if (!m) return undefined;
  const n = Number(m[1]);
  const mult: Record<string, number> = { Ki: 1024, Mi: 1024 ** 2, Gi: 1024 ** 3, Ti: 1024 ** 4, k: 1e3, M: 1e6, G: 1e9, T: 1e12 };
  return Math.round(n * (m[2] ? mult[m[2]] : 1));
}

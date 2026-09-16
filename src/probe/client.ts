/**
 * Hub-side client for probe sidecars. Discovers the probe by container name
 * in the pod spec, talks to it at podIP:port with the shared token.
 */
import type { V1Pod } from "@kubernetes/client-node";
import type { HubConfig } from "../config.js";
import type { AccessLogSummary, ConnectResult, ConnectionSummary, DnsResult, NginxStatus, ProbeInfo, ProcessSummary, RumSummary, StaticBundleStats } from "./protocol.js";
import { hasProbeContainer } from "../hub/model.js";

export class ProbeUnavailable extends Error {}

export interface ActuatorResponse {
  available: boolean;
  status?: number;
  body?: unknown;
  text?: string;
  note?: string;
}

export class ProbeClient {
  /** podIP -> time until which we consider the probe unreachable (fail fast instead of stacking timeouts). */
  private readonly unreachableUntil = new Map<string, number>();
  private static readonly NEGATIVE_CACHE_MS = 20_000;

  constructor(private readonly config: HubConfig) {}

  /** Returns the probe base URL for a pod, or throws ProbeUnavailable with a helpful reason. */
  baseUrl(pod: V1Pod): string {
    const name = pod.metadata?.name ?? "?";
    if (!hasProbeContainer(pod, this.config.probeContainerName)) {
      throw new ProbeUnavailable(
        `Pod ${name} has no "${this.config.probeContainerName}" sidecar. Add the probe (see deploy/probe/) to use in-pod tools.`,
      );
    }
    const ip = pod.status?.podIP;
    if (!ip) throw new ProbeUnavailable(`Pod ${name} has no pod IP yet (phase ${pod.status?.phase ?? "unknown"}).`);
    const container = [...(pod.spec?.initContainers ?? []), ...(pod.spec?.containers ?? [])].find((c) => c.name === this.config.probeContainerName);
    const port = container?.ports?.find((p) => p.name === "probe")?.containerPort ?? this.config.probePort;
    const host = ip.includes(":") ? `[${ip}]` : ip;
    return `http://${host}:${port}`;
  }

  private async get<T>(pod: V1Pod, path: string, params: Record<string, string | string[] | undefined> = {}): Promise<T> {
    const base = this.baseUrl(pod);
    const until = this.unreachableUntil.get(base);
    if (until && until > Date.now()) throw new ProbeUnavailable(`probe at ${base} was unreachable ${Math.round((Date.now() - (until - ProbeClient.NEGATIVE_CACHE_MS)) / 1000)}s ago; retrying after ${Math.round((until - Date.now()) / 1000)}s`);
    const url = new URL(path, base);
    for (const [k, v] of Object.entries(params)) {
      if (v === undefined) continue;
      if (Array.isArray(v)) v.forEach((x) => url.searchParams.append(k, x));
      else url.searchParams.set(k, v);
    }
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), this.config.probeTimeoutMs);
    try {
      const r = await fetch(url, {
        headers: this.config.probeToken ? { authorization: `Bearer ${this.config.probeToken}` } : {},
        signal: ctl.signal,
      });
      const body = (await r.json()) as T & { error?: string };
      if (!r.ok) throw new ProbeUnavailable(`probe ${path} returned HTTP ${r.status}${body?.error ? `: ${body.error}` : ""}`);
      this.unreachableUntil.delete(base);
      return body;
    } catch (err) {
      if (err instanceof ProbeUnavailable) throw err;
      this.unreachableUntil.set(base, Date.now() + ProbeClient.NEGATIVE_CACHE_MS);
      throw new ProbeUnavailable(`probe unreachable at ${url.origin}: ${err instanceof Error ? err.message : String(err)} (is the hub running in-cluster or with network access to pod IPs?)`);
    } finally {
      clearTimeout(t);
    }
  }

  info(pod: V1Pod) {
    return this.get<ProbeInfo>(pod, "/info");
  }
  connections(pod: V1Pod) {
    return this.get<ConnectionSummary>(pod, "/connections");
  }
  processes(pod: V1Pod) {
    return this.get<ProcessSummary>(pod, "/processes");
  }
  dns(pod: V1Pod, name: string) {
    return this.get<DnsResult>(pod, "/dns", { name });
  }
  connect(pod: V1Pod, host: string, port: number) {
    return this.get<ConnectResult>(pod, "/connect", { host, port: String(port) });
  }
  nginxStatus(pod: V1Pod) {
    return this.get<NginxStatus>(pod, "/nginx-status");
  }
  staticStats(pod: V1Pod) {
    return this.get<StaticBundleStats>(pod, "/static-stats");
  }
  accessLog(pod: V1Pod, sinceSeconds?: number) {
    return this.get<AccessLogSummary>(pod, "/access-log", { sinceSeconds: sinceSeconds ? String(sinceSeconds) : undefined });
  }
  rumSummary(pod: V1Pod, route?: string) {
    return this.get<RumSummary>(pod, "/rum-summary", { route });
  }
  actuator(pod: V1Pod, endpoint: string, metric?: string, tags?: string[]) {
    return this.get<ActuatorResponse>(pod, "/actuator", { endpoint, metric, tag: tags });
  }
}

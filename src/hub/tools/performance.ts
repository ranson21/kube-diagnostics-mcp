import type { V1Pod } from "@kubernetes/client-node";
import type { ToolContext } from "../context.js";
import { nsOf } from "../context.js";
import { cpuMillicores, memoryBytes, humanBytes, resolveWorkload, summarizePod, ageSeconds, humanDuration } from "../model.js";
import { parseWindowSeconds, assertTraceId, clampLimit } from "../../security/guard.js";
import type { ResourceUsageSample } from "../../providers/types.js";

function pct(n: number | undefined, d: number | undefined): number | undefined {
  if (n === undefined || !d) return undefined;
  return Math.round((n / d) * 100);
}

export async function getResourcePressure(ctx: ToolContext, args: { namespace?: string; service?: string; pod?: string; window?: string }) {
  const ns = nsOf(ctx, args.namespace);
  const windowSeconds = parseWindowSeconds(args.window, 300);
  let pods: V1Pod[];
  let serviceName = args.service ?? args.pod ?? "";
  if (args.pod) pods = [await ctx.k8s.getPod(ns, args.pod)];
  else if (args.service) pods = (await resolveWorkload(ctx.k8s, ns, args.service)).pods;
  else {
    pods = await ctx.k8s.listPods(ns);
    serviceName = "*";
  }
  const usage = await ctx.providers.first("resourceUsage", (p) => p.resourceUsage!({ namespace: ns, service: serviceName, pods: pods.map((p) => p.metadata?.name ?? ""), windowSeconds }));
  const samples = new Map<string, ResourceUsageSample>();
  for (const s of usage.result ?? []) samples.set(`${s.pod}/${s.container}`, s);

  const findings: string[] = [];
  const rows = pods.flatMap((pod) =>
    (pod.spec?.containers ?? []).map((c) => {
      const s = samples.get(`${pod.metadata?.name}/${c.name}`);
      const cpuReq = cpuMillicores(c.resources?.requests?.cpu);
      const cpuLim = cpuMillicores(c.resources?.limits?.cpu);
      const memReq = memoryBytes(c.resources?.requests?.memory);
      const memLim = memoryBytes(c.resources?.limits?.memory);
      const status = pod.status?.containerStatuses?.find((x) => x.name === c.name);
      const oom = status?.lastState?.terminated?.reason === "OOMKilled" || status?.state?.terminated?.reason === "OOMKilled";
      const cpuPctLim = pct(s?.cpuMillicores, cpuLim);
      const memPctLim = pct(s?.memoryBytes, memLim);
      const name = `${pod.metadata?.name}/${c.name}`;
      if (oom) findings.push(`${name}: OOMKilled (restarts=${status?.restartCount}); memory limit ${c.resources?.limits?.memory ?? "none"}.`);
      if (memPctLim !== undefined && memPctLim >= 90) findings.push(`${name}: memory at ${memPctLim}% of limit (${humanBytes(s?.memoryBytes)} / ${c.resources?.limits?.memory}) - OOMKill imminent.`);
      if (cpuPctLim !== undefined && cpuPctLim >= 85) findings.push(`${name}: CPU at ${cpuPctLim}% of limit (${s?.cpuMillicores}m / ${c.resources?.limits?.cpu}) - expect CFS throttling and latency.`);
      if (s?.cpuThrottledRatio !== undefined && s.cpuThrottledRatio > 0.25) findings.push(`${name}: ${Math.round(s.cpuThrottledRatio * 100)}% of CPU periods throttled.`);
      if (cpuLim !== undefined && cpuReq !== undefined && cpuLim === cpuReq && cpuLim < 1000) findings.push(`${name}: CPU request == limit (${c.resources?.limits?.cpu}) below 1 core; bursty JVM/Node workloads get throttled at startup and GC.`);
      if (!cpuReq && !memReq) findings.push(`${name}: no requests (BestEffort QoS).`);
      return {
        pod: pod.metadata?.name,
        container: c.name,
        node: pod.spec?.nodeName,
        cpu: { usedMillicores: s?.cpuMillicores, request: c.resources?.requests?.cpu, limit: c.resources?.limits?.cpu, pctOfRequest: pct(s?.cpuMillicores, cpuReq), pctOfLimit: cpuPctLim, throttledRatio: s?.cpuThrottledRatio },
        memory: { used: humanBytes(s?.memoryBytes), request: c.resources?.requests?.memory, limit: c.resources?.limits?.memory, pctOfRequest: pct(s?.memoryBytes, memReq), pctOfLimit: memPctLim },
        restarts: status?.restartCount ?? 0,
        oomKilled: oom,
        source: s?.source,
      };
    }),
  );
  return {
    namespace: ns,
    window: `${windowSeconds}s`,
    source: usage.provider ?? "none",
    note: usage.result ? undefined : `no usage data: ${usage.errors.join("; ") || "install metrics-server or configure DIAG_PROMETHEUS_URL"}`,
    containers: rows,
    findings,
  };
}

export async function compareReplicas(ctx: ToolContext, args: { namespace?: string; service: string }) {
  const ns = nsOf(ctx, args.namespace);
  const w = await resolveWorkload(ctx.k8s, ns, args.service);
  const usage = await ctx.providers.first("resourceUsage", (p) => p.resourceUsage!({ namespace: ns, service: w.name, pods: w.pods.map((p) => p.metadata?.name ?? ""), windowSeconds: 300 }));
  const perPod = new Map<string, { cpu: number; mem: number }>();
  for (const s of usage.result ?? []) {
    const e = perPod.get(s.pod) ?? { cpu: 0, mem: 0 };
    e.cpu += s.cpuMillicores ?? 0;
    e.mem += s.memoryBytes ?? 0;
    perPod.set(s.pod, e);
  }
  const rows = w.pods.map((p) => {
    const sum = summarizePod(p, ctx.config.probeContainerName);
    const u = perPod.get(sum.name);
    return { pod: sum.name, node: sum.node, age: sum.age, ready: sum.ready, restarts: sum.restarts, cpuMillicores: u?.cpu, memory: humanBytes(u?.mem), memoryBytes: u?.mem, problems: sum.problems, revisionHash: p.metadata?.labels?.["pod-template-hash"] };
  });
  const findings: string[] = [];
  const cpus = rows.map((r) => r.cpuMillicores).filter((x): x is number => x !== undefined);
  if (cpus.length >= 2) {
    const avg = cpus.reduce((a, b) => a + b, 0) / cpus.length;
    for (const r of rows) if (r.cpuMillicores !== undefined && avg > 20 && r.cpuMillicores > avg * 2) findings.push(`${r.pod} uses ${r.cpuMillicores}m CPU, ${(r.cpuMillicores / avg).toFixed(1)}x the replica average - hot pod (sticky sessions? uneven partition? noisy neighbour on ${r.node}?).`);
  }
  const mems = rows.map((r) => r.memoryBytes).filter((x): x is number => x !== undefined);
  if (mems.length >= 2) {
    const avg = mems.reduce((a, b) => a + b, 0) / mems.length;
    for (const r of rows) if (r.memoryBytes !== undefined && r.memoryBytes > avg * 1.5) findings.push(`${r.pod} memory ${r.memory} is 1.5x+ the replica average - leak or uneven load.`);
  }
  const hashes = new Set(rows.map((r) => r.revisionHash).filter(Boolean));
  if (hashes.size > 1) findings.push(`replicas run ${hashes.size} different template revisions - a rollout is in progress or stuck.`);
  const nodes = new Map<string, number>();
  for (const r of rows) nodes.set(r.node ?? "?", (nodes.get(r.node ?? "?") ?? 0) + 1);
  for (const [node, n] of nodes) if (rows.length >= 3 && n >= rows.length - 1) findings.push(`${n}/${rows.length} replicas are on node ${node} - no spread; a node problem takes the service down. Consider topologySpreadConstraints.`);
  const restartOutlier = rows.filter((r) => r.restarts > 0 && r.restarts >= 3 * Math.max(1, Math.min(...rows.map((x) => x.restarts))));
  for (const r of restartOutlier) findings.push(`${r.pod} has ${r.restarts} restarts vs the others - check its node and its logs (previous=true).`);
  return { workload: `${w.kind}/${w.name}`, namespace: ns, replicas: rows, findings, usageSource: usage.provider ?? "none" };
}

export async function getNodePressure(ctx: ToolContext, args: { node?: string }) {
  const [nodes, metrics, pods] = await Promise.all([ctx.k8s.listNodes(), ctx.k8s.nodeMetrics(), ctx.k8s.listPodsAll()]);
  const usage = new Map((metrics?.items ?? []).map((m) => [m.metadata?.name ?? "", m.usage]));
  const rows = nodes
    .filter((n) => !args.node || n.metadata?.name === args.node)
    .map((n) => {
      const name = n.metadata?.name ?? "";
      const onNode = pods.filter((p) => p.spec?.nodeName === name && p.status?.phase !== "Succeeded" && p.status?.phase !== "Failed");
      const reqCpu = onNode.reduce((a, p) => a + (p.spec?.containers ?? []).reduce((b, c) => b + (cpuMillicores(c.resources?.requests?.cpu) ?? 0), 0), 0);
      const reqMem = onNode.reduce((a, p) => a + (p.spec?.containers ?? []).reduce((b, c) => b + (memoryBytes(c.resources?.requests?.memory) ?? 0), 0), 0);
      const limMem = onNode.reduce((a, p) => a + (p.spec?.containers ?? []).reduce((b, c) => b + (memoryBytes(c.resources?.limits?.memory) ?? 0), 0), 0);
      const allocCpu = cpuMillicores(n.status?.allocatable?.cpu);
      const allocMem = memoryBytes(n.status?.allocatable?.memory);
      const u = usage.get(name);
      const conditions = (n.status?.conditions ?? []).map((c) => ({ type: c.type, status: c.status, reason: c.reason }));
      const bad = conditions.filter((c) => (c.type === "Ready" && c.status !== "True") || (c.type !== "Ready" && c.status === "True"));
      const findings: string[] = [];
      for (const b of bad) findings.push(`${b.type}=${b.status}${b.reason ? ` (${b.reason})` : ""}`);
      if (allocMem && limMem > allocMem * 1.5) findings.push(`memory limits overcommitted ${Math.round((limMem / allocMem) * 100)}% of allocatable - OOM/eviction risk under load.`);
      if (allocCpu && reqCpu > allocCpu * 0.9) findings.push(`CPU requests at ${Math.round((reqCpu / allocCpu) * 100)}% of allocatable - new pods will not schedule here.`);
      if (n.spec?.unschedulable) findings.push("cordoned (unschedulable)");
      const uCpu = cpuMillicores(u?.cpu);
      const uMem = memoryBytes(u?.memory);
      if (allocMem && uMem && uMem > allocMem * 0.9) findings.push(`memory usage ${Math.round((uMem / allocMem) * 100)}% of allocatable.`);
      return {
        node: name,
        ready: conditions.find((c) => c.type === "Ready")?.status === "True",
        age: humanDuration(ageSeconds(n.metadata?.creationTimestamp)),
        kubelet: n.status?.nodeInfo?.kubeletVersion,
        os: `${n.status?.nodeInfo?.osImage} / ${n.status?.nodeInfo?.containerRuntimeVersion}`,
        pods: onNode.length,
        maxPods: n.status?.allocatable?.pods,
        cpu: { allocatableMillicores: allocCpu, requestedMillicores: reqCpu, usedMillicores: uCpu, pctRequested: pct(reqCpu, allocCpu), pctUsed: pct(uCpu, allocCpu) },
        memory: { allocatable: humanBytes(allocMem), requested: humanBytes(reqMem), limits: humanBytes(limMem), used: humanBytes(uMem), pctRequested: pct(reqMem, allocMem), pctUsed: pct(uMem, allocMem) },
        pressure: conditions.filter((c) => c.type !== "Ready").map((c) => `${c.type}=${c.status}`),
        taints: (n.spec?.taints ?? []).map((t) => `${t.key}=${t.value ?? ""}:${t.effect}`),
        findings,
      };
    });
  return { nodes: rows, metricsSource: metrics ? "metrics-server" : "none (usage unavailable)" };
}

export async function getHpaStatus(ctx: ToolContext, args: { namespace?: string }) {
  const ns = nsOf(ctx, args.namespace);
  const hpas = await ctx.k8s.listHpas(ns);
  return {
    namespace: ns,
    hpas: hpas.map((h) => {
      const findings: string[] = [];
      const max = h.spec?.maxReplicas ?? 0;
      const cur = h.status?.currentReplicas ?? 0;
      if (cur >= max && max > 0) findings.push(`at maxReplicas (${max}) - cannot scale further; raise the ceiling or fix the hot path.`);
      for (const c of h.status?.conditions ?? []) {
        if (c.type === "ScalingActive" && c.status !== "True") findings.push(`ScalingActive=False (${c.reason}): ${c.message?.slice(0, 200)}`);
        if (c.type === "AbleToScale" && c.status !== "True") findings.push(`AbleToScale=False (${c.reason}): ${c.message?.slice(0, 200)}`);
      }
      return {
        name: h.metadata?.name,
        target: `${h.spec?.scaleTargetRef?.kind}/${h.spec?.scaleTargetRef?.name}`,
        min: h.spec?.minReplicas,
        max,
        current: cur,
        desired: h.status?.desiredReplicas,
        lastScale: h.status?.lastScaleTime,
        metrics: (h.spec?.metrics ?? []).map((m, i) => {
          const cur = h.status?.currentMetrics?.[i];
          if (m.type === "Resource") return { type: "Resource", name: m.resource?.name, targetUtilization: m.resource?.target?.averageUtilization, currentUtilization: cur?.resource?.current?.averageUtilization };
          return { type: m.type, detail: JSON.stringify(m).slice(0, 200), current: JSON.stringify(cur ?? {}).slice(0, 200) };
        }),
        behavior: h.spec?.behavior ? "custom" : "default",
        findings,
      };
    }),
  };
}

export async function getGoldenSignals(ctx: ToolContext, args: { namespace?: string; service: string; window?: string }) {
  const ns = nsOf(ctx, args.namespace);
  const w = await resolveWorkload(ctx.k8s, ns, args.service);
  const windowSeconds = parseWindowSeconds(args.window, 900);
  const r = await ctx.providers.first("goldenSignals", (p) => p.goldenSignals!({ namespace: ns, service: w.name, pods: w.pods.map((p) => p.metadata?.name ?? ""), windowSeconds }));
  if (!r.result) return { service: w.name, namespace: ns, available: false, tried: r.tried, errors: r.errors, note: "No golden-signals source answered. Options: add the probe sidecar to Spring Boot pods (Actuator), set DIAG_PROMETHEUS_URL, or (later) Datadog/Splunk." };
  const g = r.result;
  const findings: string[] = [];
  if ((g.errorRate5xx ?? 0) > 0.01) findings.push(`5xx rate ${(g.errorRate5xx! * 100).toFixed(2)}% (> 1%)`);
  if ((g.latencyMs?.p99 ?? 0) > 2000) findings.push(`p99 latency ${g.latencyMs?.p99}ms (> 2s)`);
  for (const e of g.byEndpoint ?? []) {
    if (e.errorRate > 0.05 && e.requestRate > 0.01) findings.push(`${e.method ?? ""} ${e.endpoint}: ${(e.errorRate * 100).toFixed(1)}% errors`);
    if ((e.p95Ms ?? 0) > 1500) findings.push(`${e.method ?? ""} ${e.endpoint}: p95 ${e.p95Ms}ms`);
  }
  return { ...g, provider: r.provider, findings };
}

export async function queryMetrics(ctx: ToolContext, args: { query: string; window?: string; step?: number }) {
  const windowSeconds = parseWindowSeconds(args.window, 3600);
  const r = await ctx.providers.first("rawMetricQuery", (p) => p.rawMetricQuery!(args.query, windowSeconds, args.step));
  if (!r.result) return { available: false, tried: r.tried, errors: r.errors, note: "No metrics backend configured (DIAG_PROMETHEUS_URL)." };
  const compact = r.result.series.map((s) => {
    const vals = s.values;
    const nums = vals.map((v) => v[1]).filter((n) => Number.isFinite(n));
    return { labels: s.labels, points: vals.length, first: vals[0]?.[1], last: vals[vals.length - 1]?.[1], min: nums.length ? Math.min(...nums) : undefined, max: nums.length ? Math.max(...nums) : undefined, avg: nums.length ? nums.reduce((a, b) => a + b, 0) / nums.length : undefined, sampled: vals.filter((_, i) => i % Math.max(1, Math.floor(vals.length / 12)) === 0).slice(0, 12) };
  });
  return { query: args.query, window: `${windowSeconds}s`, provider: r.provider, series: compact, truncated: r.result.truncated };
}

export async function findSlowTraces(ctx: ToolContext, args: { namespace?: string; service: string; min_duration_ms?: number; window?: string; limit?: number }) {
  const ns = nsOf(ctx, args.namespace);
  const windowSeconds = parseWindowSeconds(args.window, 3600);
  const r = await ctx.providers.first("slowTraces", (p) => p.slowTraces!({ namespace: ns, service: args.service, windowSeconds }, args.min_duration_ms ?? 1000, clampLimit(args.limit, 20, 100)));
  if (!r.result) return { available: false, tried: r.tried, errors: r.errors, note: "No tracing backend is configured. Tracing providers (Tempo/Jaeger/Datadog APM) plug in via src/providers; until then use get_endpoint_metrics / summarize_access_log for latency by endpoint." };
  return { service: args.service, namespace: ns, provider: r.provider, traces: r.result };
}

export async function getTrace(ctx: ToolContext, args: { trace_id: string }) {
  assertTraceId(args.trace_id);
  const r = await ctx.providers.first("trace", (p) => p.trace!(args.trace_id));
  if (!r.result) return { available: false, tried: r.tried, errors: r.errors, note: "No tracing backend is configured." };
  return r.result;
}

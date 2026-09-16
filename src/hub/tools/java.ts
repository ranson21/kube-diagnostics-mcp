/**
 * Java / Spring Boot tools. Everything comes from Actuator via the probe on
 * localhost (never exposed outside the pod) or from Prometheus if configured.
 */
import type { V1Pod } from "@kubernetes/client-node";
import type { ToolContext } from "../context.js";
import { nsOf } from "../context.js";
import { resolveWorkload, memoryBytes, humanBytes } from "../model.js";
import { describeEnv, jvmFindings } from "./config.js";
import { getGoldenSignals } from "./performance.js";

interface Meter {
  name?: string;
  measurements?: Array<{ statistic: string; value: number }>;
  availableTags?: Array<{ tag: string; values: string[] }>;
}

async function meter(ctx: ToolContext, pod: V1Pod, name: string, tags?: string[]): Promise<Meter | undefined> {
  try {
    const r = await ctx.probe.actuator(pod, "metrics", name, tags);
    if (!r.available || r.status !== 200) return undefined;
    return r.body as Meter;
  } catch {
    return undefined;
  }
}
const val = (m: Meter | undefined, stat = "VALUE") => m?.measurements?.find((x) => x.statistic === stat)?.value;

async function runningPods(ctx: ToolContext, ns: string, args: { service?: string; pod?: string }): Promise<V1Pod[]> {
  if (args.pod) return [await ctx.k8s.getPod(ns, args.pod)];
  if (!args.service) throw new Error("Provide `service` or `pod`.");
  const w = await resolveWorkload(ctx.k8s, ns, args.service);
  return w.pods.filter((p) => p.status?.phase === "Running");
}

export async function getJvmHealth(ctx: ToolContext, args: { namespace?: string; service?: string; pod?: string }) {
  const ns = nsOf(ctx, args.namespace);
  const pods = await runningPods(ctx, ns, args);
  const rows = [];
  for (const pod of pods.slice(0, 10)) {
    const findings: string[] = [];
    let heapUsed, heapMax, heapCommitted, nonHeapUsed, gcPauseMax, gcPauseCount, gcPauseTotal, threadsLive, threadsPeak, threadsDaemon, classes, uptime, cpuUsage, cpuCount, memPromoted, memAllocated;
    try {
      heapUsed = val(await meter(ctx, pod, "jvm.memory.used", ["area:heap"]));
      heapMax = val(await meter(ctx, pod, "jvm.memory.max", ["area:heap"]));
      heapCommitted = val(await meter(ctx, pod, "jvm.memory.committed", ["area:heap"]));
      nonHeapUsed = val(await meter(ctx, pod, "jvm.memory.used", ["area:nonheap"]));
      const gc = await meter(ctx, pod, "jvm.gc.pause");
      gcPauseMax = val(gc, "MAX");
      gcPauseCount = val(gc, "COUNT");
      gcPauseTotal = val(gc, "TOTAL_TIME");
      threadsLive = val(await meter(ctx, pod, "jvm.threads.live"));
      threadsPeak = val(await meter(ctx, pod, "jvm.threads.peak"));
      threadsDaemon = val(await meter(ctx, pod, "jvm.threads.daemon"));
      classes = val(await meter(ctx, pod, "jvm.classes.loaded"));
      uptime = val(await meter(ctx, pod, "process.uptime"));
      cpuUsage = val(await meter(ctx, pod, "process.cpu.usage"));
      cpuCount = val(await meter(ctx, pod, "system.cpu.count"));
      memPromoted = val(await meter(ctx, pod, "jvm.gc.memory.promoted"), "COUNT");
      memAllocated = val(await meter(ctx, pod, "jvm.gc.memory.allocated"), "COUNT");
    } catch (err) {
      rows.push({ pod: pod.metadata?.name, error: err instanceof Error ? err.message : String(err) });
      continue;
    }
    if (heapUsed === undefined) {
      rows.push({ pod: pod.metadata?.name, available: false, note: "no jvm.* meters from Actuator (probe missing, Actuator not enabled, or not a JVM)" });
      continue;
    }
    const container = pod.spec?.containers?.find((c) => c.name !== ctx.config.probeContainerName);
    const limit = memoryBytes(container?.resources?.limits?.memory);
    const heapPct = heapMax && heapMax > 0 ? Math.round((heapUsed / heapMax) * 100) : undefined;
    if (heapPct !== undefined && heapPct > 85) findings.push(`heap ${heapPct}% of max after GC pressure - leak or undersized heap`);
    if (limit && heapMax && heapMax > 0 && heapMax + (nonHeapUsed ?? 0) > limit * 0.9) findings.push(`heap max (${humanBytes(heapMax)}) + non-heap (${humanBytes(nonHeapUsed)}) exceeds 90% of the container limit (${humanBytes(limit)}) - OOMKill risk regardless of heap health`);
    if (gcPauseMax !== undefined && gcPauseMax > 1) findings.push(`GC pause max ${(gcPauseMax * 1000).toFixed(0)}ms`);
    if (gcPauseTotal !== undefined && uptime && gcPauseTotal / uptime > 0.05) findings.push(`${((gcPauseTotal / uptime) * 100).toFixed(1)}% of uptime spent in GC pauses`);
    if (threadsLive !== undefined && threadsLive > 500) findings.push(`${threadsLive} live threads`);
    if (cpuCount !== undefined && cpuCount < 2) findings.push(`JVM sees ${cpuCount} CPU - SerialGC by default and a single-threaded JIT/GC; give it >= 2 CPUs`);
    rows.push({
      pod: pod.metadata?.name,
      available: true,
      uptime: uptime !== undefined ? `${Math.round(uptime / 60)}m` : undefined,
      heap: { used: humanBytes(heapUsed), committed: humanBytes(heapCommitted), max: heapMax && heapMax > 0 ? humanBytes(heapMax) : "unbounded/unknown", pctOfMax: heapPct },
      nonHeap: humanBytes(nonHeapUsed),
      containerLimit: humanBytes(limit),
      gc: { pauseCount: gcPauseCount, pauseTotalSeconds: gcPauseTotal !== undefined ? Number(gcPauseTotal.toFixed(2)) : undefined, pauseMaxMs: gcPauseMax !== undefined ? Math.round(gcPauseMax * 1000) : undefined, allocated: humanBytes(memAllocated), promoted: humanBytes(memPromoted) },
      threads: { live: threadsLive, peak: threadsPeak, daemon: threadsDaemon },
      classesLoaded: classes,
      cpu: { processUsage: cpuUsage !== undefined ? `${(cpuUsage * 100).toFixed(1)}%` : undefined, availableProcessors: cpuCount },
      findings,
    });
  }
  return { namespace: ns, jvms: rows };
}

interface ThreadInfo {
  threadName: string;
  threadState: string;
  lockName?: string;
  lockOwnerName?: string;
  stackTrace?: Array<{ className: string; methodName: string; lineNumber?: number }>;
  lockedMonitors?: Array<{ className: string }>;
}

export function summarizeThreadDump(threads: ThreadInfo[]) {
  const byState: Record<string, number> = {};
  const pools = new Map<string, { total: number; busy: number }>();
  const blockedOn = new Map<string, { count: number; owner?: string }>();
  const signatures = new Map<string, { count: number; states: Set<string>; example: string }>();
  const isAppFrame = (c: string) => !/^(java\.|javax\.|jakarta\.|sun\.|jdk\.|org\.springframework\.|org\.apache\.(tomcat|coyote|catalina)|com\.zaxxer\.|io\.netty\.|reactor\.|org\.hibernate\.|kotlin\.)/.test(c);
  for (const t of threads) {
    byState[t.threadState] = (byState[t.threadState] ?? 0) + 1;
    const poolName = t.threadName.replace(/[-_ ]?\d+$/, "").replace(/\[.*$/, "");
    const pool = pools.get(poolName) ?? { total: 0, busy: 0 };
    pool.total++;
    if (t.threadState === "RUNNABLE" || t.threadState === "BLOCKED") pool.busy++;
    pools.set(poolName, pool);
    if (t.threadState === "BLOCKED" && t.lockName) {
      const b = blockedOn.get(t.lockName) ?? { count: 0, owner: t.lockOwnerName };
      b.count++;
      blockedOn.set(t.lockName, b);
    }
    const frames = t.stackTrace ?? [];
    const top = frames.find((f) => isAppFrame(f.className)) ?? frames[0];
    if (top && t.threadState !== "WAITING" && t.threadState !== "TIMED_WAITING") {
      const sig = `${top.className}.${top.methodName}`;
      const s = signatures.get(sig) ?? { count: 0, states: new Set(), example: t.threadName };
      s.count++;
      s.states.add(t.threadState);
      signatures.set(sig, s);
    }
  }
  // Deadlock: A blocked on lock owned by B, B blocked on lock owned by A.
  const ownerOf = new Map<string, string>();
  for (const t of threads) for (const m of t.lockedMonitors ?? []) ownerOf.set(m.className, t.threadName);
  const waits = new Map<string, string>();
  for (const t of threads) if (t.threadState === "BLOCKED" && t.lockOwnerName) waits.set(t.threadName, t.lockOwnerName);
  const deadlocks: string[][] = [];
  const seen = new Set<string>();
  for (const [start] of waits) {
    if (seen.has(start)) continue;
    const chain = [start];
    let cur = waits.get(start);
    while (cur && !chain.includes(cur) && chain.length < 20) {
      chain.push(cur);
      cur = waits.get(cur);
    }
    if (cur && chain.includes(cur)) {
      const cycle = chain.slice(chain.indexOf(cur));
      cycle.forEach((c) => seen.add(c));
      deadlocks.push(cycle);
    }
  }
  const findings: string[] = [];
  for (const d of deadlocks) findings.push(`DEADLOCK: ${d.join(" -> ")} -> ${d[0]}`);
  for (const [pool, p] of pools) if (p.total >= 8 && p.busy >= p.total * 0.9) findings.push(`pool "${pool}" saturated: ${p.busy}/${p.total} busy - requests queue; raise pool size or fix the slow path below`);
  for (const [lock, b] of blockedOn) if (b.count >= 5) findings.push(`${b.count} threads BLOCKED on ${lock}${b.owner ? ` held by ${b.owner}` : ""} - lock contention`);
  const hot = [...signatures.entries()].sort((a, b) => b[1].count - a[1].count).slice(0, 10);
  for (const [sig, s] of hot.slice(0, 3)) if (s.count >= 5 && s.states.has("RUNNABLE")) findings.push(`${s.count} threads in ${sig} - hot spot`);
  return {
    total: threads.length,
    byState,
    pools: [...pools.entries()].filter(([, p]) => p.total >= 2).map(([name, p]) => ({ name, total: p.total, busy: p.busy })).sort((a, b) => b.total - a.total).slice(0, 20),
    blockedOn: [...blockedOn.entries()].map(([lock, b]) => ({ lock, count: b.count, owner: b.owner })).sort((a, b) => b.count - a.count).slice(0, 10),
    topStacks: hot.map(([signature, s]) => ({ signature, count: s.count, states: [...s.states], exampleThread: s.example })),
    deadlocks,
    findings,
  };
}

export async function getThreadDumpSummary(ctx: ToolContext, args: { namespace?: string; service?: string; pod?: string }) {
  const ns = nsOf(ctx, args.namespace);
  const pods = await runningPods(ctx, ns, args);
  const pod = pods[0];
  if (!pod) throw new Error("no running pod");
  const r = await ctx.probe.actuator(pod, "threaddump");
  if (!r.available || r.status !== 200) return { pod: pod.metadata?.name, available: false, note: r.note ?? `actuator/threaddump returned ${r.status}` };
  const threads = ((r.body as { threads?: ThreadInfo[] })?.threads ?? []) as ThreadInfo[];
  return { pod: pod.metadata?.name, namespace: ns, ...summarizeThreadDump(threads), note: "Summary only; the raw dump (thread names, full stacks) is not returned to keep output compact and free of request data." };
}

export async function getConnectionPoolStatus(ctx: ToolContext, args: { namespace?: string; service?: string; pod?: string }) {
  const ns = nsOf(ctx, args.namespace);
  const pods = await runningPods(ctx, ns, args);
  const rows = [];
  for (const pod of pods.slice(0, 10)) {
    const active = val(await meter(ctx, pod, "hikaricp.connections.active"));
    if (active === undefined) {
      rows.push({ pod: pod.metadata?.name, available: false, note: "no hikaricp.* meters (not HikariCP, or Actuator/probe unavailable)" });
      continue;
    }
    const idle = val(await meter(ctx, pod, "hikaricp.connections.idle"));
    const pending = val(await meter(ctx, pod, "hikaricp.connections.pending"));
    const max = val(await meter(ctx, pod, "hikaricp.connections.max"));
    const min = val(await meter(ctx, pod, "hikaricp.connections.min"));
    const total = val(await meter(ctx, pod, "hikaricp.connections"));
    const timeouts = val(await meter(ctx, pod, "hikaricp.connections.timeout"), "COUNT");
    const acq = await meter(ctx, pod, "hikaricp.connections.acquire");
    const usage = await meter(ctx, pod, "hikaricp.connections.usage");
    const creation = await meter(ctx, pod, "hikaricp.connections.creation");
    const findings: string[] = [];
    if (max && active >= max) findings.push(`pool EXHAUSTED: ${active}/${max} active, ${pending ?? 0} threads waiting - requests block until a connection frees (see get_thread_dump_summary for who holds them, and the DB's get_active_queries/get_blocking_locks).`);
    else if (max && active >= max * 0.8) findings.push(`pool at ${Math.round((active / max) * 100)}% (${active}/${max})`);
    if ((pending ?? 0) > 0) findings.push(`${pending} threads waiting for a connection`);
    if ((timeouts ?? 0) > 0) findings.push(`${timeouts} connection acquisition timeouts since start`);
    const acqMax = val(acq, "MAX");
    if (acqMax !== undefined && acqMax > 1) findings.push(`max acquire time ${(acqMax * 1000).toFixed(0)}ms`);
    const usageMean = val(usage, "TOTAL_TIME") && val(usage, "COUNT") ? val(usage, "TOTAL_TIME")! / val(usage, "COUNT")! : undefined;
    if (usageMean !== undefined && usageMean > 1) findings.push(`connections are held ${(usageMean * 1000).toFixed(0)}ms on average - long transactions or slow queries hold the pool`);
    rows.push({
      pod: pod.metadata?.name,
      available: true,
      pool: { active, idle, pending, total, max, min },
      acquireMs: { mean: acq && val(acq, "COUNT") ? Math.round((val(acq, "TOTAL_TIME")! / val(acq, "COUNT")!) * 1000) : undefined, max: acqMax !== undefined ? Math.round(acqMax * 1000) : undefined },
      usageMs: { mean: usageMean !== undefined ? Math.round(usageMean * 1000) : undefined, max: val(usage, "MAX") !== undefined ? Math.round(val(usage, "MAX")! * 1000) : undefined },
      creationMs: { mean: creation && val(creation, "COUNT") ? Math.round((val(creation, "TOTAL_TIME")! / val(creation, "COUNT")!) * 1000) : undefined },
      timeouts,
      findings,
    });
  }
  return { namespace: ns, pools: rows, tip: "Pair with postgres-readonly-mcp: get_active_queries / get_blocking_locks / get_connection_usage show the same problem from the database side." };
}

export async function getEndpointMetrics(ctx: ToolContext, args: { namespace?: string; service: string; window?: string }) {
  return getGoldenSignals(ctx, args);
}

export async function getOutboundClientMetrics(ctx: ToolContext, args: { namespace?: string; service?: string; pod?: string }) {
  const ns = nsOf(ctx, args.namespace);
  const pods = await runningPods(ctx, ns, args);
  const byTarget = new Map<string, { count: number; total: number; max: number; errors: number }>();
  let any = false;
  for (const pod of pods.slice(0, 10)) {
    const m = await meter(ctx, pod, "http.client.requests");
    if (!m) continue;
    any = true;
    const targets = m.availableTags?.find((t) => t.tag === "clientName")?.values ?? [];
    for (const target of targets.slice(0, 30)) {
      const tm = await meter(ctx, pod, "http.client.requests", [`clientName:${target}`]);
      const em = await meter(ctx, pod, "http.client.requests", [`clientName:${target}`, "outcome:SERVER_ERROR"]);
      const e = byTarget.get(target) ?? { count: 0, total: 0, max: 0, errors: 0 };
      e.count += val(tm, "COUNT") ?? 0;
      e.total += val(tm, "TOTAL_TIME") ?? 0;
      e.max = Math.max(e.max, val(tm, "MAX") ?? 0);
      e.errors += val(em, "COUNT") ?? 0;
      byTarget.set(target, e);
    }
  }
  if (!any) return { namespace: ns, available: false, note: "no http.client.requests meter - the service uses no instrumented HTTP client (RestTemplate/WebClient/RestClient via Spring's builders are instrumented automatically)." };
  const rows = [...byTarget.entries()].map(([target, e]) => ({ target, requests: e.count, meanMs: e.count ? Math.round((e.total / e.count) * 1000) : undefined, maxMs: Math.round(e.max * 1000), errorRate: e.count ? e.errors / e.count : 0 })).sort((a, b) => (b.meanMs ?? 0) - (a.meanMs ?? 0));
  return { namespace: ns, downstreams: rows, findings: rows.filter((r) => (r.meanMs ?? 0) > 500 || r.errorRate > 0.05).map((r) => `${r.target}: mean ${r.meanMs}ms, ${(r.errorRate * 100).toFixed(1)}% errors`), note: "cumulative since JVM start" };
}

export async function getActuatorHealth(ctx: ToolContext, args: { namespace?: string; service?: string; pod?: string }) {
  const ns = nsOf(ctx, args.namespace);
  const pods = await runningPods(ctx, ns, args);
  const rows = [];
  for (const pod of pods.slice(0, 10)) {
    try {
      const r = await ctx.probe.actuator(pod, "health");
      const body = r.body as { status?: string; components?: Record<string, { status?: string; details?: Record<string, unknown> }> } | undefined;
      const components = Object.entries(body?.components ?? {}).map(([name, c]) => ({ name, status: c.status, details: c.status !== "UP" ? c.details : undefined }));
      rows.push({ pod: pod.metadata?.name, httpStatus: r.status, status: body?.status, components, down: components.filter((c) => c.status && c.status !== "UP").map((c) => c.name) });
    } catch (err) {
      rows.push({ pod: pod.metadata?.name, error: err instanceof Error ? err.message : String(err) });
    }
  }
  return { namespace: ns, health: rows };
}

export async function getJvmConfig(ctx: ToolContext, args: { namespace?: string; service: string }) {
  const ns = nsOf(ctx, args.namespace);
  const w = await resolveWorkload(ctx.k8s, ns, args.service);
  const cms = await ctx.k8s.listConfigMaps(ns);
  const cmData = new Map(cms.map((c) => [c.metadata?.name ?? "", c.data ?? {}]));
  const containers = w.containers.filter((c) => c.name !== ctx.config.probeContainerName).map((c) => {
    const env = describeEnv(c.env, cmData);
    const jvmOpts = env.filter((e) => /^(JAVA_TOOL_OPTIONS|JAVA_OPTS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS|CATALINA_OPTS)$/.test(e.name));
    const spring = env.filter((e) => /^(SPRING_|SERVER_|MANAGEMENT_|LOGGING_)/.test(e.name));
    return { container: c.name, image: c.image, resources: c.resources, jvmOptions: jvmOpts, springEnv: spring, findings: jvmFindings(c, env) };
  });
  let info;
  const pod = w.pods.find((p) => p.status?.phase === "Running");
  if (pod) {
    try {
      const r = await ctx.probe.actuator(pod, "info");
      info = r.body;
    } catch {
      /* no probe */
    }
  }
  return { workload: `${w.kind}/${w.name}`, namespace: ns, containers, actuatorInfo: info };
}

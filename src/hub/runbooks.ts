/**
 * Composed runbooks: the tools that answer a question rather than return a
 * resource. Each collects evidence from the primitives, then ranks
 * hypotheses. Every hypothesis names the evidence and the tool to dig deeper.
 */
import type { ToolContext } from "./context.js";
import { nsOf } from "./context.js";
import { resolveWorkload, summarizePod } from "./model.js";
import { getEvents, getPodStatus, whatChanged } from "./tools/health.js";
import { summarizeLogErrors } from "./tools/logs.js";
import { getResourcePressure, getGoldenSignals, getHpaStatus, getNodePressure } from "./tools/performance.js";
import { getEndpoints, getNetworkPolicies } from "./tools/network.js";
import { getConfig } from "./tools/config.js";
import { getJvmHealth, getConnectionPoolStatus, getThreadDumpSummary, getOutboundClientMetrics } from "./tools/java.js";
import { summarizeAccessLog, getStaticBundleStats, getProxyConfigSummary } from "./tools/proxy.js";
import { getWebVitals, getPageLoadBreakdown, getBrowserApiLatency } from "./tools/rum.js";
import { securityPosture } from "./tools/security.js";
import { getTlsStatus } from "./tools/security.js";

export interface Hypothesis {
  rank: number;
  confidence: "high" | "medium" | "low";
  title: string;
  evidence: string[];
  nextStep: string;
}

type Step<T> = { name: string; result?: T; error?: string; ms: number };

async function step<T>(name: string, fn: () => Promise<T>): Promise<Step<T>> {
  const t = Date.now();
  try {
    return { name, result: await fn(), ms: Date.now() - t };
  } catch (err) {
    return { name, error: err instanceof Error ? err.message : String(err), ms: Date.now() - t };
  }
}

function rank(hs: Omit<Hypothesis, "rank">[]): Hypothesis[] {
  const order = { high: 0, medium: 1, low: 2 };
  // Stable: within a confidence level, runbook order (insertion order) is the priority.
  return hs.sort((a, b) => order[a.confidence] - order[b.confidence]).map((h, i) => ({ rank: i + 1, ...h }));
}

export async function diagnoseService(ctx: ToolContext, args: { namespace?: string; service: string; window?: string }) {
  const ns = nsOf(ctx, args.namespace);
  const w = await resolveWorkload(ctx.k8s, ns, args.service);
  const window = args.window ?? "30m";
  const [status, events, pressure, changed, endpoints, config, golden, logs, jvm, pool, outbound] = await Promise.all([
    step("pod status", () => getPodStatus(ctx, { namespace: ns, service: w.name })),
    step("events", () => getEvents(ctx, { namespace: ns, since: "2h", object: w.name })),
    step("resource pressure", () => getResourcePressure(ctx, { namespace: ns, service: w.name })),
    step("what changed", () => whatChanged(ctx, { namespace: ns, service: w.name, since: "24h" })),
    step("endpoints", () => getEndpoints(ctx, { namespace: ns })),
    step("config", () => getConfig(ctx, { namespace: ns, service: w.name })),
    step("golden signals", () => getGoldenSignals(ctx, { namespace: ns, service: w.name, window })),
    step("log errors", () => summarizeLogErrors(ctx, { namespace: ns, service: w.name, since: window })),
    step("jvm", () => getJvmHealth(ctx, { namespace: ns, service: w.name })),
    step("connection pool", () => getConnectionPoolStatus(ctx, { namespace: ns, service: w.name })),
    step("outbound calls", () => getOutboundClientMetrics(ctx, { namespace: ns, service: w.name })),
  ]);

  const hs: Omit<Hypothesis, "rank">[] = [];
  const pods = (status.result && "pods" in status.result ? status.result.pods : undefined) ?? [];
  const problems = pods.flatMap((p) => p.problems.map((x) => `${p.name}: ${x}`));

  // 1. Crash / OOM / scheduling
  const oom = problems.filter((p) => /OOMKilled/.test(p));
  if (oom.length) hs.push({ confidence: "high", title: "Container is being OOM-killed", evidence: oom, nextStep: "get_resource_pressure + get_jvm_health: compare heap max vs memory limit; raise the limit or cap the heap (MaxRAMPercentage)." });
  const crash = problems.filter((p) => /CrashLoopBackOff|exited with code|Error/.test(p) && !/OOMKilled/.test(p));
  if (crash.length) hs.push({ confidence: "high", title: "Container crashes on start (CrashLoopBackOff)", evidence: crash, nextStep: "get_logs with previous=true on the crashing pod; check get_config for a missing ConfigMap/Secret or bad env." });
  const sched = problems.filter((p) => /Unschedulable|Pending|FailedScheduling/.test(p));
  if (sched.length) hs.push({ confidence: "high", title: "Pods cannot be scheduled", evidence: sched, nextStep: "get_node_pressure: insufficient CPU/memory, taints, or a PVC that cannot bind." });
  // Probe failures: ignore the diagnostics sidecar's own readiness port and one-off "connection refused" during startup.
  const probePort = `:${ctx.config.probePort}/`;
  const probeFail = (events.result?.events ?? []).filter((e) => e.reason === "Unhealthy" && !(e.message ?? "").includes(probePort) && (e.count >= 3 || /statuscode|timeout|deadline/i.test(e.message ?? "")));
  if (probeFail.length) hs.push({ confidence: probeFail.some((e) => /Liveness/.test(e.message ?? "")) ? "high" : "medium", title: probeFail.some((e) => /Liveness/.test(e.message ?? "")) ? "Liveness probe failing (container will be restarted)" : "Readiness probe failing (pod removed from Service endpoints)", evidence: probeFail.map((e) => `${e.object}: ${e.message} (x${e.count})`), nextStep: "get_config -> probes: is the path/port right? Is initialDelay long enough for a JVM start? get_actuator_health for the real health state." });
  const imgPull = problems.filter((p) => /ImagePull|ErrImage/.test(p));
  if (imgPull.length) hs.push({ confidence: "high", title: "Image cannot be pulled", evidence: imgPull, nextStep: "check the tag exists and imagePullSecrets; get_image_inventory." });

  // 2. Endpoints / networking
  const epProblems = (endpoints.result?.problems ?? []).filter((p) => p.startsWith(w.name) || (endpoints.result?.services ?? []).some((s) => s.service === w.name && p.startsWith(s.service)));
  if (epProblems.length) hs.push({ confidence: "high", title: "Service has no ready endpoints (traffic cannot reach the pods)", evidence: epProblems, nextStep: "fix the selector/targetPort or the readiness probe; get_endpoints." });

  // 3. Saturation
  const pf = pressure.result?.findings ?? [];
  const cpu = pf.filter((f) => /CPU|throttl/.test(f));
  if (cpu.length) hs.push({ confidence: "high", title: "CPU throttling / saturation", evidence: cpu, nextStep: "raise the CPU limit (or remove it and keep the request); compare_replicas to see if one pod is hot." });
  const mem = pf.filter((f) => /memory/.test(f) && !/OOMKilled/.test(f));
  if (mem.length) hs.push({ confidence: "medium", title: "Memory near limit", evidence: mem, nextStep: "get_jvm_health (heap vs limit), watch for OOMKill." });

  // 4. JVM
  const jvmFindings = (jvm.result?.jvms ?? []).flatMap((j) => ("findings" in j ? (j.findings as string[]).map((f) => `${j.pod}: ${f}`) : []));
  const jvmSizing = jvmFindings.filter((f) => /container limit|CPU/.test(f));
  const jvmRuntime = jvmFindings.filter((f) => !/container limit|CPU/.test(f));
  if (jvmSizing.length) hs.push({ confidence: oom.length ? "high" : "medium", title: "JVM is sized larger than its container (OOMKill risk) or starved of CPU", evidence: jvmSizing, nextStep: "get_jvm_config: set -XX:MaxRAMPercentage (or -Xmx) so heap + metaspace + threads fit the limit; give the JVM >= 2 CPUs." });
  if (jvmRuntime.length) hs.push({ confidence: "medium", title: "JVM memory/GC pressure", evidence: jvmRuntime, nextStep: "get_thread_dump_summary during the slow period; tune heap/GC; check get_jvm_config." });
  const poolFindings = (pool.result?.pools ?? []).flatMap((p) => ("findings" in p ? (p.findings as string[]).map((f) => `${p.pod}: ${f}`) : []));
  if (poolFindings.some((f) => /EXHAUSTED|waiting/.test(f))) hs.push({ confidence: "high", title: "Database connection pool exhausted", evidence: poolFindings, nextStep: "postgres-readonly-mcp get_active_queries / get_blocking_locks to see what holds connections; get_thread_dump_summary for threads blocked in getConnection; shorten transactions or raise maximum-pool-size." });
  else if (poolFindings.length) hs.push({ confidence: "medium", title: "Database connection pool under pressure", evidence: poolFindings, nextStep: "get_connection_pool_status over time; check slow queries on the DB side." });
  const slowDown = outbound.result && "findings" in outbound.result ? (outbound.result.findings as string[]) : [];
  if (slowDown.length) hs.push({ confidence: "medium", title: "A downstream dependency is slow or failing", evidence: slowDown, nextStep: "diagnose_service on the downstream service; check_connectivity from this pod to it." });

  // 5. Errors in logs
  const lg = logs.result?.groups ?? [];
  const topErr = lg.filter((g) => g.level === "ERROR").slice(0, 5);
  if (topErr.length) hs.push({ confidence: topErr[0].count > 20 ? "medium" : "low", title: "Application errors in logs", evidence: topErr.map((g) => `${g.count}x ${g.signature}`), nextStep: "get_logs with grep for the signature; correlate timestamps with what_changed." });
  // 6. Golden signals
  const gf = golden.result && "findings" in golden.result ? (golden.result.findings as string[]) : [];
  if (gf.length) hs.push({ confidence: "medium", title: "Elevated latency / error rate at the service", evidence: gf, nextStep: "get_endpoint_metrics for the worst endpoint; summarize_access_log at the proxy for the user-facing view." });
  // 7. Recent change
  const ch = (changed.result?.changes ?? []).filter((c) => /^rollout$|configmap|hpa/.test(c.kind)).slice(0, 5);
  const recent = ch.some((c) => Date.now() - Date.parse(c.time) < 2 * 3600_000);
  if (ch.length && hs.length) hs.push({ confidence: recent ? "medium" : "low", title: recent ? "A change in the last 2 hours may have introduced the problem" : "Changes in the window (older than 2 hours)", evidence: ch.map((c) => `${c.time} ${c.kind} ${c.object}: ${c.detail}`), nextStep: "get_rollout_history to see the diff; consider rolling back to the previous revision." });
  // 8. Config smells
  const cf = (config.result?.findings ?? []).filter((f) => /Xmx|MaxRAMPercentage|no readiness|no resource requests|missing/.test(f));
  if (cf.length) hs.push({ confidence: "low", title: "Configuration smells that cause exactly these symptoms", evidence: cf, nextStep: "get_config for the full picture." });

  if (!hs.length) hs.push({ confidence: "low", title: "No obvious fault found in the last window", evidence: [`${pods.length} pods, ${pods.filter((p) => p.ready.split("/")[0] === p.ready.split("/")[1]).length} fully ready`, `${lg.length} distinct error signatures`, golden.result && "requestRate" in golden.result ? `request rate ${(golden.result.requestRate as number)?.toFixed(2)}/s` : "no golden signals source"], nextStep: "widen the window, check summarize_access_log at the proxy, or diagnose the downstream dependencies." });

  return {
    workload: `${w.kind}/${w.name}`,
    namespace: ns,
    window,
    hypotheses: rank(hs),
    snapshot: { pods: pods.map((p) => ({ name: p.name, ready: p.ready, restarts: p.restarts, node: p.node })), replicas: w.desiredReplicas !== undefined ? `${w.readyReplicas}/${w.desiredReplicas}` : undefined },
    stepsRun: [status, events, pressure, changed, endpoints, config, golden, logs, jvm, pool, outbound].map((s) => ({ step: s.name, ok: !s.error, ms: s.ms, error: s.error })),
  };
}

export async function diagnoseSlowRequests(ctx: ToolContext, args: { namespace?: string; service: string; window?: string; proxy_service?: string }) {
  const ns = nsOf(ctx, args.namespace);
  const w = await resolveWorkload(ctx.k8s, ns, args.service);
  const window = args.window ?? "30m";
  const [golden, pressure, jvm, pool, outbound, threads, access] = await Promise.all([
    step("golden signals", () => getGoldenSignals(ctx, { namespace: ns, service: w.name, window })),
    step("resource pressure", () => getResourcePressure(ctx, { namespace: ns, service: w.name })),
    step("jvm", () => getJvmHealth(ctx, { namespace: ns, service: w.name })),
    step("connection pool", () => getConnectionPoolStatus(ctx, { namespace: ns, service: w.name })),
    step("outbound", () => getOutboundClientMetrics(ctx, { namespace: ns, service: w.name })),
    step("thread dump", () => getThreadDumpSummary(ctx, { namespace: ns, service: w.name })),
    args.proxy_service ? step("access log", () => summarizeAccessLog(ctx, { namespace: ns, service: args.proxy_service!, since: window })) : Promise.resolve<Step<unknown>>({ name: "access log", ms: 0, error: "no proxy_service given" }),
  ]);
  const hs: Omit<Hypothesis, "rank">[] = [];
  const g = golden.result && "byEndpoint" in golden.result ? golden.result : undefined;
  const slowEps = (g?.byEndpoint ?? []).filter((e) => (e.p95Ms ?? 0) > 1000).slice(0, 5);
  if (slowEps.length) hs.push({ confidence: "high", title: "Specific endpoints are slow (not the whole service)", evidence: slowEps.map((e) => `${e.method ?? ""} ${e.endpoint}: p95 ${e.p95Ms}ms @ ${e.requestRate.toFixed(2)}/s`), nextStep: "look at those handlers: N+1 queries (get_slow_statements on postgres-readonly-mcp), remote calls (get_outbound_client_metrics)." });
  const pf = (pressure.result?.findings ?? []).filter((f) => /CPU|throttl/.test(f));
  if (pf.length) hs.push({ confidence: "high", title: "CPU throttling adds latency to every request", evidence: pf, nextStep: "raise/remove the CPU limit; check GC (get_jvm_health)." });
  const poolF = (pool.result?.pools ?? []).flatMap((p) => ("findings" in p ? (p.findings as string[]) : []));
  if (poolF.length) hs.push({ confidence: "high", title: "Waiting for database connections", evidence: poolF, nextStep: "get_active_queries / get_blocking_locks on the DB; shorten transactions." });
  const tf = threads.result && "findings" in threads.result ? (threads.result.findings as string[]) : [];
  if (tf.length) hs.push({ confidence: "high", title: "Thread pool saturation / lock contention / deadlock", evidence: tf, nextStep: "get_thread_dump_summary -> topStacks shows where threads are stuck." });
  const jf = (jvm.result?.jvms ?? []).flatMap((j) => ("findings" in j ? (j.findings as string[]) : []));
  if (jf.some((f) => /GC/.test(f))) hs.push({ confidence: "medium", title: "GC pauses", evidence: jf.filter((f) => /GC|heap/.test(f)), nextStep: "raise heap or reduce allocation; G1/ZGC; >= 2 CPUs." });
  const of = outbound.result && "findings" in outbound.result ? (outbound.result.findings as string[]) : [];
  if (of.length) hs.push({ confidence: "medium", title: "Slow downstream dependency", evidence: of, nextStep: "diagnose_slow_requests on that dependency." });
  const af = (access.result as { pods?: Array<{ findings?: string[] }> } | undefined)?.pods?.flatMap((p) => p.findings ?? []) ?? [];
  if (af.some((f) => /504|499/.test(f))) hs.push({ confidence: "high", title: "Users see timeouts at the proxy", evidence: af.filter((f) => /504|499|gap/.test(f)), nextStep: "get_proxy_config_summary: proxy_read_timeout vs the endpoint's real latency." });
  if (!hs.length) hs.push({ confidence: "low", title: "No saturation signal found; latency may be in the request path itself", evidence: [g?.latencyMs ? `service latency p50 ${g.latencyMs.p50}ms p99 ${g.latencyMs.p99}ms` : "no golden signals"], nextStep: "find_slow_traces once a tracing provider is configured; otherwise summarize_access_log per path." });
  return { workload: `${w.kind}/${w.name}`, namespace: ns, window, hypotheses: rank(hs), stepsRun: [golden, pressure, jvm, pool, outbound, threads, access].map((s) => ({ step: s.name, ok: !s.error, ms: s.ms, error: s.error })) };
}

export async function diagnoseSlowPage(ctx: ToolContext, args: { namespace?: string; route: string; proxy_service?: string; api_service?: string }) {
  const ns = nsOf(ctx, args.namespace);
  const [vitals, nav, api, bundle, proxyConf, access, golden] = await Promise.all([
    step("web vitals", () => getWebVitals(ctx, { namespace: ns, service: args.proxy_service, route: args.route })),
    step("page load", () => getPageLoadBreakdown(ctx, { namespace: ns, service: args.proxy_service, route: args.route })),
    step("browser api latency", () => getBrowserApiLatency(ctx, { namespace: ns, service: args.proxy_service, route: args.route })),
    args.proxy_service ? step("bundle", () => getStaticBundleStats(ctx, { namespace: ns, service: args.proxy_service! })) : Promise.resolve<Step<unknown>>({ name: "bundle", ms: 0, error: "no proxy_service" }),
    args.proxy_service ? step("proxy config", () => getProxyConfigSummary(ctx, { namespace: ns, service: args.proxy_service! })) : Promise.resolve<Step<unknown>>({ name: "proxy config", ms: 0, error: "no proxy_service" }),
    args.proxy_service ? step("access log", () => summarizeAccessLog(ctx, { namespace: ns, service: args.proxy_service!, since: "30m" })) : Promise.resolve<Step<unknown>>({ name: "access log", ms: 0, error: "no proxy_service" }),
    args.api_service ? step("api golden signals", () => getGoldenSignals(ctx, { namespace: ns, service: args.api_service! })) : Promise.resolve<Step<unknown>>({ name: "api golden signals", ms: 0, error: "no api_service" }),
  ]);
  const hs: Omit<Hypothesis, "rank">[] = [];
  const v = (vitals.result as { routes?: Array<{ route: string; metrics: Record<string, { p75: number; rating: string; samples: number }> }> } | undefined)?.routes?.[0];
  const m = v?.metrics ?? {};
  const navF = (nav.result as { routes?: Array<{ findings: string[] }> } | undefined)?.routes?.[0]?.findings ?? [];
  const apiF = (api.result as { findings?: string[] } | undefined)?.findings ?? [];
  const bundleF = (bundle.result as { findings?: string[] } | undefined)?.findings ?? [];
  const confF = ((proxyConf.result as { configs?: Array<{ findings: string[] }> } | undefined)?.configs ?? []).flatMap((c) => c.findings);
  const accF = ((access.result as { pods?: Array<{ findings?: string[] }> } | undefined)?.pods ?? []).flatMap((p) => p.findings ?? []);
  const gF = (golden.result as { findings?: string[] } | undefined)?.findings ?? [];

  if (m.TTFB?.rating === "poor" || navF.some((f) => /TTFB/.test(f))) hs.push({ confidence: "high", title: "Slow first byte: the server/proxy is slow before any rendering starts", evidence: [m.TTFB ? `TTFB p75 ${m.TTFB.p75}ms` : "", ...navF.filter((f) => /TTFB/.test(f)), ...accF.filter((f) => /504|499|gap|p95/.test(f))].filter(Boolean), nextStep: "summarize_access_log for /, get_proxy_status; if index.html is served fast, the proxy is fine and the API calls are the problem." });
  if (m.LCP?.rating === "poor" && m.TTFB?.rating !== "poor") hs.push({ confidence: "high", title: "Slow LCP with a fast TTFB: render-side (bundle size, hero image, blocking API call)", evidence: [`LCP p75 ${m.LCP.p75}ms`, ...bundleF, ...navF.filter((f) => /JS parse|bundle/.test(f))], nextStep: "get_static_bundle_stats; lazy-load routes; size/compress the LCP image; preload it." });
  if (apiF.length) hs.push({ confidence: "high", title: "API calls on this route are slow from the browser", evidence: [...apiF, ...gF], nextStep: gF.length ? "the service itself is slow: diagnose_slow_requests on the API service" : "service-side metrics look fine: the time is in the network/proxy - get_proxy_config_summary (buffering, timeouts) and summarize_access_log gap." });
  if (m.CLS?.rating === "poor") hs.push({ confidence: "medium", title: "Layout shift: images/ads/fonts without reserved space", evidence: [`CLS p75 ${m.CLS.p75}`], nextStep: "set width/height on images, font-display: optional, reserve space for async content." });
  if (m.INP?.rating === "poor") hs.push({ confidence: "medium", title: "Slow interactions: long tasks on the main thread", evidence: [`INP p75 ${m.INP.p75}ms`], nextStep: "profile the route's handlers; move work off ngOnInit / into web workers; OnPush change detection." });
  if (confF.some((f) => /Cache-Control|gzip|index.html/.test(f))) hs.push({ confidence: "medium", title: "Proxy caching/compression misconfiguration makes every load slower than it needs to be", evidence: confF.filter((f) => /Cache-Control|gzip|index.html|source/.test(f)), nextStep: "get_proxy_config_summary; add immutable caching for hashed chunks, no-cache for index.html, gzip/brotli on." });
  if (!hs.length) hs.push({ confidence: "low", title: v ? "Vitals for this route are within thresholds" : "No RUM data for this route", evidence: v ? Object.entries(m).map(([k, x]) => `${k} p75 ${x.p75} (${x.rating}, n=${x.samples})`) : [(vitals.result as { note?: string } | undefined)?.note ?? "no data"], nextStep: v ? "compare with other routes via get_web_vitals" : "install the RUM client and probe on the proxy pod." });
  return { route: args.route, namespace: ns, vitals: m, hypotheses: rank(hs), stepsRun: [vitals, nav, api, bundle, proxyConf, access, golden].map((s) => ({ step: s.name, ok: !s.error, ms: s.ms, error: s.error })) };
}

export async function healthReport(ctx: ToolContext, args: { namespace?: string }) {
  const ns = nsOf(ctx, args.namespace);
  const [status, events, pressure, hpa, nodes, endpoints, policies, posture, tls] = await Promise.all([
    step("pods", () => getPodStatus(ctx, { namespace: ns })),
    step("events", () => getEvents(ctx, { namespace: ns, since: "24h" })),
    step("pressure", () => getResourcePressure(ctx, { namespace: ns })),
    step("hpa", () => getHpaStatus(ctx, { namespace: ns })),
    step("nodes", () => getNodePressure(ctx, {})),
    step("endpoints", () => getEndpoints(ctx, { namespace: ns })),
    step("network policies", () => getNetworkPolicies(ctx, { namespace: ns })),
    step("security posture", () => securityPosture(ctx, { namespace: ns, min_severity: "medium" })),
    step("tls", () => getTlsStatus(ctx, { namespace: ns })),
  ]);
  const s = status.result as { total?: number; healthy?: number; unhealthy?: ReturnType<typeof summarizePod>[]; restartsTop?: Array<{ pod: string; restarts: number }> } | undefined;
  const sections = {
    workloads: { total: s?.total, healthy: s?.healthy, unhealthy: (s?.unhealthy ?? []).map((p) => ({ pod: p.name, problems: p.problems })), topRestarts: (s?.restartsTop ?? []).filter((r) => r.restarts > 0) },
    warningsLast24h: Object.entries(events.result?.byReason ?? {}).slice(0, 10),
    resourcePressure: pressure.result?.findings ?? [],
    autoscaling: (hpa.result?.hpas ?? []).flatMap((h) => h.findings.map((f) => `${h.name}: ${f}`)),
    nodes: (nodes.result?.nodes ?? []).flatMap((n) => n.findings.map((f) => `${n.node}: ${f}`)),
    endpoints: endpoints.result?.problems ?? [],
    network: policies.result?.findings ?? [],
    security: { summary: posture.result?.summary, top: (posture.result?.findings ?? []).slice(0, 10).map((f) => `[${f.severity}] ${f.object}: ${f.detail}`) },
    tls: tls.result?.findings ?? [],
  };
  const actions: string[] = [];
  if (sections.workloads.unhealthy.length) actions.push(`fix ${sections.workloads.unhealthy.length} unhealthy pod(s): diagnose_service on their workloads`);
  if (sections.resourcePressure.length) actions.push("right-size resources for the containers listed under resourcePressure");
  if (sections.endpoints.length) actions.push("repair Services with no ready endpoints");
  if (sections.autoscaling.length) actions.push("review HPA ceilings");
  if (sections.network.length) actions.push("add NetworkPolicies (default-deny + allows)");
  if ((posture.result?.summary?.critical ?? 0) + (posture.result?.summary?.high ?? 0) > 0) actions.push(`address ${(posture.result?.summary?.critical ?? 0) + (posture.result?.summary?.high ?? 0)} high/critical security findings (security_posture)`);
  if (sections.tls.length) actions.push("add TLS to the ingress hosts listed");
  return { namespace: ns, generatedAt: new Date().toISOString(), sections, suggestedActions: actions, stepsRun: [status, events, pressure, hpa, nodes, endpoints, policies, posture, tls].map((x) => ({ step: x.name, ok: !x.error, ms: x.ms, error: x.error })) };
}

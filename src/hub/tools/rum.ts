/**
 * Real-user-monitoring tools. Data comes from probe sidecars in the proxy
 * pods that ingest beacons from the browser client (rum-client/). Summaries
 * from several replicas are merged by weighting percentiles by sample count
 * (approximate, but honest about being approximate).
 */
import type { V1Pod } from "@kubernetes/client-node";
import type { ToolContext } from "../context.js";
import { nsOf } from "../context.js";
import { resolveWorkload, hasProbeContainer } from "../model.js";
import type { Percentiles, RumSummary } from "../../probe/protocol.js";

async function rumPods(ctx: ToolContext, ns: string, service?: string): Promise<V1Pod[]> {
  if (service) return (await resolveWorkload(ctx.k8s, ns, service)).pods.filter((p) => p.status?.phase === "Running");
  const pods = (await ctx.k8s.listPods(ns)).filter((p) => p.status?.phase === "Running" && hasProbeContainer(p, ctx.config.probeContainerName));
  const out: V1Pod[] = [];
  for (const p of pods) {
    try {
      const info = await ctx.probe.info(p);
      if (info.features.rum) out.push(p);
    } catch {
      /* skip */
    }
  }
  return out;
}

function mergePct(list: Percentiles[]): Percentiles {
  const total = list.reduce((a, p) => a + p.count, 0) || 1;
  const w = (k: keyof Percentiles) => Math.round((list.reduce((a, p) => a + p[k] * p.count, 0) / total) * 1000) / 1000;
  return { count: total, p50: w("p50"), p75: w("p75"), p95: w("p95"), max: Math.max(...list.map((p) => p.max)) };
}

export function mergeSummaries(list: RumSummary[]): RumSummary {
  const merge2 = (key: "vitals" | "nav") => {
    const out: Record<string, Record<string, Percentiles>> = {};
    const acc = new Map<string, Map<string, Percentiles[]>>();
    for (const s of list) for (const [route, m] of Object.entries(s[key] ?? {})) for (const [k, p] of Object.entries(m)) {
      const r = acc.get(route) ?? new Map();
      r.set(k, [...(r.get(k) ?? []), p]);
      acc.set(route, r);
    }
    for (const [route, m] of acc) {
      out[route] = {};
      for (const [k, ps] of m) out[route][k] = mergePct(ps);
    }
    return out;
  };
  const views = new Map<string, { views: number; entries: number; dur: number[] }>();
  for (const s of list) for (const v of s.views ?? []) {
    const e = views.get(v.route) ?? { views: 0, entries: 0, dur: [] };
    e.views += v.views;
    e.entries += v.entries;
    if (v.avgDurationMs !== undefined) e.dur.push(v.avgDurationMs);
    views.set(v.route, e);
  }
  const resources = new Map<string, { count: number; p50: number[]; p95: number[]; errors: number; routes: Set<string> }>();
  for (const s of list) for (const r of s.resources ?? []) {
    const e = resources.get(r.url) ?? { count: 0, p50: [], p95: [], errors: 0, routes: new Set() };
    e.count += r.count;
    e.p50.push(r.p50Ms);
    e.p95.push(r.p95Ms);
    e.errors += r.errors;
    r.routes.forEach((x) => e.routes.add(x));
    resources.set(r.url, e);
  }
  const errors = new Map<string, RumSummary["errors"][number]>();
  for (const s of list) for (const e of s.errors ?? []) {
    const x = errors.get(e.signature);
    if (!x) errors.set(e.signature, { ...e, routes: [...e.routes] });
    else {
      x.count += e.count;
      if (e.firstSeen < x.firstSeen) x.firstSeen = e.firstSeen;
      if (e.lastSeen > x.lastSeen) x.lastSeen = e.lastSeen;
      x.routes = [...new Set([...x.routes, ...e.routes])];
    }
  }
  const devices: Record<string, number> = {};
  for (const s of list) for (const [d, n] of Object.entries(s.devices ?? {})) devices[d] = (devices[d] ?? 0) + n;
  return {
    available: list.some((s) => s.available),
    since: list.map((s) => s.since).filter(Boolean).sort()[0],
    vitals: merge2("vitals"),
    nav: merge2("nav"),
    views: [...views.entries()].map(([route, e]) => ({ route, views: e.views, entries: e.entries, avgDurationMs: e.dur.length ? Math.round(e.dur.reduce((a, b) => a + b, 0) / e.dur.length) : undefined })).sort((a, b) => b.views - a.views),
    resources: [...resources.entries()].map(([url, e]) => ({ url, count: e.count, p50Ms: Math.round(Math.max(...e.p50)), p95Ms: Math.round(Math.max(...e.p95)), errors: e.errors, routes: [...e.routes] })).sort((a, b) => b.p95Ms - a.p95Ms),
    errors: [...errors.values()].sort((a, b) => b.count - a.count),
    devices,
    sessions: list.reduce((a, s) => a + (s.sessions ?? 0), 0),
  };
}

async function collect(ctx: ToolContext, args: { namespace?: string; service?: string; route?: string }) {
  const ns = nsOf(ctx, args.namespace);
  const pods = await rumPods(ctx, ns, args.service);
  if (!pods.length) {
    const r = await ctx.providers.first("webVitals", (p) => p.webVitals!({ namespace: ns, service: args.service ?? "*", windowSeconds: 24 * 3600 }, args.route) as Promise<RumSummary | undefined>);
    if (r.result) return { ns, pods: 0, summary: r.result, note: `RUM data from provider ${r.provider}` };
    return { ns, pods: 0, summary: undefined as RumSummary | undefined, note: `no pods with a RUM-enabled probe found${r.tried.length ? ` and provider(s) ${r.tried.join(", ")} returned nothing${r.errors.length ? ` (${r.errors.join("; ")})` : ""}` : ""}. Add the probe to the proxy pod with DIAG_PROBE_RUM_ENABLED=true, route /__rum to it, and include rum-client in the Angular app - or configure Datadog RUM.` };
  }
  const summaries: RumSummary[] = [];
  const errors: string[] = [];
  for (const p of pods.slice(0, 10)) {
    try {
      const s = await ctx.probe.rumSummary(p, args.route);
      if (s.available) summaries.push(s);
    } catch (err) {
      errors.push(`${p.metadata?.name}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  return { ns, pods: pods.length, summary: summaries.length ? mergeSummaries(summaries) : undefined, note: errors.length ? errors.join("; ") : undefined };
}

const THRESHOLDS: Record<string, [number, number]> = { LCP: [2500, 4000], INP: [200, 500], CLS: [0.1, 0.25], FCP: [1800, 3000], TTFB: [800, 1800] };
function rating(metric: string, p75: number): "good" | "needs-improvement" | "poor" {
  const t = THRESHOLDS[metric];
  if (!t) return "good";
  return p75 <= t[0] ? "good" : p75 <= t[1] ? "needs-improvement" : "poor";
}

export async function getWebVitals(ctx: ToolContext, args: { namespace?: string; service?: string; route?: string }) {
  const c = await collect(ctx, args);
  if (!c.summary) return { namespace: c.ns, available: false, note: c.note };
  const routes = Object.entries(c.summary.vitals).map(([route, m]) => ({
    route,
    metrics: Object.fromEntries(Object.entries(m).map(([k, p]) => [k, { p75: p.p75, p95: p.p95, samples: p.count, rating: rating(k, p.p75) }])),
  }));
  const findings = routes.flatMap((r) => Object.entries(r.metrics).filter(([, v]) => v.rating === "poor" && v.samples >= 5).map(([k, v]) => `${r.route}: ${k} p75 ${v.p75}${k === "CLS" ? "" : "ms"} is POOR (threshold ${THRESHOLDS[k][1]})`));
  return { namespace: c.ns, since: c.summary.since, sessions: c.summary.sessions, devices: c.summary.devices, routes, findings, note: "p75 is the Web Vitals standard; ratings use Google's thresholds. Merged across proxy replicas (weighted by sample count)." };
}

export async function getPageViews(ctx: ToolContext, args: { namespace?: string; service?: string }) {
  const c = await collect(ctx, args);
  if (!c.summary) return { namespace: c.ns, available: false, note: c.note };
  const total = c.summary.views.reduce((a, v) => a + v.views, 0) || 1;
  return { namespace: c.ns, since: c.summary.since, sessions: c.summary.sessions, totalViews: total, routes: c.summary.views.map((v) => ({ ...v, share: `${((v.views / total) * 100).toFixed(1)}%` })), entryRoutes: [...c.summary.views].sort((a, b) => b.entries - a.entries).slice(0, 10).map((v) => ({ route: v.route, entries: v.entries })), devices: c.summary.devices };
}

export async function getPageLoadBreakdown(ctx: ToolContext, args: { namespace?: string; service?: string; route?: string }) {
  const c = await collect(ctx, args);
  if (!c.summary) return { namespace: c.ns, available: false, note: c.note };
  const routes = Object.entries(c.summary.nav).map(([route, phases]) => {
    const p = (k: string) => phases[k]?.p75;
    const findings: string[] = [];
    if ((p("ttfb") ?? 0) > 800) findings.push(`TTFB p75 ${p("ttfb")}ms - server/proxy side (check summarize_access_log and get_endpoint_metrics)`);
    if ((p("download") ?? 0) > 500) findings.push(`HTML download p75 ${p("download")}ms - large index.html or slow network`);
    const dcl = p("domContentLoaded");
    const ttfb = p("ttfb");
    if (dcl !== undefined && ttfb !== undefined && dcl - ttfb > 2500) findings.push(`${dcl - ttfb}ms between TTFB and DOMContentLoaded - JS parse/execute: bundle too big (get_static_bundle_stats)`);
    if ((p("dns") ?? 0) > 200) findings.push(`DNS p75 ${p("dns")}ms`);
    if ((p("tls") ?? 0) > 300) findings.push(`TLS handshake p75 ${p("tls")}ms - no session resumption / HTTP2?`);
    return { route, phasesP75: Object.fromEntries(Object.entries(phases).map(([k, v]) => [k, v.p75])), samples: phases.load?.count ?? phases.ttfb?.count, findings };
  });
  return { namespace: c.ns, since: c.summary.since, routes, note: "Navigation Timing applies to full page loads (first load / refresh / deep link), not SPA route changes. Phases are ms since navigation start except dns/connect/tls/download which are durations." };
}

export async function getBrowserApiLatency(ctx: ToolContext, args: { namespace?: string; service?: string; route?: string }) {
  const c = await collect(ctx, args);
  if (!c.summary) return { namespace: c.ns, available: false, note: c.note };
  const api = c.summary.resources.filter((r) => !/\.(js|css|png|jpe?g|gif|svg|webp|woff2?|ico|map)$/i.test(r.url));
  const assets = c.summary.resources.filter((r) => /\.(js|css|png|jpe?g|gif|svg|webp|woff2?|ico)$/i.test(r.url));
  return {
    namespace: c.ns,
    since: c.summary.since,
    apiCalls: api.slice(0, 30),
    slowestAssets: assets.slice(0, 10),
    findings: api.filter((r) => r.p95Ms > 1000 || (r.count > 10 && r.errors / r.count > 0.05)).map((r) => `${r.url}: p95 ${r.p95Ms}ms, ${r.errors} errors / ${r.count}`),
    note: "Browser-observed durations include network + proxy + service. Compare with get_endpoint_metrics (service-side) and summarize_access_log (proxy-side) for the same path: the gaps localize the slowness.",
  };
}

export async function getFrontendErrors(ctx: ToolContext, args: { namespace?: string; service?: string; route?: string }) {
  const c = await collect(ctx, args);
  if (!c.summary) return { namespace: c.ns, available: false, note: c.note };
  return { namespace: c.ns, since: c.summary.since, sessions: c.summary.sessions, errors: c.summary.errors.slice(0, 40), totalErrors: c.summary.errors.reduce((a, e) => a + e.count, 0) };
}

/**
 * In-memory RUM aggregator. Receives beacons from the browser client (via the
 * proxy's /__rum location), keeps bounded rolling samples per route, and
 * answers summary queries. Privacy: no IPs, no user ids, no query strings; a
 * beacon is validated against an allow-list of fields and everything else is
 * dropped. Also exposes Prometheus-style text for long-term retention.
 */
import type { Percentiles, RumBeacon, RumSummary } from "./protocol.js";
import { percentile } from "../hub/model.js";
import { redactText } from "../security/sanitize.js";

const VITALS = new Set(["LCP", "INP", "CLS", "FCP", "TTFB"]);
const NAV_PHASES = ["dns", "connect", "tls", "ttfb", "download", "domInteractive", "domContentLoaded", "load"] as const;
const MAX_SAMPLES_PER_KEY = 2000;
const MAX_ROUTES = 200;
const MAX_RESOURCES = 300;
const MAX_ERRORS = 200;

interface Sample {
  t: number;
  v: number;
}

class RollingSamples {
  private samples: Sample[] = [];
  push(v: number, t: number) {
    this.samples.push({ t, v });
    if (this.samples.length > MAX_SAMPLES_PER_KEY) this.samples.splice(0, this.samples.length - MAX_SAMPLES_PER_KEY);
  }
  prune(cutoff: number) {
    this.samples = this.samples.filter((s) => s.t >= cutoff);
  }
  percentiles(): Percentiles {
    const sorted = this.samples.map((s) => s.v).sort((a, b) => a - b);
    const r = (x: number) => Math.round(x * 1000) / 1000;
    return {
      count: sorted.length,
      p50: r(percentile(sorted, 50)),
      p75: r(percentile(sorted, 75)),
      p95: r(percentile(sorted, 95)),
      max: r(sorted[sorted.length - 1] ?? 0),
    };
  }
  get size() {
    return this.samples.length;
  }
}

export function normalizeRoute(route: string | undefined): string {
  if (!route) return "(unknown)";
  let r = route.split("?")[0].split("#")[0];
  if (r.length > 200) r = r.slice(0, 200);
  // Defensive: the client should already send the route *pattern*, but strip ids anyway.
  r = r
    .replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=\/|$)/gi, "/:uuid")
    .replace(/\/\d+(?=\/|$)/g, "/:id");
  return r || "/";
}

export function normalizeResourceUrl(url: string): string {
  try {
    const u = new URL(url, "http://local");
    const path = u.pathname
      .replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=\/|$)/gi, "/:uuid")
      .replace(/\/\d+(?=\/|$)/g, "/:id")
      .replace(/([.-])[0-9a-f]{8,}(\.[a-z]+)$/i, "$1[hash]$2");
    return (u.origin === "http://local" ? "" : u.origin) + path;
  } catch {
    return url.split("?")[0].slice(0, 200);
  }
}

function errorSignature(message: string, stack?: string): string {
  const firstFrame = stack?.split("\n").find((l) => /\bat\b|@/.test(l))?.trim().replace(/:\d+:\d+\)?$/, "") ?? "";
  const msg = message.replace(/\d+/g, "N").slice(0, 120);
  return firstFrame ? `${msg} | ${firstFrame.slice(0, 120)}` : msg;
}

export class RumAggregator {
  private vitals = new Map<string, Map<string, RollingSamples>>(); // route -> metric
  private nav = new Map<string, Map<string, RollingSamples>>(); // route -> phase
  private views = new Map<string, { views: number; entries: number; durations: RollingSamples }>();
  private resources = new Map<string, { count: number; times: RollingSamples; errors: number; routes: Set<string> }>();
  private errors = new Map<string, { count: number; first: number; last: number; routes: Set<string>; sample: string }>();
  private devices = new Map<string, number>();
  private sessions = new Map<string, number>();
  private startedAt = Date.now();
  private lastPrune = Date.now();

  constructor(private readonly retentionMs: number) {}

  /** Validates and ingests one beacon. Returns the number of events accepted. */
  ingest(raw: unknown, now = Date.now()): number {
    if (!raw || typeof raw !== "object") return 0;
    const b = raw as Partial<RumBeacon>;
    if (!Array.isArray(b.events)) return 0;
    const device = typeof b.device === "string" && ["mobile", "desktop", "tablet"].includes(b.device) ? b.device : "unknown";
    this.devices.set(device, (this.devices.get(device) ?? 0) + 1);
    if (typeof b.session === "string" && /^[A-Za-z0-9_-]{4,64}$/.test(b.session)) this.sessions.set(b.session, now);
    const beaconRoute = normalizeRoute(typeof b.route === "string" ? b.route : undefined);

    let accepted = 0;
    for (const ev of b.events.slice(0, 200)) {
      if (!ev || typeof ev !== "object") continue;
      const e = ev as Record<string, unknown>;
      const route = normalizeRoute(typeof e.route === "string" ? e.route : beaconRoute);
      switch (e.type) {
        case "vital": {
          const name = String(e.name);
          const value = Number(e.value);
          if (!VITALS.has(name) || !Number.isFinite(value) || value < 0 || value > 600000) continue;
          this.bucket(this.vitals, route, name).push(value, now);
          accepted++;
          break;
        }
        case "view": {
          const v = this.views.get(route) ?? { views: 0, entries: 0, durations: new RollingSamples() };
          if (!this.views.has(route) && this.views.size >= MAX_ROUTES) continue;
          v.views++;
          if (e.entry === true) v.entries++;
          const d = Number(e.durationMs);
          if (Number.isFinite(d) && d >= 0 && d < 600000) v.durations.push(d, now);
          this.views.set(route, v);
          accepted++;
          break;
        }
        case "resource": {
          if (typeof e.url !== "string") continue;
          const key = normalizeResourceUrl(e.url);
          const d = Number(e.durationMs);
          if (!Number.isFinite(d) || d < 0 || d > 600000) continue;
          const r = this.resources.get(key) ?? { count: 0, times: new RollingSamples(), errors: 0, routes: new Set() };
          if (!this.resources.has(key) && this.resources.size >= MAX_RESOURCES) continue;
          r.count++;
          r.times.push(d, now);
          const status = Number(e.status);
          if (Number.isFinite(status) && status >= 400) r.errors++;
          if (r.routes.size < 20) r.routes.add(route);
          this.resources.set(key, r);
          accepted++;
          break;
        }
        case "error": {
          if (typeof e.message !== "string") continue;
          const message = redactText(e.message.slice(0, 500));
          const stack = typeof e.stack === "string" ? redactText(e.stack.slice(0, 2000)) : undefined;
          const sig = errorSignature(message, stack);
          const er = this.errors.get(sig) ?? { count: 0, first: now, last: now, routes: new Set(), sample: message.slice(0, 200) };
          if (!this.errors.has(sig) && this.errors.size >= MAX_ERRORS) continue;
          er.count++;
          er.last = now;
          if (er.routes.size < 20) er.routes.add(route);
          this.errors.set(sig, er);
          accepted++;
          break;
        }
        case "nav": {
          for (const phase of NAV_PHASES) {
            const v = Number(e[phase]);
            if (Number.isFinite(v) && v >= 0 && v < 600000) this.bucket(this.nav, route, phase).push(v, now);
          }
          accepted++;
          break;
        }
        default:
          continue;
      }
    }
    if (now - this.lastPrune > 60_000) this.prune(now);
    return accepted;
  }

  private bucket(map: Map<string, Map<string, RollingSamples>>, route: string, key: string): RollingSamples {
    let m = map.get(route);
    if (!m) {
      if (map.size >= MAX_ROUTES) {
        m = map.get("(other)") ?? new Map();
        map.set("(other)", m);
      } else {
        m = new Map();
        map.set(route, m);
      }
    }
    let s = m.get(key);
    if (!s) {
      s = new RollingSamples();
      m.set(key, s);
    }
    return s;
  }

  prune(now = Date.now()) {
    const cutoff = now - this.retentionMs;
    for (const m of [this.vitals, this.nav]) for (const routes of m.values()) for (const s of routes.values()) s.prune(cutoff);
    for (const r of this.resources.values()) r.times.prune(cutoff);
    for (const [k, t] of this.sessions) if (t < cutoff) this.sessions.delete(k);
    for (const [k, e] of this.errors) if (e.last < cutoff) this.errors.delete(k);
    this.lastPrune = now;
  }

  summary(routeFilter?: string): RumSummary {
    const matches = (route: string) => !routeFilter || route === normalizeRoute(routeFilter);
    const vitals: RumSummary["vitals"] = {};
    for (const [route, m] of this.vitals) {
      if (!matches(route)) continue;
      vitals[route] = {};
      for (const [k, s] of m) if (s.size) vitals[route][k] = s.percentiles();
    }
    const nav: RumSummary["nav"] = {};
    for (const [route, m] of this.nav) {
      if (!matches(route)) continue;
      nav[route] = {};
      for (const [k, s] of m) if (s.size) nav[route][k] = s.percentiles();
    }
    return {
      available: true,
      since: new Date(this.startedAt).toISOString(),
      vitals,
      nav,
      views: [...this.views.entries()]
        .filter(([route]) => matches(route))
        .map(([route, v]) => ({ route, views: v.views, entries: v.entries, avgDurationMs: v.durations.size ? Math.round(v.durations.percentiles().p50) : undefined }))
        .sort((a, b) => b.views - a.views),
      resources: [...this.resources.entries()]
        .filter(([, r]) => !routeFilter || r.routes.has(normalizeRoute(routeFilter)))
        .map(([url, r]) => {
          const p = r.times.percentiles();
          return { url, count: r.count, p50Ms: Math.round(p.p50), p95Ms: Math.round(p.p95), errors: r.errors, routes: [...r.routes] };
        })
        .sort((a, b) => b.p95Ms - a.p95Ms)
        .slice(0, 50),
      errors: [...this.errors.entries()]
        .filter(([, e]) => !routeFilter || e.routes.has(normalizeRoute(routeFilter)))
        .map(([signature, e]) => ({
          signature,
          count: e.count,
          firstSeen: new Date(e.first).toISOString(),
          lastSeen: new Date(e.last).toISOString(),
          routes: [...e.routes],
          sample: e.sample,
        }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 50),
      devices: Object.fromEntries(this.devices),
      sessions: this.sessions.size,
    };
  }

  /** Prometheus text exposition (summary-style quantiles) for scraping. */
  prometheusText(): string {
    const lines: string[] = [];
    const esc = (s: string) => s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
    lines.push("# TYPE rum_web_vital gauge");
    for (const [route, m] of this.vitals) {
      for (const [metric, s] of m) {
        const p = s.percentiles();
        for (const q of ["p50", "p75", "p95"] as const) {
          lines.push(`rum_web_vital{route="${esc(route)}",metric="${metric}",quantile="${q.slice(1) === "50" ? "0.5" : q === "p75" ? "0.75" : "0.95"}"} ${p[q]}`);
        }
        lines.push(`rum_web_vital_count{route="${esc(route)}",metric="${metric}"} ${p.count}`);
      }
    }
    lines.push("# TYPE rum_page_views_total counter");
    for (const [route, v] of this.views) lines.push(`rum_page_views_total{route="${esc(route)}"} ${v.views}`);
    lines.push("# TYPE rum_frontend_errors_total counter");
    let errTotal = 0;
    for (const e of this.errors.values()) errTotal += e.count;
    lines.push(`rum_frontend_errors_total ${errTotal}`);
    lines.push("# TYPE rum_sessions gauge");
    lines.push(`rum_sessions ${this.sessions.size}`);
    return `${lines.join("\n")}\n`;
  }
}

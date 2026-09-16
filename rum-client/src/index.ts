/**
 * kube-diagnostics RUM client.
 *
 * Collects Core Web Vitals (LCP, INP, CLS, FCP, TTFB via the `web-vitals`
 * library), Navigation Timing phases, SPA route views, API/resource timings,
 * and JS errors, and beacons them to the probe behind the proxy's /__rum path.
 *
 * Privacy by construction:
 *  - routes are reported as PATTERNS (/products/:id), never concrete URLs;
 *    pass `routeResolver` to map the current location to your Angular route
 *    config, or rely on the built-in id/uuid normalizer
 *  - query strings and fragments are never sent
 *  - no cookies; session id lives in sessionStorage and dies with the tab
 *  - no user identifiers, no IP handling client-side, no input values
 *  - the ingest rejects any field not in its allow-list
 */
import { onCLS, onFCP, onINP, onLCP, onTTFB, type Metric } from "web-vitals";

export interface RumOptions {
  /** Ingest endpoint, same-origin. Default "/__rum". */
  endpoint?: string;
  /** App name label. */
  app?: string;
  /** 0..1 sampling of sessions. Default 1. */
  sampleRate?: number;
  /** Map a pathname to a route pattern (e.g. from Angular's Router config). */
  routeResolver?: (pathname: string) => string;
  /** Only report resources whose URL matches (default: same-origin /api/ or XHR/fetch). */
  resourceFilter?: (url: string, initiatorType: string) => boolean;
  /** Called before each send; return false to drop (consent gate). */
  beforeSend?: () => boolean;
  /** Max events buffered before a flush. Default 25. */
  batchSize?: number;
  /** Flush interval in ms. Default 10000. */
  flushIntervalMs?: number;
}

type RumEvent =
  | { type: "vital"; name: Metric["name"]; value: number; route?: string }
  | { type: "view"; route: string; durationMs?: number; entry?: boolean }
  | { type: "resource"; url: string; durationMs: number; status?: number; initiator?: string; bytes?: number; route?: string }
  | { type: "error"; message: string; stack?: string; route?: string }
  | { type: "nav"; route?: string; dns?: number; connect?: number; tls?: number; ttfb?: number; download?: number; domInteractive?: number; domContentLoaded?: number; load?: number };

const UUID = /\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=\/|$)/gi;
const NUM = /\/\d+(?=\/|$)/g;

export function defaultRouteResolver(pathname: string): string {
  return (pathname.split("?")[0].split("#")[0] || "/").replace(UUID, "/:uuid").replace(NUM, "/:id");
}

function deviceClass(): "mobile" | "desktop" | "tablet" | "unknown" {
  const ua = navigator.userAgent || "";
  if (/iPad|Tablet/i.test(ua)) return "tablet";
  if (/Mobi|Android|iPhone/i.test(ua)) return "mobile";
  return ua ? "desktop" : "unknown";
}

function sessionId(): string {
  try {
    const k = "__kd_rum_session";
    let v = sessionStorage.getItem(k);
    if (!v) {
      v = Math.random().toString(36).slice(2, 12) + Date.now().toString(36);
      sessionStorage.setItem(k, v);
    }
    return v;
  } catch {
    return "nostorage";
  }
}

export interface RumClient {
  /** Report an SPA route change. Call from Angular Router NavigationEnd. */
  routeChanged(pathname: string, durationMs?: number): void;
  /** Report a handled error. */
  error(message: string, stack?: string): void;
  /** Flush now (beacon). */
  flush(): void;
  /** Stop listening. */
  destroy(): void;
}

export function initRum(opts: RumOptions = {}): RumClient {
  const endpoint = opts.endpoint ?? "/__rum";
  const resolve = opts.routeResolver ?? defaultRouteResolver;
  const sampled = Math.random() < (opts.sampleRate ?? 1);
  const batchSize = opts.batchSize ?? 25;
  const session = sessionId();
  let currentRoute = resolve(location.pathname);
  let routeStartedAt = performance.now();
  const buffer: RumEvent[] = [];
  let timer: number | undefined;
  let entryReported = false;
  const cleanups: Array<() => void> = [];

  const flush = () => {
    if (!sampled) return;
    drainVitals();
    if (!buffer.length) return;
    if (opts.beforeSend && !opts.beforeSend()) {
      buffer.length = 0;
      return;
    }
    const payload = JSON.stringify({ app: opts.app, session, route: currentRoute, device: deviceClass(), connection: (navigator as { connection?: { effectiveType?: string } }).connection?.effectiveType, events: buffer.splice(0, buffer.length) });
    try {
      if (!navigator.sendBeacon || !navigator.sendBeacon(endpoint, new Blob([payload], { type: "application/json" }))) {
        fetch(endpoint, { method: "POST", body: payload, headers: { "content-type": "application/json" }, keepalive: true }).catch(() => undefined);
      }
    } catch {
      /* never throw into the app */
    }
  };
  const push = (e: RumEvent) => {
    if (!sampled) return;
    buffer.push(e);
    if (buffer.length >= batchSize) flush();
  };

  // Web Vitals. LCP/CLS/INP are only "final" when the page is hidden, and callback timing around
  // pagehide is not guaranteed to precede our flush, so we track the latest value of every metric
  // (reportAllChanges) and send it on the next flush only if it changed since the last send.
  const latest = new Map<string, { value: number; route: string; sent: number | undefined }>();
  const vital = (m: Metric) => {
    const k = `${m.name}:${m.id}`;
    const prev = latest.get(k);
    latest.set(k, { value: m.value, route: prev?.route ?? currentRoute, sent: prev?.sent });
  };
  const opts2 = { reportAllChanges: true } as const;
  onLCP(vital, opts2);
  onINP(vital, opts2);
  onCLS(vital, opts2);
  onFCP(vital, opts2);
  onTTFB(vital, opts2);
  function drainVitals() {
    for (const [k, v] of latest) {
      if (v.sent === v.value) continue;
      buffer.push({ type: "vital", name: k.split(":")[0] as Metric["name"], value: v.value, route: v.route });
      v.sent = v.value;
    }
  }

  // Navigation Timing (full page loads only).
  const nav = performance.getEntriesByType("navigation")[0] as PerformanceNavigationTiming | undefined;
  const reportNav = () => {
    const n = nav ?? (performance.getEntriesByType("navigation")[0] as PerformanceNavigationTiming | undefined);
    if (!n) return;
    push({
      type: "nav",
      route: currentRoute,
      dns: Math.max(0, n.domainLookupEnd - n.domainLookupStart),
      connect: Math.max(0, n.connectEnd - n.connectStart),
      tls: n.secureConnectionStart > 0 ? Math.max(0, n.connectEnd - n.secureConnectionStart) : 0,
      ttfb: Math.max(0, n.responseStart - n.startTime),
      download: Math.max(0, n.responseEnd - n.responseStart),
      domInteractive: Math.max(0, n.domInteractive - n.startTime),
      domContentLoaded: Math.max(0, n.domContentLoadedEventEnd - n.startTime),
      load: n.loadEventEnd > 0 ? Math.max(0, n.loadEventEnd - n.startTime) : undefined,
    });
  };
  if (document.readyState === "complete") setTimeout(reportNav, 0);
  else {
    const onLoad = () => setTimeout(reportNav, 0);
    addEventListener("load", onLoad, { once: true });
    cleanups.push(() => removeEventListener("load", onLoad));
  }

  // Resource timing for API calls (fetch/xhr) - URLs are path-only, no query.
  const filter = opts.resourceFilter ?? ((url, initiator) => (initiator === "fetch" || initiator === "xmlhttprequest") && new URL(url, location.href).origin === location.origin);
  const po = typeof PerformanceObserver !== "undefined" ? new PerformanceObserver((list) => {
    for (const entry of list.getEntries() as PerformanceResourceTiming[]) {
      if (!filter(entry.name, entry.initiatorType)) continue;
      const u = new URL(entry.name, location.href);
      push({ type: "resource", url: u.origin === location.origin ? u.pathname : `${u.origin}${u.pathname}`, durationMs: Math.round(entry.duration), status: (entry as { responseStatus?: number }).responseStatus, initiator: entry.initiatorType, bytes: entry.transferSize || undefined, route: currentRoute });
    }
  }) : undefined;
  try {
    po?.observe({ type: "resource", buffered: true });
  } catch {
    /* unsupported */
  }
  cleanups.push(() => po?.disconnect());

  // Errors.
  const onError = (ev: ErrorEvent) => push({ type: "error", message: String(ev.message ?? "error").slice(0, 500), stack: ev.error?.stack?.slice(0, 2000), route: currentRoute });
  const onRejection = (ev: PromiseRejectionEvent) => {
    const r = ev.reason as { message?: string; stack?: string } | string | undefined;
    push({ type: "error", message: (typeof r === "string" ? r : r?.message ?? "unhandledrejection").slice(0, 500), stack: typeof r === "object" ? r?.stack?.slice(0, 2000) : undefined, route: currentRoute });
  };
  addEventListener("error", onError);
  addEventListener("unhandledrejection", onRejection);
  cleanups.push(() => {
    removeEventListener("error", onError);
    removeEventListener("unhandledrejection", onRejection);
  });

  // Initial view + flush on hide.
  push({ type: "view", route: currentRoute, entry: true });
  entryReported = true;
  const onHide = () => {
    if (document.visibilityState === "hidden") flush();
  };
  addEventListener("visibilitychange", onHide);
  addEventListener("pagehide", flush);
  cleanups.push(() => {
    removeEventListener("visibilitychange", onHide);
    removeEventListener("pagehide", flush);
  });
  timer = setInterval(flush, opts.flushIntervalMs ?? 10000) as unknown as number;

  return {
    routeChanged(pathname, durationMs) {
      const route = resolve(pathname);
      const now = performance.now();
      currentRoute = route;
      push({ type: "view", route, durationMs: durationMs ?? Math.round(now - routeStartedAt), entry: !entryReported });
      routeStartedAt = now;
    },
    error(message, stack) {
      push({ type: "error", message: message.slice(0, 500), stack: stack?.slice(0, 2000), route: currentRoute });
    },
    flush,
    destroy() {
      flush();
      if (timer) clearInterval(timer);
      cleanups.forEach((c) => c());
    },
  };
}

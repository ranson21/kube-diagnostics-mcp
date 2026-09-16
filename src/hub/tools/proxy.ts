/**
 * Reverse-proxy tools (nginx-flavoured; other proxies degrade gracefully).
 */
import type { ToolContext } from "../context.js";
import { nsOf, requireActive } from "../context.js";
import { resolveWorkload } from "../model.js";
import { parseWindowSeconds } from "../../security/guard.js";

export async function getProxyStatus(ctx: ToolContext, args: { namespace?: string; service: string }) {
  const ns = nsOf(ctx, args.namespace);
  const w = await resolveWorkload(ctx.k8s, ns, args.service);
  const rows = [];
  for (const pod of w.pods.filter((p) => p.status?.phase === "Running").slice(0, 10)) {
    try {
      const s = await ctx.probe.nginxStatus(pod);
      const findings: string[] = [];
      if ((s.dropped ?? 0) > 0) findings.push(`${s.dropped} connections accepted but not handled - worker_connections / fd limit reached`);
      if ((s.waiting ?? 0) > 5000) findings.push(`${s.waiting} keep-alive connections idle - consider lowering keepalive_timeout`);
      if ((s.writing ?? 0) > (s.reading ?? 0) * 10 + 100) findings.push(`${s.writing} connections in writing state - slow upstreams or slow clients holding workers`);
      rows.push({ pod: pod.metadata?.name, ...s, findings });
    } catch (err) {
      rows.push({ pod: pod.metadata?.name, error: err instanceof Error ? err.message : String(err) });
    }
  }
  return { workload: `${w.kind}/${w.name}`, namespace: ns, pods: rows };
}

export async function summarizeAccessLog(ctx: ToolContext, args: { namespace?: string; service: string; since?: string }) {
  const ns = nsOf(ctx, args.namespace);
  const w = await resolveWorkload(ctx.k8s, ns, args.service);
  const since = parseWindowSeconds(args.since, 900);
  const rows = [];
  for (const pod of w.pods.filter((p) => p.status?.phase === "Running").slice(0, 5)) {
    try {
      const s = await ctx.probe.accessLog(pod, since);
      const findings: string[] = [];
      const total = s.lines || 1;
      const p5 = s.byStatusClass["5xx"] ?? 0;
      if (p5 / total > 0.01) findings.push(`${((p5 / total) * 100).toFixed(1)}% 5xx`);
      if (s.clientAbandoned499 / total > 0.005) findings.push(`${s.clientAbandoned499} requests ended with 499 (client gave up waiting) - upstream latency too high for users`);
      for (const u of s.byUpstream) if (u.timeouts504) findings.push(`upstream ${u.upstream}: ${u.timeouts504} x 504 gateway timeouts (proxy_read_timeout too low for that endpoint, or upstream hung)`);
      for (const p of s.topPaths) if ((p.p95Ms ?? 0) > 2000) findings.push(`${p.path}: p95 ${p.p95Ms}ms`);
      if ((s.requestVsUpstreamGapP95Ms ?? 0) > 200) findings.push(`p95 gap between request_time and upstream_response_time is ${s.requestVsUpstreamGapP95Ms}ms - time spent in the proxy or sending to slow clients (buffering, large bodies, TLS)`);
      if (s.suspiciousPaths.length) findings.push(`scanner-like traffic: ${s.suspiciousPaths.slice(0, 3).map((x) => `${x.path} (${x.reason})`).join("; ")}`);
      if (s.sensitive?.length) findings.push(`SENSITIVE DATA in access log: ${s.sensitive.map((x) => `${x.kind} x${x.count}`).join(", ")} - query strings or bodies are being logged`);
      rows.push({ pod: pod.metadata?.name, ...s, findings });
    } catch (err) {
      rows.push({ pod: pod.metadata?.name, error: err instanceof Error ? err.message : String(err) });
    }
  }
  return { workload: `${w.kind}/${w.name}`, namespace: ns, since: `${since}s`, pods: rows };
}

export interface NginxConfSummary {
  upstreams: Array<{ name: string; servers: string[] }>;
  locations: Array<{ path: string; proxyPass?: string; root?: string; tryFiles?: string; cacheControl?: string; expires?: string; hasAuth?: boolean }>;
  timeouts: Record<string, string>;
  buffering: Record<string, string>;
  gzip?: string;
  brotli?: string;
  clientMaxBodySize?: string;
  securityHeaders: Record<string, string | undefined>;
  serverTokens?: string;
  rateLimit: boolean;
  stubStatus: boolean;
  logFormatHasUpstreamTime: boolean;
  workerConnections?: string;
  keepaliveTimeout?: string;
  findings: string[];
}

/** Heuristic nginx.conf parser: enough for upstreams, locations, timeouts, headers. */
export function summarizeNginxConf(conf: string): NginxConfSummary {
  const text = conf.replace(/#.*$/gm, "");
  const get = (name: string) => new RegExp(`(?:^|[;{}\\s])${name}\\s+([^;]+);`).exec(text)?.[1]?.trim();
  const upstreams = [...text.matchAll(/upstream\s+([\w.-]+)\s*\{([^}]*)\}/g)].map((m) => ({ name: m[1], servers: [...m[2].matchAll(/server\s+([^;]+);/g)].map((s) => s[1].trim()) }));
  const locations = [...text.matchAll(/location\s+([^{]+)\{((?:[^{}]|\{[^{}]*\})*)\}/g)].map((m) => {
    const body = m[2];
    const g = (name: string) => new RegExp(`(?:^|[;{}\\s])${name}\\s+([^;]+);`).exec(body)?.[1]?.trim();
    return { path: m[1].trim(), proxyPass: g("proxy_pass"), root: g("root") ?? g("alias"), tryFiles: g("try_files"), cacheControl: /add_header\s+Cache-Control\s+([^;]+);/i.exec(body)?.[1]?.trim(), expires: g("expires"), hasAuth: /auth_basic|auth_request/.test(body) };
  });
  const header = (name: string) => new RegExp(`add_header\\s+${name}\\s+([^;]+);`, "i").exec(text)?.[1]?.trim();
  const securityHeaders = {
    "Strict-Transport-Security": header("Strict-Transport-Security"),
    "Content-Security-Policy": header("Content-Security-Policy"),
    "X-Frame-Options": header("X-Frame-Options"),
    "X-Content-Type-Options": header("X-Content-Type-Options"),
    "Referrer-Policy": header("Referrer-Policy"),
    "Permissions-Policy": header("Permissions-Policy"),
  };
  const timeouts: Record<string, string> = {};
  for (const t of ["proxy_connect_timeout", "proxy_read_timeout", "proxy_send_timeout", "send_timeout", "client_body_timeout", "keepalive_timeout"]) {
    const v = get(t);
    if (v) timeouts[t] = v;
  }
  const buffering: Record<string, string> = {};
  for (const b of ["proxy_buffering", "proxy_buffers", "proxy_buffer_size", "proxy_busy_buffers_size", "proxy_request_buffering"]) {
    const v = get(b);
    if (v) buffering[b] = v;
  }
  const findings: string[] = [];
  const secs = (v?: string) => (v ? Number(/^(\d+)(s|m)?$/.exec(v)?.[1] ?? NaN) * (/m$/.test(v) ? 60 : 1) : undefined);
  const prt = secs(timeouts.proxy_read_timeout);
  if (prt !== undefined && prt < 10) findings.push(`proxy_read_timeout ${timeouts.proxy_read_timeout} is very low - any upstream call slower than that returns 504 to the user`);
  if (!get("gzip") || get("gzip") === "off") findings.push("gzip is off - JS/CSS/JSON are sent uncompressed (3-5x larger)");
  for (const h of Object.entries(securityHeaders)) if (!h[1] && h[0] !== "Permissions-Policy") findings.push(`missing security header ${h[0]}`);
  const assetLoc = locations.find((l) => /\\\.\(|\.js|\.css|assets|static|~\*/.test(l.path));
  if (!assetLoc || (!assetLoc.cacheControl && !assetLoc.expires)) findings.push("no Cache-Control/expires for static assets - browsers re-download hashed Angular chunks on every visit");
  const indexLoc = locations.find((l) => l.tryFiles?.includes("index.html") || l.path === "/");
  if (indexLoc && !/no-cache|no-store|max-age=0/i.test(indexLoc.cacheControl ?? "")) findings.push("index.html is cacheable - users can be stuck on an old bundle after a deploy (set Cache-Control: no-cache on index.html)");
  if (get("server_tokens") !== "off") findings.push("server_tokens not off - nginx version disclosed in headers/error pages");
  if (!/limit_req_zone|limit_conn_zone/.test(text)) findings.push("no rate limiting (limit_req) configured at the proxy");
  if (!/\$upstream_response_time/.test(text)) findings.push("log_format lacks $upstream_response_time - cannot separate proxy time from upstream time");
  if (/proxy_pass\s+http:\/\/[^;]*\/actuator/.test(text) || locations.some((l) => /actuator/.test(l.path) && !l.hasAuth)) findings.push("/actuator is proxied to the outside without auth");
  return {
    upstreams,
    locations,
    timeouts,
    buffering,
    gzip: get("gzip"),
    brotli: get("brotli"),
    clientMaxBodySize: get("client_max_body_size"),
    securityHeaders,
    serverTokens: get("server_tokens"),
    rateLimit: /limit_req_zone|limit_conn_zone/.test(text),
    stubStatus: /stub_status/.test(text),
    logFormatHasUpstreamTime: /\$upstream_response_time/.test(text),
    workerConnections: get("worker_connections"),
    keepaliveTimeout: get("keepalive_timeout"),
    findings,
  };
}

export async function getProxyConfigSummary(ctx: ToolContext, args: { namespace?: string; service: string }) {
  const ns = nsOf(ctx, args.namespace);
  const w = await resolveWorkload(ctx.k8s, ns, args.service);
  const spec = w.deployment?.spec?.template?.spec ?? w.pods[0]?.spec;
  const cmNames = new Set<string>();
  for (const v of spec?.volumes ?? []) if (v.configMap?.name) cmNames.add(v.configMap.name);
  if (!cmNames.size) return { workload: `${w.kind}/${w.name}`, available: false, note: "no ConfigMap volumes on this workload; the proxy config is baked into the image (not readable without the probe's static dir support)" };
  const cms = await ctx.k8s.listConfigMaps(ns);
  const results = [];
  for (const name of cmNames) {
    const cm = cms.find((c) => c.metadata?.name === name);
    for (const [key, value] of Object.entries(cm?.data ?? {})) {
      if (!/server\s*\{|http\s*\{|location\s|upstream\s/.test(value)) continue;
      results.push({ configMap: name, key, ...summarizeNginxConf(value) });
    }
  }
  if (!results.length) return { workload: `${w.kind}/${w.name}`, available: false, note: `ConfigMaps ${[...cmNames].join(", ")} contain no nginx-looking config` };
  return { workload: `${w.kind}/${w.name}`, namespace: ns, configs: results };
}

export async function getStaticBundleStats(ctx: ToolContext, args: { namespace?: string; service: string }) {
  const ns = nsOf(ctx, args.namespace);
  const w = await resolveWorkload(ctx.k8s, ns, args.service);
  const pod = w.pods.find((p) => p.status?.phase === "Running");
  if (!pod) throw new Error("no running pod");
  const s = await ctx.probe.staticStats(pod);
  const findings: string[] = [];
  if (s.available) {
    if ((s.jsBytes ?? 0) > 2 * 1024 * 1024) findings.push(`${Math.round((s.jsBytes ?? 0) / 1024 / 1024)}MiB of JavaScript - the initial bundle is too large; check for unused deps (lodash/moment/full icon sets) and lazy-load routes`);
    if ((s.sourceMaps ?? 0) > 0) findings.push(`${s.sourceMaps} source maps shipped - exposes original source to anyone (and wastes bytes); build without --source-map for prod`);
    if ((s.unhashedJs ?? []).length) findings.push(`unhashed JS files (${s.unhashedJs!.slice(0, 3).join(", ")}) cannot be long-cached`);
    for (const f of s.largest.slice(0, 3)) if (f.bytes > 1024 * 1024 && /\.(png|jpe?g|gif)$/i.test(f.file)) findings.push(`${f.file} is ${Math.round(f.bytes / 1024 / 1024)}MiB - convert to WebP/AVIF and size it`);
  }
  return { workload: `${w.kind}/${w.name}`, pod: pod.metadata?.name, ...s, findings };
}

export async function checkSecurityHeaders(ctx: ToolContext, args: { url: string }) {
  requireActive(ctx, "check_security_headers");
  const u = new URL(args.url);
  if (!/^https?:$/.test(u.protocol)) throw new Error("only http/https URLs");
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 8000);
  try {
    const r = await fetch(u, { method: "GET", redirect: "manual", signal: ctl.signal, headers: { "user-agent": "kube-diagnostics-mcp/health-check" } });
    const h = (n: string) => r.headers.get(n) ?? undefined;
    const findings: string[] = [];
    if (u.protocol === "https:" && !h("strict-transport-security")) findings.push("no HSTS");
    if (!h("content-security-policy")) findings.push("no Content-Security-Policy");
    if (!h("x-content-type-options")) findings.push("no X-Content-Type-Options: nosniff");
    if (!h("x-frame-options") && !/frame-ancestors/.test(h("content-security-policy") ?? "")) findings.push("clickjacking: no X-Frame-Options or CSP frame-ancestors");
    if (!h("referrer-policy")) findings.push("no Referrer-Policy");
    if (h("server") && /\d/.test(h("server")!)) findings.push(`Server header discloses version: ${h("server")}`);
    if (h("x-powered-by")) findings.push(`X-Powered-By discloses stack: ${h("x-powered-by")}`);
    if (u.protocol === "http:" && !(r.status >= 300 && r.status < 400 && /^https:/.test(h("location") ?? ""))) findings.push("plain HTTP is served without redirect to HTTPS");
    const setCookie = r.headers.getSetCookie?.() ?? [];
    for (const c of setCookie) {
      const name = c.split("=")[0];
      if (!/;\s*secure/i.test(c) && u.protocol === "https:") findings.push(`cookie ${name} lacks Secure`);
      if (!/;\s*httponly/i.test(c)) findings.push(`cookie ${name} lacks HttpOnly`);
      if (!/;\s*samesite/i.test(c)) findings.push(`cookie ${name} lacks SameSite`);
    }
    return { url: u.toString(), status: r.status, headers: { server: h("server"), hsts: h("strict-transport-security"), csp: h("content-security-policy")?.slice(0, 300), xfo: h("x-frame-options"), xcto: h("x-content-type-options"), referrer: h("referrer-policy"), permissions: h("permissions-policy")?.slice(0, 200), cacheControl: h("cache-control"), contentEncoding: h("content-encoding") }, cookies: setCookie.length, findings };
  } finally {
    clearTimeout(t);
  }
}

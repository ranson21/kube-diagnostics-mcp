/**
 * Probe sidecar HTTP server. Tiny, dependency-free (node:http), read-only.
 *
 * Security posture: no Kubernetes credentials are mounted; the only caller
 * is the hub, which must present the shared bearer token; active checks
 * (DNS, TCP connect) are off unless DIAG_ALLOW_ACTIVE_CHECKS=true; Actuator
 * endpoints that dump state (heapdump, env, logfile, shutdown...) are never
 * proxied; RUM ingest is on a separate, unauthenticated path that only the
 * proxy should route to and that accepts an allow-listed schema only.
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { lookup } from "node:dns/promises";
import { readFile, readdir, stat } from "node:fs/promises";
import { connect as netConnect } from "node:net";
import { join, relative } from "node:path";
import { timingSafeEqual } from "node:crypto";
import type { ProbeConfig } from "../config.js";
import type { LoggerLike } from "../logger.js";
import { summarizeConnections } from "./procnet.js";
import { summarizeProcesses } from "./processes.js";
import { summarizeAccessLogFile } from "./accesslog.js";
import { RumAggregator } from "./rum.js";
import { PROBE_PROTOCOL_VERSION, type ConnectResult, type DnsResult, type NginxStatus, type ProbeInfo, type StaticBundleStats } from "./protocol.js";
import { sanitizeDeep } from "../security/sanitize.js";
import { assertHostname, assertPort, GuardError } from "../security/guard.js";

export const PROBE_VERSION = "0.1.0";

/** Actuator endpoints the probe is willing to fetch. Everything else is refused. */
const ACTUATOR_ALLOW = new Set(["health", "health/liveness", "health/readiness", "info", "metrics", "prometheus", "threaddump", "loggers", "caches", "scheduledtasks", "conditions", "configprops", "beans", "mappings"]);
const ACTUATOR_METRIC_NAME = /^[A-Za-z0-9_.]{1,120}$/;
const ACTUATOR_TAG = /^[A-Za-z0-9_.:/{}\-*,]{1,200}$/;

function json(res: ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(sanitizeDeep(body));
  res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(text) });
  res.end(text);
}

function text(res: ServerResponse, status: number, body: string, type = "text/plain; version=0.0.4"): void {
  res.writeHead(status, { "content-type": type, "content-length": Buffer.byteLength(body) });
  res.end(body);
}

function tokenMatches(header: string | undefined, expected: string): boolean {
  if (!header?.startsWith("Bearer ")) return false;
  const given = Buffer.from(header.slice(7));
  const want = Buffer.from(expected);
  return given.length === want.length && timingSafeEqual(given, want);
}

async function readBody(req: IncomingMessage, maxBytes: number): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > maxBytes) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

async function fetchWithTimeout(url: string, ms: number, init?: RequestInit): Promise<Response> {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), ms);
  try {
    return await fetch(url, { ...init, signal: ctl.signal });
  } finally {
    clearTimeout(t);
  }
}

export async function fetchNginxStatus(url: string): Promise<NginxStatus> {
  try {
    const r = await fetchWithTimeout(url, 3000);
    const body = await r.text();
    if (!r.ok) return { available: false, note: `stub_status returned HTTP ${r.status}` };
    const active = /Active connections:\s*(\d+)/.exec(body);
    const counters = /\n\s*(\d+)\s+(\d+)\s+(\d+)\s*\n/.exec(body);
    const rww = /Reading:\s*(\d+)\s*Writing:\s*(\d+)\s*Waiting:\s*(\d+)/.exec(body);
    const accepts = counters ? Number(counters[1]) : undefined;
    const handled = counters ? Number(counters[2]) : undefined;
    return {
      available: true,
      activeConnections: active ? Number(active[1]) : undefined,
      accepts,
      handled,
      requests: counters ? Number(counters[3]) : undefined,
      reading: rww ? Number(rww[1]) : undefined,
      writing: rww ? Number(rww[2]) : undefined,
      waiting: rww ? Number(rww[3]) : undefined,
      dropped: accepts !== undefined && handled !== undefined ? accepts - handled : undefined,
    };
  } catch (err) {
    return { available: false, note: `stub_status unreachable: ${err instanceof Error ? err.message : String(err)}` };
  }
}

export async function staticBundleStats(dir: string): Promise<StaticBundleStats> {
  const files: Array<{ file: string; bytes: number }> = [];
  async function walk(d: string, depth: number) {
    if (depth > 6) return;
    let entries;
    try {
      entries = await readdir(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const p = join(d, e.name);
      if (e.isDirectory()) await walk(p, depth + 1);
      else if (e.isFile()) {
        try {
          const s = await stat(p);
          files.push({ file: relative(dir, p), bytes: s.size });
        } catch {
          /* ignore */
        }
      }
      if (files.length > 5000) return;
    }
  }
  await walk(dir, 0);
  if (!files.length) return { available: false, note: `no files under ${dir}`, largest: [] };
  const sum = (pred: (f: string) => boolean) => files.filter((f) => pred(f.file)).reduce((a, f) => a + f.bytes, 0);
  const js = files.filter((f) => /\.m?js$/.test(f.file));
  const hashed = js.filter((f) => /[.-][0-9A-Za-z]{8,}\.m?js$/.test(f.file));
  return {
    available: true,
    dir,
    fileCount: files.length,
    totalBytes: files.reduce((a, f) => a + f.bytes, 0),
    largest: [...files].sort((a, b) => b.bytes - a.bytes).slice(0, 15),
    jsBytes: sum((f) => /\.m?js$/.test(f)),
    cssBytes: sum((f) => /\.css$/.test(f)),
    imageBytes: sum((f) => /\.(png|jpe?g|gif|webp|avif|svg|ico)$/i.test(f)),
    hashedChunks: hashed.length,
    unhashedJs: js.filter((f) => !hashed.includes(f)).map((f) => f.file).slice(0, 20),
    sourceMaps: files.filter((f) => /\.map$/.test(f.file)).length,
    hasIndexHtml: files.some((f) => f.file === "index.html"),
  };
}

async function resolveDns(name: string): Promise<DnsResult> {
  const started = Date.now();
  let resolvConf: DnsResult["resolvConf"];
  try {
    const rc = await readFile("/etc/resolv.conf", "utf8");
    resolvConf = { nameservers: [], search: [], options: [] };
    for (const line of rc.split("\n")) {
      const [k, ...rest] = line.trim().split(/\s+/);
      if (k === "nameserver") resolvConf.nameservers.push(rest[0]);
      else if (k === "search") resolvConf.search.push(...rest);
      else if (k === "options") resolvConf.options.push(...rest);
    }
  } catch {
    /* fine */
  }
  try {
    const results = await lookup(name, { all: true });
    return { name, addresses: results.map((r) => r.address), durationMs: Date.now() - started, resolvConf };
  } catch (err) {
    return { name, addresses: [], durationMs: Date.now() - started, error: err instanceof Error ? err.message : String(err), resolvConf };
  }
}

function tcpConnect(host: string, port: number, timeoutMs = 3000): Promise<ConnectResult> {
  const started = Date.now();
  return new Promise((resolve) => {
    const sock = netConnect({ host, port });
    const done = (ok: boolean, error?: string) => {
      sock.destroy();
      resolve({ host, port, ok, durationMs: Date.now() - started, error });
    };
    sock.setTimeout(timeoutMs, () => done(false, `timeout after ${timeoutMs}ms`));
    sock.once("connect", () => done(true));
    sock.once("error", (e) => done(false, e.message));
  });
}

export function createProbeServer(config: ProbeConfig, logger: LoggerLike) {
  const rum = config.rumEnabled ? new RumAggregator(config.rumRetentionMinutes * 60_000) : undefined;

  const info: ProbeInfo = {
    protocol: PROBE_PROTOCOL_VERSION,
    version: PROBE_VERSION,
    pod: config.podName,
    namespace: config.podNamespace,
    features: {
      connections: true,
      processes: true,
      dns: config.allowActiveChecks,
      connect: config.allowActiveChecks,
      actuator: Boolean(config.actuatorUrl),
      nginxStatus: Boolean(config.nginxStatusUrl),
      staticDir: Boolean(config.staticDir),
      accessLog: Boolean(config.accessLogPath),
      rum: Boolean(rum),
    },
    allowActiveChecks: config.allowActiveChecks,
  };

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", "http://probe");
    const path = url.pathname;

    // Unauthenticated: RUM ingest (proxied from the browser) and metrics scrape.
    if (rum && path === "/rum" && req.method === "POST") {
      let body: string;
      try {
        body = await readBody(req, config.rumMaxBodyBytes);
      } catch {
        res.writeHead(413).end();
        return;
      }
      try {
        const accepted = rum.ingest(JSON.parse(body));
        res.writeHead(accepted ? 204 : 400).end();
      } catch {
        res.writeHead(400).end();
      }
      return;
    }
    if (path === "/metrics" && req.method === "GET") {
      text(res, 200, rum ? rum.prometheusText() : "# rum disabled\n");
      return;
    }
    if (path === "/healthz") {
      text(res, 200, "ok");
      return;
    }

    if (!config.allowUnauthenticated) {
      if (!config.token || !tokenMatches(req.headers.authorization, config.token)) {
        json(res, 401, { error: "unauthorized" });
        return;
      }
    }
    if (req.method !== "GET") {
      json(res, 405, { error: "method not allowed" });
      return;
    }

    try {
      switch (path) {
        case "/info":
          return json(res, 200, info);
        case "/connections":
          return json(res, 200, await summarizeConnections());
        case "/processes":
          return json(res, 200, await summarizeProcesses());
        case "/dns": {
          if (!config.allowActiveChecks) return json(res, 403, { error: "active checks disabled (DIAG_ALLOW_ACTIVE_CHECKS)" });
          const name = assertHostname(url.searchParams.get("name") ?? "");
          return json(res, 200, await resolveDns(name));
        }
        case "/connect": {
          if (!config.allowActiveChecks) return json(res, 403, { error: "active checks disabled (DIAG_ALLOW_ACTIVE_CHECKS)" });
          const host = assertHostname(url.searchParams.get("host") ?? "");
          const port = assertPort(Number(url.searchParams.get("port")));
          return json(res, 200, await tcpConnect(host, port));
        }
        case "/nginx-status": {
          if (!config.nginxStatusUrl) return json(res, 200, { available: false, note: "DIAG_PROBE_NGINX_STATUS_URL not set" });
          return json(res, 200, await fetchNginxStatus(config.nginxStatusUrl));
        }
        case "/static-stats": {
          if (!config.staticDir) return json(res, 200, { available: false, note: "DIAG_PROBE_STATIC_DIR not set", largest: [] });
          return json(res, 200, await staticBundleStats(config.staticDir));
        }
        case "/access-log": {
          if (!config.accessLogPath) return json(res, 200, { available: false, note: "DIAG_PROBE_ACCESS_LOG_PATH not set", lines: 0 });
          const since = Number(url.searchParams.get("sinceSeconds")) || undefined;
          return json(res, 200, await summarizeAccessLogFile(config.accessLogPath, undefined, since));
        }
        case "/rum-summary": {
          if (!rum) return json(res, 200, { available: false, note: "DIAG_PROBE_RUM_ENABLED is not true on this probe" });
          return json(res, 200, rum.summary(url.searchParams.get("route") ?? undefined));
        }
        case "/actuator": {
          if (!config.actuatorUrl) return json(res, 200, { available: false, note: "DIAG_PROBE_ACTUATOR_URL not set" });
          const endpoint = (url.searchParams.get("endpoint") ?? "health").replace(/^\/+|\/+$/g, "");
          if (!ACTUATOR_ALLOW.has(endpoint)) return json(res, 403, { error: `actuator endpoint "${endpoint}" is not allowed` });
          let target = `${config.actuatorUrl}/${endpoint}`;
          const metric = url.searchParams.get("metric");
          if (endpoint === "metrics" && metric) {
            if (!ACTUATOR_METRIC_NAME.test(metric)) throw new GuardError("invalid metric name");
            target += `/${metric}`;
            const tags = url.searchParams.getAll("tag").filter((t) => ACTUATOR_TAG.test(t));
            if (tags.length) target += `?${tags.map((t) => `tag=${encodeURIComponent(t)}`).join("&")}`;
          }
          const r = await fetchWithTimeout(target, 8000, { headers: { accept: "application/json, text/plain" } });
          const ct = r.headers.get("content-type") ?? "";
          if (ct.includes("json")) return json(res, 200, { available: true, status: r.status, body: await r.json() });
          const t = await r.text();
          return json(res, 200, { available: true, status: r.status, text: t.slice(0, 512 * 1024), truncated: t.length > 512 * 1024 });
        }
        default:
          return json(res, 404, { error: "not found" });
      }
    } catch (err) {
      const status = err instanceof GuardError ? 400 : 500;
      json(res, status, { error: err instanceof Error ? err.message : String(err) });
    }
  }

  const server = createServer((req, res) => {
    handle(req, res).catch((err) => {
      logger.error("probe handler crashed", { error: err instanceof Error ? err.message : String(err) });
      if (!res.headersSent) json(res, 500, { error: "internal error" });
    });
  });
  server.keepAliveTimeout = 30_000;
  return { server, info, rum };
}

export function startProbe(config: ProbeConfig, logger: LoggerLike): Promise<void> {
  const { server } = createProbeServer(config, logger);
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.port, config.host, () => {
      logger.info("probe listening", { host: config.host, port: config.port });
      resolve();
    });
  });
}

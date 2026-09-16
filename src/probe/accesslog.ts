/**
 * Reverse-proxy access log summarizer. Understands nginx JSON logs (the
 * fault lab's format) and the "combined" text format with optional
 * request_time / upstream_response_time suffix. Never returns raw lines:
 * only aggregates, plus sensitive-data findings with masked samples.
 */
import { open } from "node:fs/promises";
import type { AccessLogSummary } from "./protocol.js";
import { scanForSensitiveData } from "../security/sensitive.js";
import { percentile } from "../hub/model.js";

export interface AccessRecord {
  time?: string;
  method?: string;
  path?: string;
  status?: number;
  requestMs?: number;
  upstreamMs?: number;
  upstream?: string;
  userAgent?: string;
}

const COMBINED =
  /^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) (\d+|-)(?: "([^"]*)" "([^"]*)")?(?: (?:rt=)?([\d.]+|-))?(?: (?:urt=|uct=)?([\d.,\s-]+))?/;

export function parseAccessLine(line: string): AccessRecord | undefined {
  const trimmed = line.trim();
  if (!trimmed) return undefined;
  if (trimmed.startsWith("{")) {
    try {
      const j = JSON.parse(trimmed) as Record<string, unknown>;
      const num = (v: unknown) => {
        if (v === undefined || v === null || v === "-" || v === "") return undefined;
        const s = String(v).split(",")[0].trim(); // upstream_response_time can be "0.1, 0.2" on retries
        const n = Number(s);
        return Number.isFinite(n) ? n : undefined;
      };
      const path = String(j.uri ?? j.path ?? j.request_uri ?? j.request ?? "").split("?")[0].split(" ")[j.request ? 1 : 0] || String(j.uri ?? j.path ?? "");
      const rt = num(j.request_time);
      const urt = num(j.upstream_response_time);
      return {
        time: (j.time ?? j.time_iso8601 ?? j.timestamp) as string | undefined,
        method: (j.request_method ?? j.method) as string | undefined,
        path: path.split("?")[0],
        status: num(j.status),
        requestMs: rt === undefined ? undefined : rt * 1000,
        upstreamMs: urt === undefined ? undefined : urt * 1000,
        upstream: (j.upstream_addr ?? j.upstream) as string | undefined,
        userAgent: (j.http_user_agent ?? j.user_agent) as string | undefined,
      };
    } catch {
      return undefined;
    }
  }
  const m = COMBINED.exec(trimmed);
  if (!m) return undefined;
  const rt = m[9] && m[9] !== "-" ? Number(m[9]) : undefined;
  const urt = m[10] && m[10] !== "-" ? Number(m[10].split(",")[0]) : undefined;
  return {
    time: m[2],
    method: m[3],
    path: m[4].split("?")[0],
    status: Number(m[5]),
    requestMs: rt === undefined || !Number.isFinite(rt) ? undefined : rt * 1000,
    upstreamMs: urt === undefined || !Number.isFinite(urt) ? undefined : urt * 1000,
    userAgent: m[8],
  };
}

const SUSPICIOUS: Array<{ re: RegExp; reason: string }> = [
  { re: /\/(wp-admin|wp-login\.php|xmlrpc\.php|wp-content)/i, reason: "WordPress probing" },
  { re: /\/\.env\b|\/\.git\b|\/\.aws\b|\/\.ssh\b/i, reason: "dotfile/secret probing" },
  { re: /\/(phpmyadmin|pma|adminer)\b/i, reason: "DB admin probing" },
  { re: /\/(actuator|env|heapdump|threaddump|jolokia)\b/i, reason: "management endpoint access" },
  { re: /\/(cgi-bin|shell|cmd|eval)\b|\.\.\//i, reason: "path traversal / RCE probing" },
  { re: /(%27|%22|'|")\s*(or|and)\s*[\d'"]/i, reason: "SQL injection pattern" },
  { re: /<script|%3Cscript/i, reason: "XSS pattern" },
];

/** Normalizes ids in paths so /products/123 and /products/456 group together. */
export function normalizePath(path: string): string {
  return path
    .replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=\/|$)/gi, "/:uuid")
    .replace(/\/\d+(?=\/|$)/g, "/:id")
    .replace(/\/[0-9a-f]{16,}(?=\/|$)/gi, "/:hash");
}

export function summarizeAccessRecords(records: AccessRecord[], rawLinesForScan: string[] = []): AccessLogSummary {
  const byStatusClass: Record<string, number> = {};
  const byStatus: Record<string, number> = {};
  const paths = new Map<string, { count: number; times: number[]; errors: number }>();
  const upstreams = new Map<string, { count: number; times: number[]; utimes: number[]; errors5xx: number; timeouts504: number }>();
  const gaps: number[] = [];
  const suspicious = new Map<string, { count: number; reason: string }>();
  let clientAbandoned499 = 0;
  let from: string | undefined;
  let to: string | undefined;

  for (const r of records) {
    if (r.time) {
      if (!from) from = r.time;
      to = r.time;
    }
    const status = r.status ?? 0;
    const cls = `${Math.floor(status / 100)}xx`;
    byStatusClass[cls] = (byStatusClass[cls] ?? 0) + 1;
    byStatus[String(status)] = (byStatus[String(status)] ?? 0) + 1;
    if (status === 499) clientAbandoned499++;

    const p = normalizePath(r.path ?? "/");
    const pe = paths.get(p) ?? { count: 0, times: [], errors: 0 };
    pe.count++;
    if (r.requestMs !== undefined) pe.times.push(r.requestMs);
    if (status >= 500) pe.errors++;
    paths.set(p, pe);

    if (r.upstream && r.upstream !== "-") {
      const u = r.upstream.split(",")[0].trim();
      const ue = upstreams.get(u) ?? { count: 0, times: [], utimes: [], errors5xx: 0, timeouts504: 0 };
      ue.count++;
      if (r.requestMs !== undefined) ue.times.push(r.requestMs);
      if (r.upstreamMs !== undefined) ue.utimes.push(r.upstreamMs);
      if (status >= 500) ue.errors5xx++;
      if (status === 504) ue.timeouts504++;
      upstreams.set(u, ue);
    }
    if (r.requestMs !== undefined && r.upstreamMs !== undefined) gaps.push(Math.max(0, r.requestMs - r.upstreamMs));

    for (const s of SUSPICIOUS) {
      if (s.re.test(r.path ?? "")) {
        const se = suspicious.get(p) ?? { count: 0, reason: s.reason };
        se.count++;
        suspicious.set(p, se);
        break;
      }
    }
  }

  const pct = (arr: number[], p: number) => (arr.length ? Math.round(percentile([...arr].sort((a, b) => a - b), p)) : undefined);
  const findings = rawLinesForScan.length ? scanForSensitiveData(rawLinesForScan, { exclude: ["phone", "ipv4_private"] }) : [];

  return {
    available: true,
    lines: records.length,
    window: { from, to },
    byStatusClass,
    byStatus,
    topPaths: [...paths.entries()]
      .map(([path, e]) => ({ path, count: e.count, p50Ms: pct(e.times, 50), p95Ms: pct(e.times, 95), errors: e.errors }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 30),
    byUpstream: [...upstreams.entries()]
      .map(([upstream, e]) => ({
        upstream,
        count: e.count,
        p50Ms: pct(e.times, 50),
        p95Ms: pct(e.times, 95),
        p95UpstreamMs: pct(e.utimes, 95),
        errors5xx: e.errors5xx,
        timeouts504: e.timeouts504,
      }))
      .sort((a, b) => b.count - a.count),
    clientAbandoned499,
    requestVsUpstreamGapP95Ms: pct(gaps, 95),
    suspiciousPaths: [...suspicious.entries()]
      .map(([path, e]) => ({ path, count: e.count, reason: e.reason }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 20),
    sensitive: findings.map((f) => ({ kind: f.kind, count: f.count, sample: f.sample })),
  };
}

/** Reads the tail of a log file (bounded) and summarizes it. */
export async function summarizeAccessLogFile(path: string, maxBytes = 8 * 1024 * 1024, sinceSeconds?: number): Promise<AccessLogSummary> {
  let fh;
  try {
    fh = await open(path, "r");
  } catch (err) {
    return {
      available: false,
      note: `access log not readable: ${err instanceof Error ? err.message : String(err)}`,
      lines: 0,
      byStatusClass: {},
      byStatus: {},
      topPaths: [],
      byUpstream: [],
      clientAbandoned499: 0,
      suspiciousPaths: [],
    };
  }
  try {
    const { size } = await fh.stat();
    const start = Math.max(0, size - maxBytes);
    const buf = Buffer.alloc(size - start);
    await fh.read(buf, 0, buf.length, start);
    let text = buf.toString("utf8");
    if (start > 0) text = text.slice(text.indexOf("\n") + 1);
    const lines = text.split("\n").filter(Boolean);
    const cutoff = sinceSeconds ? Date.now() - sinceSeconds * 1000 : undefined;
    const records: AccessRecord[] = [];
    const kept: string[] = [];
    for (const line of lines) {
      const r = parseAccessLine(line);
      if (!r) continue;
      if (cutoff && r.time) {
        const t = Date.parse(r.time.replace(/^(\d+)\/(\w+)\/(\d+):(\d+:\d+:\d+) ([+-]\d+)$/, "$1 $2 $3 $4 $5"));
        if (Number.isFinite(t) && t < cutoff) continue;
      }
      records.push(r);
      kept.push(line);
    }
    const summary = summarizeAccessRecords(records, kept);
    if (start > 0) summary.note = `only the last ${Math.round(maxBytes / 1024 / 1024)}MiB of the file were read`;
    return summary;
  } finally {
    await fh.close();
  }
}

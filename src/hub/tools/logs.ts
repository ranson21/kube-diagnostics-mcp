import type { ToolContext } from "../context.js";
import { nsOf } from "../context.js";
import { appContainerName, resolveWorkload } from "../model.js";
import { parseWindowSeconds, clampLimit } from "../../security/guard.js";
import { redactText } from "../../security/sanitize.js";
import { scanForSensitiveData } from "../../security/sensitive.js";

async function podsFor(ctx: ToolContext, ns: string, args: { service?: string; pod?: string }) {
  if (args.pod) return [await ctx.k8s.getPod(ns, args.pod)];
  if (args.service) return (await resolveWorkload(ctx.k8s, ns, args.service)).pods;
  throw new Error("Provide either `service` or `pod`.");
}

export async function getLogs(ctx: ToolContext, args: { namespace?: string; service?: string; pod?: string; container?: string; since?: string; tail?: number; grep?: string; previous?: boolean }) {
  const ns = nsOf(ctx, args.namespace);
  const pods = await podsFor(ctx, ns, args);
  const sinceSeconds = args.since ? parseWindowSeconds(args.since, 900) : undefined;
  const tail = clampLimit(args.tail, 200, ctx.config.logMaxLines);
  const re = args.grep ? safeRegex(args.grep) : undefined;
  const results = [];
  for (const pod of pods.slice(0, 10)) {
    const container = args.container ?? appContainerName(pod, ctx.config.probeContainerName);
    try {
      const text = await ctx.k8s.readPodLog(ns, pod.metadata?.name ?? "", { container, sinceSeconds, tailLines: tail, previous: args.previous, limitBytes: ctx.config.logMaxBytes, timestamps: true });
      let lines = text.split("\n").filter(Boolean);
      const total = lines.length;
      if (re) lines = lines.filter((l) => re.test(l));
      else if (args.grep) lines = lines.filter((l) => l.includes(args.grep!));
      results.push({ pod: pod.metadata?.name, container, lines: lines.slice(-tail).map(redactText), matched: lines.length, fetched: total });
    } catch (err) {
      results.push({ pod: pod.metadata?.name, container, error: err instanceof Error ? err.message : String(err) });
    }
  }
  return { namespace: ns, previous: Boolean(args.previous), results, note: pods.length > 10 ? `only the first 10 of ${pods.length} pods were read` : undefined };
}

const LEVEL_RE = /\b(ERROR|SEVERE|FATAL|CRITICAL|WARN(?:ING)?|Exception|Traceback|panic:|level=(?:error|warn|fatal))\b/i;

/** Normalizes a log line into a signature: drops timestamps, numbers, ids, and hex. */
export function logSignature(line: string): string {
  return line
    .replace(/^\S+\s+/, "") // kubectl timestamp prefix
    .replace(/\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?/g, "<ts>")
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, "<uuid>")
    .replace(/\b[0-9a-f]{16,}\b/gi, "<hex>")
    .replace(/\b\d+(?:\.\d+)?/g, "N")
    .replace(/\[(?:[\w-]+-)?(?:exec|nio|http|pool|thread|worker)[^\]]*\]/gi, "[<thread>]")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 200);
}

/** Structured (JSON) log line -> level, message, exception type, stack. Supports ECS, logstash, and flat shapes. */
export function parseJsonLog(line: string): { level?: string; message: string; exceptionType?: string; stack?: string; logger?: string } | undefined {
  const start = line.indexOf("{");
  if (start < 0 || !line.trimEnd().endsWith("}")) return undefined;
  try {
    const j = JSON.parse(line.slice(start)) as Record<string, unknown>;
    const log = j.log as Record<string, unknown> | undefined;
    const error = j.error as Record<string, unknown> | undefined;
    const level = (log?.level ?? j.level ?? j.severity ?? j["log.level"]) as string | undefined;
    const message = String(j.message ?? j.msg ?? j.event ?? "");
    if (!message && !error) return undefined;
    return {
      level: level ? String(level).toUpperCase() : undefined,
      message,
      exceptionType: (error?.type ?? j.exception_class ?? j["exception.type"]) as string | undefined,
      stack: (error?.stack_trace ?? j.stack_trace ?? j.exception ?? j["error.stack_trace"]) as string | undefined,
      logger: (log?.logger ?? j.logger ?? j.logger_name) as string | undefined,
    };
  } catch {
    return undefined;
  }
}

const APP_FRAME_SKIP = /^(java\.|javax\.|jakarta\.|sun\.|jdk\.|org\.springframework\.|org\.apache\.|org\.hibernate\.|com\.zaxxer\.|io\.netty\.|reactor\.|kotlin\.)/;

export function firstAppFrame(stack: string | undefined): string | undefined {
  if (!stack) return undefined;
  for (const l of stack.split(/\r?\n/).slice(0, 80)) {
    const m = /^\s*at\s+([\w$.]+)\(/.exec(l);
    if (m && !APP_FRAME_SKIP.test(m[1])) return m[1];
  }
  return undefined;
}

/** Java-aware: an exception class + the first application frame make a better signature than the message. */
export function javaSignature(lines: string[], idx: number): string | undefined {
  const line = lines[idx];
  const exc = /\b([a-zA-Z_$][\w$]*(?:\.[a-zA-Z_$][\w$]*)+(?:Exception|Error|Throwable))\b(?::\s*(.{0,80}))?/.exec(line);
  if (!exc) return undefined;
  let frame: string | undefined;
  for (let j = idx + 1; j < Math.min(lines.length, idx + 40); j++) {
    const m = /^\s*at\s+([\w$.]+)\(/.exec(lines[j]);
    if (m && !/^(java\.|javax\.|jakarta\.|sun\.|jdk\.|org\.springframework\.|org\.apache\.|org\.hibernate\.|com\.zaxxer\.|io\.netty\.|reactor\.)/.test(m[1])) {
      frame = m[1];
      break;
    }
  }
  return `${exc[1]}${frame ? ` @ ${frame}` : ""}`;
}

export async function summarizeLogErrors(ctx: ToolContext, args: { namespace?: string; service?: string; pod?: string; since?: string; include_warnings?: boolean }) {
  const ns = nsOf(ctx, args.namespace);
  const pods = await podsFor(ctx, ns, args);
  const sinceSeconds = parseWindowSeconds(args.since, 3600);
  const groups = new Map<string, { count: number; first?: string; last?: string; sample: string; pods: Set<string>; level: string }>();
  let scanned = 0;
  let truncated = false;
  for (const pod of pods.slice(0, 20)) {
    const container = appContainerName(pod, ctx.config.probeContainerName);
    let text: string;
    try {
      text = await ctx.k8s.readPodLog(ns, pod.metadata?.name ?? "", { container, sinceSeconds, tailLines: ctx.config.logMaxLines * 4, limitBytes: ctx.config.logMaxBytes * 2, timestamps: true });
    } catch {
      continue;
    }
    const lines = text.split("\n").filter(Boolean);
    scanned += lines.length;
    if (lines.length >= ctx.config.logMaxLines * 4) truncated = true;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const ts = /^(\S+)\s/.exec(line)?.[1];
      const body = line.replace(/^\S+\s+/, "");
      const json = parseJsonLog(body);
      let level: string;
      let sig: string;
      let sampleText: string;
      if (json) {
        const lv = json.level ?? (LEVEL_RE.exec(json.message)?.[1] ?? "");
        if (!/error|severe|fatal|critical|warn/i.test(lv) && !json.exceptionType) continue;
        level = /warn/i.test(lv) ? "WARN" : "ERROR";
        if (level === "WARN" && !args.include_warnings) continue;
        const frame = firstAppFrame(json.stack);
        sig = json.exceptionType ? `${json.exceptionType}${frame ? ` @ ${frame}` : ""}` : `${json.logger ? `${json.logger.split(".").pop()}: ` : ""}${logSignature(json.message)}`;
        sampleText = `${json.logger ? `[${json.logger}] ` : ""}${json.message}${json.exceptionType ? ` (${json.exceptionType})` : ""}`;
      } else {
        const m = LEVEL_RE.exec(line);
        if (!m) continue;
        level = /warn/i.test(m[1]) ? "WARN" : "ERROR";
        if (level === "WARN" && !args.include_warnings) continue;
        if (/^\s*at\s+[\w$.]+\(/.test(line) || /^\s*\.\.\. \d+ (more|common frames omitted)/.test(line)) continue; // stack frame lines
        sig = javaSignature(lines, i) ?? logSignature(body);
        sampleText = body;
      }
      const g = groups.get(sig) ?? { count: 0, sample: redactText(sampleText.slice(0, 300)), pods: new Set(), level };
      g.count++;
      if (ts) {
        if (!g.first || ts < g.first) g.first = ts;
        if (!g.last || ts > g.last) g.last = ts;
      }
      g.pods.add(pod.metadata?.name ?? "");
      groups.set(sig, g);
    }
  }
  const out = [...groups.entries()].map(([signature, g]) => ({ signature, level: g.level, count: g.count, firstSeen: g.first, lastSeen: g.last, pods: [...g.pods], sample: g.sample })).sort((a, b) => b.count - a.count);
  return { namespace: ns, since: `${sinceSeconds}s`, linesScanned: scanned, truncated, groups: out.slice(0, 40), distinct: out.length, totalMatches: out.reduce((a, g) => a + g.count, 0) };
}

export async function scanLogsForSensitiveData(ctx: ToolContext, args: { namespace?: string; service?: string; pod?: string; since?: string }) {
  const ns = nsOf(ctx, args.namespace);
  const pods = await podsFor(ctx, ns, args);
  const sinceSeconds = parseWindowSeconds(args.since, 3600);
  const perPod = [];
  let scanned = 0;
  for (const pod of pods.slice(0, 20)) {
    const container = appContainerName(pod, ctx.config.probeContainerName);
    let text: string;
    try {
      text = await ctx.k8s.readPodLog(ns, pod.metadata?.name ?? "", { container, sinceSeconds, tailLines: ctx.config.logMaxLines * 4, limitBytes: ctx.config.logMaxBytes * 2 });
    } catch (err) {
      perPod.push({ pod: pod.metadata?.name, error: err instanceof Error ? err.message : String(err) });
      continue;
    }
    const lines = text.split("\n").filter(Boolean);
    scanned += lines.length;
    const findings = scanForSensitiveData(lines, { exclude: ["ipv4_private"] });
    if (findings.length) perPod.push({ pod: pod.metadata?.name, container, lines: lines.length, findings });
  }
  const totals = new Map<string, number>();
  for (const p of perPod) for (const f of (p as { findings?: Array<{ kind: string; count: number }> }).findings ?? []) totals.set(f.kind, (totals.get(f.kind) ?? 0) + f.count);
  return {
    namespace: ns,
    since: `${sinceSeconds}s`,
    linesScanned: scanned,
    verdict: totals.size ? "SENSITIVE DATA FOUND IN LOGS" : "no sensitive-data patterns matched",
    totalsByKind: Object.fromEntries(totals),
    perPod,
    note: "Samples are masked; values are never returned. Pattern matching has false positives (phone/low confidence) - verify high-confidence kinds first.",
  };
}

function safeRegex(q: string): RegExp | undefined {
  if (!/^\/.+\/[imsu]*$/.test(q)) return undefined;
  const last = q.lastIndexOf("/");
  try {
    return new RegExp(q.slice(1, last), q.slice(last + 1));
  } catch {
    return undefined;
  }
}

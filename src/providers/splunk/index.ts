/**
 * Splunk provider (Splunk Enterprise / Splunk Cloud Platform REST API).
 *
 * Runs oneshot SPL searches via POST /services/search/jobs. Provides log
 * search over your Kubernetes log index and, when DIAG_SPLUNK_REQUEST_LOG_SEARCH
 * points at structured request logs (e.g. the nginx JSON access log), golden
 * signals computed with `stats`. Splunk Observability Cloud (SignalFlow/APM)
 * is a different API and is not covered here.
 *
 * Enable with DIAG_SPLUNK_URL (https://splunk:8089) + DIAG_SPLUNK_TOKEN (an
 * authentication token; set DIAG_SPLUNK_AUTH_SCHEME=Splunk for a session key).
 * Field names default to Splunk Connect for Kubernetes (namespace,
 * container_name); override with DIAG_SPLUNK_NAMESPACE_FIELD / _SERVICE_FIELD.
 */
import { Agent } from "undici";
import type { SplunkConfig } from "../../config.js";
import type { Capability, GoldenSignals, LogSearchResult, ProviderContext, SignalProvider } from "../types.js";

interface OneshotResponse {
  results?: Array<Record<string, string>>;
  fields?: Array<{ name: string }>;
  messages?: Array<{ type: string; text: string }>;
}

/** Quote a value for SPL (double quotes, backslash-escaped). */
export function splQuote(v: string): string {
  return `"${v.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

export class SplunkProvider implements SignalProvider {
  readonly name = "splunk";
  readonly capabilities: Capability[];
  private readonly dispatcher: Agent | undefined;

  constructor(
    private readonly cfg: SplunkConfig,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {
    this.capabilities = cfg.requestLogSearch ? ["logSearch", "goldenSignals"] : ["logSearch"];
    this.dispatcher = cfg.verifyTls ? undefined : new Agent({ connect: { rejectUnauthorized: false } });
  }

  private get indexClause(): string {
    return this.cfg.index ? `index=${splQuote(this.cfg.index)}` : "index=*";
  }

  /** Runs `search <spl>` as a oneshot job and returns rows. Exposed for tests. */
  async oneshot(spl: string, earliest: string, latest = "now", count = 500): Promise<OneshotResponse> {
    const body = new URLSearchParams({
      search: spl.trim().startsWith("search ") || spl.trim().startsWith("|") ? spl : `search ${spl}`,
      exec_mode: "oneshot",
      output_mode: "json",
      earliest_time: earliest,
      latest_time: latest,
      count: String(count),
    });
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), this.cfg.timeoutMs);
    try {
      const r = await this.fetchImpl(`${this.cfg.url}/services/search/jobs`, {
        method: "POST",
        headers: { authorization: `${this.cfg.authScheme} ${this.cfg.token}`, "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
        body,
        signal: ctl.signal,
        ...(this.dispatcher ? ({ dispatcher: this.dispatcher } as RequestInit) : {}),
      });
      const text = await r.text();
      if (!r.ok) throw new Error(`splunk search: HTTP ${r.status}${text ? ` - ${text.slice(0, 200).replace(/\s+/g, " ")}` : ""}`);
      const json = JSON.parse(text) as OneshotResponse;
      const fatal = (json.messages ?? []).filter((m) => m.type === "FATAL" || m.type === "ERROR");
      if (fatal.length) throw new Error(`splunk search: ${fatal.map((m) => m.text).join("; ")}`);
      return json;
    } finally {
      clearTimeout(t);
    }
  }

  async status() {
    try {
      const ctl = new AbortController();
      const t = setTimeout(() => ctl.abort(), 5000);
      const r = await this.fetchImpl(`${this.cfg.url}/services/server/info?output_mode=json`, {
        headers: { authorization: `${this.cfg.authScheme} ${this.cfg.token}` },
        signal: ctl.signal,
        ...(this.dispatcher ? ({ dispatcher: this.dispatcher } as RequestInit) : {}),
      }).finally(() => clearTimeout(t));
      const j = (await r.json().catch(() => ({}))) as { entry?: Array<{ content?: { version?: string; serverName?: string } }> };
      const c = j.entry?.[0]?.content;
      return { configured: true, reachable: r.ok, detail: r.ok ? `${this.cfg.url} v${c?.version ?? "?"} (${c?.serverName ?? "?"}) index=${this.cfg.index ?? "*"}${this.cfg.requestLogSearch ? " request-logs=yes" : ""}` : `${this.cfg.url}: HTTP ${r.status}` };
    } catch (err) {
      return { configured: true, reachable: false, detail: `${this.cfg.url}: ${err instanceof Error ? err.message : String(err)}` };
    }
  }

  async logSearch(ctx: ProviderContext, query: string, limit: number): Promise<LogSearchResult | undefined> {
    const svc = ctx.service.replace(/[^\w.-]/g, "");
    const scope = `${this.indexClause} ${this.cfg.namespaceField}=${splQuote(ctx.namespace)} (${this.cfg.serviceField}=${splQuote(svc)} OR ${this.cfg.serviceField}=${splQuote(`${svc}*`)})`;
    // A query wrapped in /.../ is a regex; anything else is a free-text term list.
    const term = query ? (/^\/.+\/[imsu]*$/.test(query) ? `| regex _raw=${splQuote(query.slice(1, query.lastIndexOf("/")))}` : query.replace(/\|/g, " ")) : "";
    const spl = term.startsWith("|") ? `${scope} ${term} | head ${limit}` : `${scope} ${term} | head ${limit}`;
    const r = await this.oneshot(spl, `-${ctx.windowSeconds}s`, "now", limit);
    const lines = (r.results ?? []).map((row) => `${row._time ?? ""} ${row._raw ?? JSON.stringify(row)}`.trim());
    return { lines, truncated: lines.length >= limit, source: `splunk:${this.cfg.index ?? "*"}` };
  }

  async goldenSignals(ctx: ProviderContext): Promise<GoldenSignals | undefined> {
    if (!this.cfg.requestLogSearch) return undefined;
    const f = this.cfg.requestFields;
    const base = `${this.indexClause} ${this.cfg.requestLogSearch} ${this.cfg.namespaceField}=${splQuote(ctx.namespace)}`;
    const totals = await this.oneshot(
      `${base} | stats count as hits, count(eval(${f.status}>=500)) as err5, count(eval(${f.status}>=400)) as err, perc50(${f.durationSeconds}) as p50, perc95(${f.durationSeconds}) as p95, perc99(${f.durationSeconds}) as p99`,
      `-${ctx.windowSeconds}s`,
    );
    const t = totals.results?.[0];
    const hits = Number(t?.hits ?? 0);
    if (!hits) return undefined;
    const byPath = await this.oneshot(
      `${base} | stats count as hits, count(eval(${f.status}>=500)) as err5, perc95(${f.durationSeconds}) as p95 by ${f.method}, ${f.path} | sort - hits | head 25`,
      `-${ctx.windowSeconds}s`,
    );
    const ms = (v: string | undefined) => (v === undefined || v === "" ? undefined : Math.round(Number(v) * 1000));
    return {
      service: ctx.service,
      namespace: ctx.namespace,
      windowSeconds: ctx.windowSeconds,
      requestRate: hits / ctx.windowSeconds,
      errorRate: Number(t?.err ?? 0) / hits,
      errorRate5xx: Number(t?.err5 ?? 0) / hits,
      latencyMs: { p50: ms(t?.p50), p95: ms(t?.p95), p99: ms(t?.p99) },
      byEndpoint: (byPath.results ?? []).map((row) => {
        const c = Number(row.hits ?? 0);
        return { endpoint: row[f.path] ?? "?", method: row[f.method], requestRate: c / ctx.windowSeconds, errorRate: c ? Number(row.err5 ?? 0) / c : 0, p95Ms: ms(row.p95) };
      }),
      source: `splunk:${this.cfg.requestLogSearch}`,
      note: "computed from proxy request logs (user-facing latency incl. proxy), not from the service's own metrics",
    };
  }
}

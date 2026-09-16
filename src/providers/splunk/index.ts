/**
 * Splunk provider - PLACEHOLDER.
 *
 * Splunk's REST/MCP endpoints are not reachable from the environments this
 * project currently targets. This provider validates configuration and
 * reports itself as "configured, not implemented". Intended mapping:
 *   logSearch     -> POST /services/search/jobs (SPL: index=<idx> kubernetes.namespace=<ns> kubernetes.container_name=<svc>)
 *   goldenSignals -> Observability Cloud SignalFlow (if licensed), else SPL over access logs
 *   slowTraces    -> Observability Cloud APM (if licensed)
 * Tokens never leave this process.
 */
import type { SignalProvider } from "../types.js";

export class SplunkProvider implements SignalProvider {
  readonly name = "splunk";
  readonly capabilities: SignalProvider["capabilities"] = [];

  constructor(private readonly cfg: { url: string; token: string; index?: string }) {}

  async status() {
    return {
      configured: true,
      reachable: undefined,
      detail: `url=${this.cfg.url}${this.cfg.index ? ` index=${this.cfg.index}` : ""}; token present; provider not implemented yet - see src/providers/splunk/index.ts`,
    };
  }
}

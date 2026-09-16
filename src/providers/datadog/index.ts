/**
 * Datadog provider - PLACEHOLDER.
 *
 * Datadog's APIs and MCP server are not reachable from the environments this
 * project currently targets, so this provider only validates configuration
 * and reports itself as "configured, not implemented". The contract it will
 * fulfil is SignalProvider; the intended mapping is:
 *   goldenSignals  -> /api/v2/query/timeseries (trace.servlet.request.hits/errors/duration by service)
 *   resourceUsage  -> kubernetes.cpu.usage.total, kubernetes.memory.working_set, kubernetes.cpu.cfs.throttled.periods
 *   slowTraces     -> /api/v2/spans/events/search (filter service:, @duration:>)
 *   trace          -> /api/v2/spans/events/search (trace_id:)
 *   logSearch      -> /api/v2/logs/events/search
 *   webVitals      -> /api/v2/rum/events/search (@type:view, @view.largest_contentful_paint ...)
 * Keys never leave this process; the hub, not the model, holds them.
 */
import type { SignalProvider } from "../types.js";

export class DatadogProvider implements SignalProvider {
  readonly name = "datadog";
  readonly capabilities: SignalProvider["capabilities"] = [];

  constructor(private readonly cfg: { site: string; apiKey: string; appKey: string }) {}

  async status() {
    return {
      configured: true,
      reachable: undefined,
      detail: `site=${this.cfg.site}; keys present; provider not implemented yet - see src/providers/datadog/index.ts`,
    };
  }
}

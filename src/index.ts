#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadConfig, summarize, ConfigError, type HubConfig } from "./config.js";
import { createLogger } from "./logger.js";
import { ReadOnlyKubeClient, loadKubeConfig } from "./k8s/client.js";
import { ProbeClient } from "./probe/client.js";
import { ProviderRegistry, type SignalProvider } from "./providers/types.js";
import { NativeProvider } from "./providers/native/index.js";
import { PrometheusProvider } from "./providers/prometheus/index.js";
import { DatadogProvider } from "./providers/datadog/index.js";
import { SplunkProvider } from "./providers/splunk/index.js";
import { createServer } from "./hub/server.js";
import { startHttp } from "./hub/transport/http.js";
import { startProbe } from "./probe/server.js";
import type { ToolContext } from "./hub/context.js";

function buildContext(config: HubConfig, logger: ReturnType<typeof createLogger>): ToolContext {
  const kc = loadKubeConfig();
  const k8s = new ReadOnlyKubeClient(kc, { namespaces: config.namespaces, timeoutMs: config.k8sTimeoutMs });
  const probe = new ProbeClient(config);
  const providers: SignalProvider[] = [];
  // Priority: Prometheus (windowed, cheap) before native (probe fan-out).
  if (config.providers.prometheusUrl) providers.push(new PrometheusProvider({ baseUrl: config.providers.prometheusUrl, httpMetric: process.env.DIAG_PROM_HTTP_METRIC, serviceLabel: process.env.DIAG_PROM_SERVICE_LABEL }));
  providers.push(new NativeProvider(k8s, probe, config.probeContainerName, { lines: config.logMaxLines, bytes: config.logMaxBytes }));
  if (config.providers.datadog) providers.push(new DatadogProvider(config.providers.datadog));
  if (config.providers.splunk) providers.push(new SplunkProvider(config.providers.splunk));
  return { k8s, probe, providers: new ProviderRegistry(providers), config, logger };
}

async function main() {
  const logger = createLogger();
  let config;
  try {
    config = loadConfig();
  } catch (err) {
    if (err instanceof ConfigError) {
      logger.error("startup failed", { reason: err.message });
      process.exit(1);
    }
    throw err;
  }

  if (config.mode === "probe") {
    await startProbe(config, createLogger(process.env, "kube-diagnostics-probe"));
    logger.info("probe started", summarize(config));
    return;
  }

  const ctx = buildContext(config, logger);
  if (config.transport === "http") {
    await startHttp(config, logger, () => createServer(ctx));
  } else {
    const server = createServer(ctx);
    await server.connect(new StdioServerTransport());
  }
  logger.info("hub started", { ...summarize(config), context: ctx.k8s.contextName, readOnly: true });
}

main().catch((err) => {
  console.error(`[${new Date().toISOString()}] [ERROR] [kube-diagnostics-mcp] fatal error: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});

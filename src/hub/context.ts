import type { HubConfig } from "../config.js";
import type { ReadOnlyKubeClient } from "../k8s/client.js";
import type { LoggerLike } from "../logger.js";
import type { ProbeClient } from "../probe/client.js";
import type { ProviderRegistry } from "../providers/types.js";
import { GuardError } from "../security/guard.js";

export interface ToolContext {
  k8s: ReadOnlyKubeClient;
  probe: ProbeClient;
  providers: ProviderRegistry;
  config: HubConfig;
  logger: LoggerLike;
}

/** Resolves the namespace argument against the configured default. */
export function nsOf(ctx: ToolContext, namespace: string | undefined): string {
  const ns = namespace ?? ctx.config.defaultNamespace;
  if (!ns) {
    throw new GuardError(
      "namespace is required (no DIAG_DEFAULT_NAMESPACE configured). Call list_namespaces to see what is available.",
    );
  }
  return ns;
}

export function requireActive(ctx: ToolContext, what: string): void {
  if (!ctx.config.allowActiveChecks) {
    throw new GuardError(`${what} is an active check (it generates traffic) and is disabled. Set DIAG_ALLOW_ACTIVE_CHECKS=true on the hub and the probe to enable it.`);
  }
}

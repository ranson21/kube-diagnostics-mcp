import { readFileSync } from "node:fs";

export type Mode = "hub" | "probe";
export type Transport = "stdio" | "http";

export class ConfigError extends Error {}

export interface ProviderConfig {
  /** Optional Prometheus-compatible HTTP API base URL (e.g. http://prometheus.monitoring:9090). */
  prometheusUrl?: string;
  /** Datadog: recognized now, provider implemented later (see src/providers/datadog). */
  datadog?: { site: string; apiKey: string; appKey: string };
  /** Splunk: recognized now, provider implemented later (see src/providers/splunk). */
  splunk?: { url: string; token: string; index?: string };
}

export interface HubConfig {
  mode: "hub";
  transport: Transport;
  httpHost: string;
  httpPort: number;
  /** Bearer token clients must present. Required in http mode unless allowUnauthenticated. */
  httpToken?: string;
  allowUnauthenticated: boolean;
  /** Namespaces the hub may look at. Empty = every namespace RBAC allows. */
  namespaces: string[];
  defaultNamespace?: string;
  allowActiveChecks: boolean;
  logMaxLines: number;
  logMaxBytes: number;
  maxResultBytes: number;
  /** How to find probe sidecars: container name and port. */
  probeContainerName: string;
  probePort: number;
  probeToken?: string;
  probeTimeoutMs: number;
  k8sTimeoutMs: number;
  providers: ProviderConfig;
}

export interface ProbeConfig {
  mode: "probe";
  host: string;
  port: number;
  /** Shared bearer token the hub must present. Required unless allowUnauthenticated. */
  token?: string;
  allowUnauthenticated: boolean;
  allowActiveChecks: boolean;
  /** e.g. http://127.0.0.1:8080/actuator */
  actuatorUrl?: string;
  /** e.g. http://127.0.0.1:8081/stub_status */
  nginxStatusUrl?: string;
  /** Directory holding the served static build (for bundle stats). */
  staticDir?: string;
  /** Path to the proxy's access log, if it is written to a shared volume. */
  accessLogPath?: string;
  rumEnabled: boolean;
  rumMaxBodyBytes: number;
  rumRetentionMinutes: number;
  /** Pod/namespace identity, injected via the downward API. */
  podName?: string;
  podNamespace?: string;
}

export type AppConfig = HubConfig | ProbeConfig;

function parsePositiveInt(name: string, raw: string | undefined, fallback: number): number {
  if (!raw?.trim()) return fallback;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n <= 0) throw new ConfigError(`${name} must be a positive integer, got: ${raw}`);
  return n;
}

function parseBool(raw: string | undefined, fallback = false): boolean {
  if (raw === undefined || raw.trim() === "") return fallback;
  const v = raw.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(v)) return true;
  if (["0", "false", "no", "off"].includes(v)) return false;
  throw new ConfigError(`Expected a boolean (true/false), got: ${raw}`);
}

function parseList(raw: string | undefined): string[] {
  return (raw ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function optional(raw: string | undefined): string | undefined {
  const v = raw?.trim();
  return v ? v : undefined;
}

/** A secret from VAR, or from the file named by VAR_FILE (preferred: keeps it out of the pod spec/env). */
function secret(env: NodeJS.ProcessEnv, name: string): string | undefined {
  const file = optional(env[`${name}_FILE`]);
  if (file) {
    try {
      const v = readFileSync(file, "utf8").trim();
      if (v) return v;
      throw new ConfigError(`${name}_FILE (${file}) is empty`);
    } catch (err) {
      if (err instanceof ConfigError) throw err;
      throw new ConfigError(`${name}_FILE (${file}) could not be read: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  return optional(env[name]);
}

function parseProviders(env: NodeJS.ProcessEnv): ProviderConfig {
  const out: ProviderConfig = {};
  const prom = optional(env.DIAG_PROMETHEUS_URL);
  if (prom) out.prometheusUrl = prom.replace(/\/+$/, "");

  const ddApi = optional(env.DIAG_DATADOG_API_KEY);
  const ddApp = optional(env.DIAG_DATADOG_APP_KEY);
  if (ddApi || ddApp) {
    if (!ddApi || !ddApp) throw new ConfigError("DIAG_DATADOG_API_KEY and DIAG_DATADOG_APP_KEY must be set together.");
    out.datadog = { site: optional(env.DIAG_DATADOG_SITE) ?? "datadoghq.com", apiKey: ddApi, appKey: ddApp };
  }

  const splunkUrl = optional(env.DIAG_SPLUNK_URL);
  const splunkToken = optional(env.DIAG_SPLUNK_TOKEN);
  if (splunkUrl || splunkToken) {
    if (!splunkUrl || !splunkToken) throw new ConfigError("DIAG_SPLUNK_URL and DIAG_SPLUNK_TOKEN must be set together.");
    out.splunk = { url: splunkUrl.replace(/\/+$/, ""), token: splunkToken, index: optional(env.DIAG_SPLUNK_INDEX) };
  }
  return out;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const mode = (optional(env.DIAG_MODE) ?? "hub").toLowerCase();
  if (mode !== "hub" && mode !== "probe") throw new ConfigError(`DIAG_MODE must be "hub" or "probe", got: ${mode}`);

  if (mode === "probe") {
    const allowUnauthenticated = parseBool(env.DIAG_PROBE_ALLOW_UNAUTHENTICATED, false);
    const token = secret(env, "DIAG_PROBE_TOKEN");
    if (!token && !allowUnauthenticated) {
      throw new ConfigError(
        "DIAG_PROBE_TOKEN is required in probe mode (or set DIAG_PROBE_ALLOW_UNAUTHENTICATED=true for local dev only).",
      );
    }
    return {
      mode: "probe",
      host: optional(env.DIAG_PROBE_HOST) ?? "0.0.0.0",
      port: parsePositiveInt("DIAG_PROBE_PORT", env.DIAG_PROBE_PORT, 9911),
      token,
      allowUnauthenticated,
      allowActiveChecks: parseBool(env.DIAG_ALLOW_ACTIVE_CHECKS, false),
      actuatorUrl: optional(env.DIAG_PROBE_ACTUATOR_URL)?.replace(/\/+$/, ""),
      nginxStatusUrl: optional(env.DIAG_PROBE_NGINX_STATUS_URL),
      staticDir: optional(env.DIAG_PROBE_STATIC_DIR),
      accessLogPath: optional(env.DIAG_PROBE_ACCESS_LOG_PATH),
      rumEnabled: parseBool(env.DIAG_PROBE_RUM_ENABLED, false),
      rumMaxBodyBytes: parsePositiveInt("DIAG_PROBE_RUM_MAX_BODY_BYTES", env.DIAG_PROBE_RUM_MAX_BODY_BYTES, 8192),
      rumRetentionMinutes: parsePositiveInt("DIAG_PROBE_RUM_RETENTION_MINUTES", env.DIAG_PROBE_RUM_RETENTION_MINUTES, 360),
      podName: optional(env.DIAG_POD_NAME),
      podNamespace: optional(env.DIAG_POD_NAMESPACE),
    };
  }

  const transport = (optional(env.DIAG_TRANSPORT) ?? "stdio").toLowerCase();
  if (transport !== "stdio" && transport !== "http") {
    throw new ConfigError(`DIAG_TRANSPORT must be "stdio" or "http", got: ${transport}`);
  }
  const allowUnauthenticated = parseBool(env.DIAG_HTTP_ALLOW_UNAUTHENTICATED, false);
  const httpToken = secret(env, "DIAG_HTTP_TOKEN");
  if (transport === "http" && !httpToken && !allowUnauthenticated) {
    throw new ConfigError(
      "DIAG_HTTP_TOKEN is required when DIAG_TRANSPORT=http (or set DIAG_HTTP_ALLOW_UNAUTHENTICATED=true for local dev only).",
    );
  }
  const namespaces = parseList(env.DIAG_NAMESPACES);
  const defaultNamespace = optional(env.DIAG_DEFAULT_NAMESPACE) ?? (namespaces.length === 1 ? namespaces[0] : undefined);
  if (defaultNamespace && namespaces.length && !namespaces.includes(defaultNamespace)) {
    throw new ConfigError(`DIAG_DEFAULT_NAMESPACE "${defaultNamespace}" is not in DIAG_NAMESPACES.`);
  }

  return {
    mode: "hub",
    transport,
    httpHost: optional(env.DIAG_HTTP_HOST) ?? "0.0.0.0",
    httpPort: parsePositiveInt("DIAG_HTTP_PORT", env.DIAG_HTTP_PORT, 8090),
    httpToken,
    allowUnauthenticated,
    namespaces,
    defaultNamespace,
    allowActiveChecks: parseBool(env.DIAG_ALLOW_ACTIVE_CHECKS, false),
    logMaxLines: parsePositiveInt("DIAG_LOG_MAX_LINES", env.DIAG_LOG_MAX_LINES, 500),
    logMaxBytes: parsePositiveInt("DIAG_LOG_MAX_BYTES", env.DIAG_LOG_MAX_BYTES, 256 * 1024),
    maxResultBytes: parsePositiveInt("DIAG_MAX_RESULT_BYTES", env.DIAG_MAX_RESULT_BYTES, 200 * 1024),
    probeContainerName: optional(env.DIAG_PROBE_CONTAINER_NAME) ?? "diag-probe",
    probePort: parsePositiveInt("DIAG_PROBE_PORT", env.DIAG_PROBE_PORT, 9911),
    probeToken: secret(env, "DIAG_PROBE_TOKEN"),
    probeTimeoutMs: parsePositiveInt("DIAG_PROBE_TIMEOUT_MS", env.DIAG_PROBE_TIMEOUT_MS, 5000),
    k8sTimeoutMs: parsePositiveInt("DIAG_K8S_TIMEOUT_MS", env.DIAG_K8S_TIMEOUT_MS, 15000),
    providers: parseProviders(env),
  };
}

/** Non-secret fields safe for a startup log line. */
export function summarize(config: AppConfig): Record<string, unknown> {
  if (config.mode === "probe") {
    return {
      mode: "probe",
      port: config.port,
      auth: config.token ? "token" : "none",
      allowActiveChecks: config.allowActiveChecks,
      actuator: Boolean(config.actuatorUrl),
      nginxStatus: Boolean(config.nginxStatusUrl),
      staticDir: Boolean(config.staticDir),
      accessLog: Boolean(config.accessLogPath),
      rum: config.rumEnabled,
    };
  }
  return {
    mode: "hub",
    transport: config.transport,
    httpPort: config.transport === "http" ? config.httpPort : undefined,
    auth: config.transport === "http" ? (config.httpToken ? "token" : "none") : "n/a",
    namespaces: config.namespaces.length ? config.namespaces : "all (RBAC-limited)",
    defaultNamespace: config.defaultNamespace,
    allowActiveChecks: config.allowActiveChecks,
    providers: {
      prometheus: Boolean(config.providers.prometheusUrl),
      datadog: Boolean(config.providers.datadog),
      splunk: Boolean(config.providers.splunk),
    },
  };
}

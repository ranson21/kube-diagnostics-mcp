/**
 * Wire contract between the hub and a probe sidecar. Kept small and versioned
 * so a hub can talk to older probes and report exactly what is unsupported.
 */
export const PROBE_PROTOCOL_VERSION = 1;

export interface ProbeInfo {
  protocol: number;
  version: string;
  pod?: string;
  namespace?: string;
  features: {
    connections: boolean;
    processes: boolean;
    dns: boolean;
    connect: boolean;
    actuator: boolean;
    nginxStatus: boolean;
    staticDir: boolean;
    accessLog: boolean;
    rum: boolean;
  };
  allowActiveChecks: boolean;
}

export interface ConnectionSummary {
  /** Per remote endpoint, established connection counts. */
  established: Array<{ remote: string; port: number; count: number }>;
  states: Record<string, number>;
  listening: Array<{ address: string; port: number; proto: "tcp" | "tcp6" | "udp" | "udp6" }>;
  totals: { tcp: number; udp: number };
  /** True if /proc/net was readable. */
  available: boolean;
  note?: string;
}

export interface ProcessSummary {
  available: boolean;
  note?: string;
  processes: Array<{
    pid: number;
    comm: string;
    state: string;
    rssBytes: number;
    threads: number;
    fdCount?: number;
    fdLimit?: number;
    uptimeSeconds?: number;
    cmdline?: string;
  }>;
}

export interface DnsResult {
  name: string;
  addresses: string[];
  durationMs: number;
  error?: string;
  resolvConf?: { nameservers: string[]; search: string[]; options: string[] };
}

export interface ConnectResult {
  host: string;
  port: number;
  ok: boolean;
  durationMs: number;
  error?: string;
}

export interface NginxStatus {
  available: boolean;
  activeConnections?: number;
  accepts?: number;
  handled?: number;
  requests?: number;
  reading?: number;
  writing?: number;
  waiting?: number;
  /** accepts - handled: connections nginx could not handle (resource limits). */
  dropped?: number;
  note?: string;
}

export interface StaticBundleStats {
  available: boolean;
  note?: string;
  dir?: string;
  fileCount?: number;
  totalBytes?: number;
  largest: Array<{ file: string; bytes: number }>;
  jsBytes?: number;
  cssBytes?: number;
  imageBytes?: number;
  hashedChunks?: number;
  unhashedJs?: string[];
  sourceMaps?: number;
  hasIndexHtml?: boolean;
}

export interface AccessLogSummary {
  available: boolean;
  note?: string;
  lines: number;
  window?: { from?: string; to?: string };
  byStatusClass: Record<string, number>;
  byStatus: Record<string, number>;
  topPaths: Array<{ path: string; count: number; p50Ms?: number; p95Ms?: number; errors: number }>;
  byUpstream: Array<{ upstream: string; count: number; p50Ms?: number; p95Ms?: number; p95UpstreamMs?: number; errors5xx: number; timeouts504: number }>;
  clientAbandoned499: number;
  requestVsUpstreamGapP95Ms?: number;
  suspiciousPaths: Array<{ path: string; count: number; reason: string }>;
  sensitive?: Array<{ kind: string; count: number; sample: string }>;
}

export type RumEventType = "vital" | "view" | "resource" | "error" | "nav";

export interface RumBeacon {
  app?: string;
  session?: string;
  route?: string;
  device?: "mobile" | "desktop" | "tablet" | "unknown";
  connection?: string;
  events: Array<
    | { type: "vital"; name: "LCP" | "INP" | "CLS" | "FCP" | "TTFB"; value: number; route?: string }
    | { type: "view"; route: string; durationMs?: number; entry?: boolean }
    | { type: "resource"; url: string; durationMs: number; status?: number; initiator?: string; bytes?: number; route?: string }
    | { type: "error"; message: string; stack?: string; route?: string }
    | { type: "nav"; route?: string; dns?: number; connect?: number; tls?: number; ttfb?: number; download?: number; domInteractive?: number; domContentLoaded?: number; load?: number }
  >;
}

export interface Percentiles {
  count: number;
  p50: number;
  p75: number;
  p95: number;
  max: number;
}

export interface RumSummary {
  available: boolean;
  note?: string;
  since?: string;
  vitals: Record<string, Record<string, Percentiles>>; // route -> metric -> percentiles
  views: Array<{ route: string; views: number; entries: number; avgDurationMs?: number }>;
  nav: Record<string, Record<string, Percentiles>>; // route -> phase -> percentiles
  resources: Array<{ url: string; count: number; p50Ms: number; p95Ms: number; errors: number; routes: string[] }>;
  errors: Array<{ signature: string; count: number; firstSeen: string; lastSeen: string; routes: string[]; sample: string }>;
  devices: Record<string, number>;
  sessions: number;
}

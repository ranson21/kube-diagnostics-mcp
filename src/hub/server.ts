import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { ToolContext } from "./context.js";
import { sanitizeDeep, redactText } from "../security/sanitize.js";
import { GuardError } from "../security/guard.js";
import { KubeError } from "../k8s/client.js";
import { ProbeUnavailable } from "../probe/client.js";
import * as orientation from "./tools/orientation.js";
import * as health from "./tools/health.js";
import * as logs from "./tools/logs.js";
import * as config from "./tools/config.js";
import * as perf from "./tools/performance.js";
import * as network from "./tools/network.js";
import * as security from "./tools/security.js";
import * as java from "./tools/java.js";
import * as proxy from "./tools/proxy.js";
import * as rum from "./tools/rum.js";
import * as runbooks from "./runbooks.js";

export const SERVER_VERSION = "0.1.0";

type ToolResult = CallToolResult;

/** Every tool goes through here: audit log, sanitization, size cap, uniform errors. */
function makeRunner(ctx: ToolContext) {
  return async function run<T>(toolName: string, args: Record<string, unknown>, fn: () => Promise<T>): Promise<ToolResult> {
    const started = Date.now();
    ctx.logger.info("tool invoked", { tool: toolName, ...auditArgs(args) });
    try {
      const data = await fn();
      let text = JSON.stringify(sanitizeDeep(data), null, 2);
      let truncated = false;
      if (text.length > ctx.config.maxResultBytes) {
        text = `${text.slice(0, ctx.config.maxResultBytes)}\n... [truncated: result exceeded DIAG_MAX_RESULT_BYTES=${ctx.config.maxResultBytes}; narrow the query]`;
        truncated = true;
      }
      ctx.logger.info("tool succeeded", { tool: toolName, ms: Date.now() - started, bytes: text.length, truncated });
      return { content: [{ type: "text", text }] };
    } catch (err) {
      const message = redactText(err instanceof Error ? err.message : String(err));
      const kind = err instanceof GuardError ? "invalid-argument" : err instanceof KubeError ? "kubernetes" : err instanceof ProbeUnavailable ? "probe" : "error";
      ctx.logger.error("tool failed", { tool: toolName, kind, error: message, ms: Date.now() - started });
      return { content: [{ type: "text", text: `${kind}: ${message}` }], isError: true };
    }
  };
}

/** Args are audit-logged, but free-text fields (grep/query/url) only at debug. */
function auditArgs(args: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(args)) {
    if (v === undefined) continue;
    out[k] = ["grep", "query", "url", "name"].includes(k) ? "<omitted>" : v;
  }
  return out;
}

export function createServer(ctx: ToolContext): McpServer {
  const server = new McpServer({ name: "kube-diagnostics-mcp", version: SERVER_VERSION });
  const run = makeRunner(ctx);

  const nsDesc = ctx.config.defaultNamespace ? `Kubernetes namespace (defaults to "${ctx.config.defaultNamespace}")` : "Kubernetes namespace (required: no default configured; see list_namespaces)";
  const ns = z.string().optional().describe(nsDesc);
  const service = z.string().describe("Workload name as you would say it: a Deployment, StatefulSet, DaemonSet, Service, or Pod name");
  const serviceOpt = service.optional();
  const pod = z.string().optional().describe("Exact pod name (alternative to service)");
  const since = (def: string) => z.string().optional().describe(`Time window like 15m, 2h, 1d (default ${def})`);

  const tool = <S extends z.ZodRawShape>(name: string, description: string, shape: S, fn: (args: z.infer<z.ZodObject<S>>) => Promise<unknown>) => {
    server.registerTool(name, { description, inputSchema: shape }, (async (args: z.infer<z.ZodObject<S>>) => run(name, args as Record<string, unknown>, () => fn(args))) as never);
  };

  // ---- meta ----------------------------------------------------------------
  tool("list_providers", "Show which signal providers (metrics-server/probe, Prometheus, Datadog, Splunk) are configured and reachable, and what each can answer. Read-only.", {}, async () => ({
    cluster: { context: ctx.k8s.contextName, server: ctx.k8s.clusterServer, version: await ctx.k8s.serverVersion().catch((e) => ({ error: String(e) })) },
    activeChecksEnabled: ctx.config.allowActiveChecks,
    namespaceAllowList: ctx.config.namespaces.length ? ctx.config.namespaces : "all RBAC permits",
    providers: await Promise.all(ctx.providers.all().map(async (p) => ({ name: p.name, capabilities: p.capabilities, ...(await p.status()) }))),
  }));
  tool("list_namespaces", "List namespaces this hub may inspect. Read-only.", {}, () => orientation.listNamespaces(ctx));

  // ---- orientation ---------------------------------------------------------
  tool("list_workloads", "Deployments/StatefulSets/DaemonSets/Jobs/CronJobs in a namespace with ready counts, restarts, images, and age. Start here when you do not know what runs where.", { namespace: ns }, (a) => orientation.listWorkloads(ctx, a));
  tool("get_topology", "Service -> pods -> workload graph plus inferred dependencies (from env/ConfigMap references to Service names, and from probe-observed connections if include_connections=true). Flags Services with no ready endpoints.", { namespace: ns, include_connections: z.boolean().optional().describe("Also ask probe sidecars for established connections (slower)") }, (a) => orientation.getTopology(ctx, a));
  tool("get_service_overview", "One-call digest for a service: replicas, pod problems, recent warning events, usage vs requests/limits, golden signals if available. The first tool to call for 'is X healthy?'.", { namespace: ns, service }, (a) => orientation.getServiceOverview(ctx, a));

  // ---- health & state ------------------------------------------------------
  tool("get_pod_status", "Pod phases, container states and waiting/terminated reasons (CrashLoopBackOff, OOMKilled, ImagePullBackOff...), restart counts, exit codes, unschedulable conditions. Give a service, a pod, or neither for the whole namespace.", { namespace: ns, service: serviceOpt, pod }, (a) => health.getPodStatus(ctx, a));
  tool("get_events", "Kubernetes events, warnings first, deduplicated with counts. Filter by object name prefix.", { namespace: ns, since: since("1h"), object: z.string().optional().describe("Object name prefix (e.g. a deployment or pod name)"), warnings_only: z.boolean().optional().describe("Default true"), limit: z.number().int().optional() }, (a) => health.getEvents(ctx, a));
  tool("get_logs", "Sanitized, size-capped container logs for a service (up to 10 pods) or a pod. Use previous=true for the crashed container. grep accepts a substring or /regex/i.", { namespace: ns, service: serviceOpt, pod, container: z.string().optional(), since: since("all recent"), tail: z.number().int().optional().describe(`Lines per pod (max ${ctx.config.logMaxLines})`), grep: z.string().optional(), previous: z.boolean().optional() }, (a) => logs.getLogs(ctx, a));
  tool("summarize_log_errors", "Groups ERROR (and optionally WARN) log lines by signature (Java stack traces by exception + first app frame) with counts, first/last seen, and one redacted sample each. Read this instead of raw logs.", { namespace: ns, service: serviceOpt, pod, since: since("1h"), include_warnings: z.boolean().optional() }, (a) => logs.summarizeLogErrors(ctx, a));
  tool("get_config", "Resolved configuration of a workload: env (secret-sourced values shown as references, credential-looking keys redacted), ConfigMap previews, probes, resources, mounts, security context, plus findings (secrets in env, missing probes, JVM heap vs limit...).", { namespace: ns, service }, (a) => config.getConfig(ctx, a));
  tool("get_rollout_history", "Deployment revisions with image/env/resource diffs between them. Answers 'what changed in the last deploy?'.", { namespace: ns, deployment: z.string(), limit: z.number().int().optional() }, (a) => health.getRolloutHistory(ctx, a));
  tool("what_changed", "One timeline of rollouts, scaling, HPA actions, ConfigMap updates, restarts, and notable events in a window. The first question in any incident.", { namespace: ns, service: serviceOpt, since: since("6h") }, (a) => health.whatChanged(ctx, a));

  // ---- performance ---------------------------------------------------------
  tool("get_resource_pressure", "CPU/memory usage vs requests and limits per container, CFS throttling ratio when known, OOM kills, restarts, with findings.", { namespace: ns, service: serviceOpt, pod, window: since("5m") }, (a) => perf.getResourcePressure(ctx, a));
  tool("compare_replicas", "Is one replica the outlier? Per-pod usage, restarts, node, revision hash; flags hot pods, leaks, stuck rollouts, and no node spread.", { namespace: ns, service }, (a) => perf.compareReplicas(ctx, a));
  tool("get_node_pressure", "Node conditions (Memory/Disk/PID pressure), allocatable vs requested vs used, overcommit, taints, cordons.", { node: z.string().optional() }, (a) => perf.getNodePressure(ctx, a));
  tool("get_hpa_status", "HorizontalPodAutoscalers: current/target metrics, at-max, unable-to-scale conditions.", { namespace: ns }, (a) => perf.getHpaStatus(ctx, a));
  tool("get_golden_signals", "Request rate, error rate, latency percentiles (and per endpoint) from the best available provider: Prometheus (windowed) or Actuator via the probe (cumulative).", { namespace: ns, service, window: since("15m") }, (a) => perf.getGoldenSignals(ctx, a));
  tool("query_metrics", "Escape hatch: raw PromQL range query against the configured Prometheus, compacted (first/last/min/max/avg + 12 samples per series).", { query: z.string(), window: since("1h"), step: z.number().int().optional() }, (a) => perf.queryMetrics(ctx, a));
  tool("find_slow_traces", "Slowest traces for a service from the tracing provider (none configured yet: returns guidance).", { namespace: ns, service, min_duration_ms: z.number().optional(), window: since("1h"), limit: z.number().int().optional() }, (a) => perf.findSlowTraces(ctx, a));
  tool("get_trace", "Critical-path view of one trace (needs a tracing provider).", { trace_id: z.string() }, (a) => perf.getTrace(ctx, a));

  // ---- connectivity --------------------------------------------------------
  tool("get_endpoints", "Service -> EndpointSlice: matching pods, ready endpoints, targetPort vs containerPort mismatches. Catches the classic 'selector matches nothing'.", { namespace: ns, service: serviceOpt }, (a) => network.getEndpoints(ctx, a));
  tool("get_network_policies", "NetworkPolicies in a namespace, decoded; whether a given workload's ingress/egress is restricted; flags 'no policy = wide open'.", { namespace: ns, service: serviceOpt }, (a) => network.getNetworkPolicies(ctx, a));
  tool("get_ingress_routes", "Ingress hosts/paths -> Services, TLS coverage, dangling backends.", { namespace: ns }, (a) => network.getIngressRoutes(ctx, a));
  tool("get_open_connections", "[probe] Established connections by destination (resolved to Services/pods), socket state counts (TIME_WAIT/CLOSE_WAIT storms), listening ports - from /proc/net inside the pod's network namespace. Passive.", { namespace: ns, service: serviceOpt, pod }, (a) => network.getOpenConnections(ctx, a));
  tool("get_listening_ports", "[probe] What the application actually binds (vs what the Service targets).", { namespace: ns, service: serviceOpt, pod }, async (a) => {
    const r = await network.getOpenConnections(ctx, a);
    return { pod: r.pod, namespace: r.namespace, available: r.available, note: r.note, listening: r.listening };
  });
  tool("resolve_dns", "[probe, ACTIVE] Resolve a name from inside the pod (its resolv.conf, search domains, ndots). Requires DIAG_ALLOW_ACTIVE_CHECKS.", { namespace: ns, service: serviceOpt, pod, name: z.string() }, (a) => network.resolveDns(ctx, a));
  tool("check_connectivity", "[probe, ACTIVE] TCP connect from inside the pod to host:port with latency and a diagnosis of the failure mode. Requires DIAG_ALLOW_ACTIVE_CHECKS.", { namespace: ns, service: serviceOpt, pod, host: z.string(), port: z.number().int() }, (a) => network.checkConnectivity(ctx, a));
  tool("get_process_stats", "[probe] RSS, threads, file descriptors vs limit, state, uptime per process (needs shareProcessNamespace on the pod to see the app).", { namespace: ns, service: serviceOpt, pod }, (a) => network.getProcessStats(ctx, a));

  // ---- java ----------------------------------------------------------------
  tool("get_jvm_health", "[probe] Heap used/committed/max vs container limit, GC pause count/total/max, threads, classes, CPU seen by the JVM - from Actuator on localhost.", { namespace: ns, service: serviceOpt, pod }, (a) => java.getJvmHealth(ctx, a));
  tool("get_thread_dump_summary", "[probe] Actuator threaddump reduced to: threads by state, pool busy/total, lock contention, DEADLOCK detection, top stack signatures. Never the raw dump.", { namespace: ns, service: serviceOpt, pod }, (a) => java.getThreadDumpSummary(ctx, a));
  tool("get_connection_pool_status", "[probe] HikariCP active/idle/pending/max, acquire and usage times, timeouts. Pool exhaustion is the #1 Java+DB slowness cause.", { namespace: ns, service: serviceOpt, pod }, (a) => java.getConnectionPoolStatus(ctx, a));
  tool("get_endpoint_metrics", "[probe/Prometheus] Per-endpoint request rate, error rate, and latency (http.server.requests).", { namespace: ns, service, window: since("15m") }, (a) => java.getEndpointMetrics(ctx, a));
  tool("get_outbound_client_metrics", "[probe] Latency/error rate per downstream target from http.client.requests: which dependency is slow, from the caller's view.", { namespace: ns, service: serviceOpt, pod }, (a) => java.getOutboundClientMetrics(ctx, a));
  tool("get_actuator_health", "[probe] Actuator /health with component detail (db, diskSpace, redis, custom indicators).", { namespace: ns, service: serviceOpt, pod }, (a) => java.getActuatorHealth(ctx, a));
  tool("get_jvm_config", "Effective JVM flags and Spring env from the pod spec (redacted) with heap-vs-limit and GC findings; Actuator /info if a probe exists.", { namespace: ns, service }, (a) => java.getJvmConfig(ctx, a));

  // ---- proxy / frontend ----------------------------------------------------
  tool("get_proxy_status", "[probe] nginx stub_status per pod: active/reading/writing/waiting, accepts vs handled (drops).", { namespace: ns, service }, (a) => proxy.getProxyStatus(ctx, a));
  tool("summarize_access_log", "[probe] Proxy access log aggregated: status classes, top paths with p50/p95, per-upstream latency and 504s, 499s (clients giving up), proxy-vs-upstream gap, scanner-like paths, sensitive data in the log. Never raw lines.", { namespace: ns, service, since: since("15m") }, (a) => proxy.summarizeAccessLog(ctx, a));
  tool("get_proxy_config_summary", "Parses the nginx config from the workload's ConfigMap: upstreams, locations, timeouts, buffering, gzip, cache headers for assets vs index.html, security headers, rate limits - with findings.", { namespace: ns, service }, (a) => proxy.getProxyConfigSummary(ctx, a));
  tool("get_static_bundle_stats", "[probe] Served frontend build: JS/CSS/image bytes, largest files, hashed vs unhashed chunks, source maps shipped.", { namespace: ns, service }, (a) => proxy.getStaticBundleStats(ctx, a));
  tool("check_security_headers", "[ACTIVE] GET a URL from the hub and report missing security headers, version disclosure, cookie flags, HTTP->HTTPS redirect. Requires DIAG_ALLOW_ACTIVE_CHECKS.", { url: z.string().url() }, (a) => proxy.checkSecurityHeaders(ctx, a));

  // ---- RUM -----------------------------------------------------------------
  const rumSvc = z.string().optional().describe("Proxy workload whose probe ingests RUM (auto-discovered if omitted)");
  tool("get_web_vitals", "[probe RUM] Core Web Vitals p75/p95 per route (LCP, INP, CLS, FCP, TTFB) with good/needs-improvement/poor ratings.", { namespace: ns, service: rumSvc, route: z.string().optional() }, (a) => rum.getWebVitals(ctx, a));
  tool("get_page_views", "[probe RUM] Most visited routes, entry routes, sessions, device split.", { namespace: ns, service: rumSvc }, (a) => rum.getPageViews(ctx, a));
  tool("get_page_load_breakdown", "[probe RUM] Navigation Timing phases per route (dns, connect, tls, ttfb, download, domInteractive, DCL, load) with a diagnosis of where full-page loads spend time.", { namespace: ns, service: rumSvc, route: z.string().optional() }, (a) => rum.getPageLoadBreakdown(ctx, a));
  tool("get_browser_api_latency", "[probe RUM] Browser-observed latency per API endpoint and slowest assets; compare with service-side and proxy-side numbers to localize slowness.", { namespace: ns, service: rumSvc, route: z.string().optional() }, (a) => rum.getBrowserApiLatency(ctx, a));
  tool("get_frontend_errors", "[probe RUM] JavaScript errors grouped by signature with counts, first/last seen, routes.", { namespace: ns, service: rumSvc, route: z.string().optional() }, (a) => rum.getFrontendErrors(ctx, a));

  // ---- security ------------------------------------------------------------
  tool("security_posture", "Static security findings with severity for workloads: privileged/root/host namespaces/capabilities/seccomp/rootfs, secrets in env, unpinned images, no limits, SA token automount, missing NetworkPolicy, over-privileged RBAC. No Secret contents are read.", { namespace: ns, service: serviceOpt, min_severity: z.enum(["critical", "high", "medium", "low", "info"]).optional() }, (a) => security.securityPosture(ctx, a));
  tool("get_exposure", "What is reachable from outside: LoadBalancer/NodePort Services, Ingress routes (TLS or not), hostNetwork pods, management paths exposed.", { namespace: ns }, (a) => security.getExposure(ctx, a));
  tool("get_rbac_for_workload", "Effective RBAC of the workload's ServiceAccount, with an over-privilege verdict.", { namespace: ns, service }, (a) => security.getRbacForWorkload(ctx, a));
  tool("get_secret_usage", "Which Secrets are referenced by which workloads and how (env vs volume). Names/keys only, never values.", { namespace: ns }, (a) => security.getSecretUsage(ctx, a));
  tool("get_tls_status", "Ingress TLS coverage; with host (+port) and active checks enabled, performs a TLS handshake and reports expiry, issuer, protocol, chain trust.", { namespace: ns, host: z.string().optional(), port: z.number().int().optional() }, (a) => security.getTlsStatus(ctx, a));
  tool("scan_logs_for_sensitive_data", "Scans recent logs for PII (emails, cards with Luhn, SSNs, phones) and secrets (JWTs, cloud keys, Bearer/Basic, connection strings, PEM). Returns counts and masked samples only.", { namespace: ns, service: serviceOpt, pod, since: since("1h") }, (a) => logs.scanLogsForSensitiveData(ctx, a));
  tool("get_egress_destinations", "[probe] Where a pod currently talks to, classified (cluster service/pod, private, PUBLIC INTERNET, cloud metadata). Exfil and unexpected-dependency signal.", { namespace: ns, service: serviceOpt, pod }, (a) => security.getEgressDestinations(ctx, a));
  tool("get_image_inventory", "Images, registries, tags, running digests per workload with unpinned/latest/moved-tag findings. Input for a CVE scanner.", { namespace: ns }, (a) => security.getImageInventory(ctx, a));

  // ---- runbooks ------------------------------------------------------------
  tool("diagnose_service", "RUNBOOK: status -> events -> resources/throttling -> OOM/crash -> endpoints -> JVM/pool/downstreams -> log errors -> golden signals -> recent changes. Returns ranked hypotheses with evidence and the next tool to run. Start here for 'why is X broken/slow?'.", { namespace: ns, service, window: since("30m") }, (a) => runbooks.diagnoseService(ctx, a));
  tool("diagnose_slow_requests", "RUNBOOK for latency: per-endpoint latency, throttling, GC, connection pool, thread pool/locks, downstreams, proxy timeouts (pass proxy_service for the user-facing view).", { namespace: ns, service, window: since("30m"), proxy_service: z.string().optional() }, (a) => runbooks.diagnoseSlowRequests(ctx, a));
  tool("diagnose_slow_page", "RUNBOOK for a slow frontend route: vitals -> TTFB vs render split -> bundle/caching -> browser API latency -> service metrics. Pass proxy_service (nginx workload) and api_service.", { namespace: ns, route: z.string(), proxy_service: z.string().optional(), api_service: z.string().optional() }, (a) => runbooks.diagnoseSlowPage(ctx, a));
  tool("health_report", "RUNBOOK 'Monday morning' digest for a namespace: unhealthy pods, restarts, warnings, resource pressure, HPA at max, node pressure, endpoint problems, missing NetworkPolicies, security findings, TLS gaps, with suggested actions.", { namespace: ns }, (a) => runbooks.healthReport(ctx, a));

  return server;
}

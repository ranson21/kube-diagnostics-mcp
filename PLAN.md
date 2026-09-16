# kube-diagnostics-mcp — Plan (v0, 2026-09-16)

> **Status 2026-09-16:** approved and built. v0.1.0 is at https://github.com/ranson21/kube-diagnostics-mcp
> (hub, probe, providers, RUM client, fault lab, CI). The Datadog/Splunk providers are placeholders
> because those endpoints are not reachable yet; see README "Signal providers". This file is the
> original design and is kept for the reasoning behind the shape of the tool set.

Read-only MCP diagnostics service for microservices on Kubernetes. Goal: make
"why is checkout slow?", "what changed?", "is anything leaking?" a conversation,
by encoding the debugging runbook as tools rather than exposing raw kubectl.

Sibling projects: `jira-readonly-mcp`, `postgres-readonly-mcp` (same stack and
security posture: TypeScript, `@modelcontextprotocol/sdk`, zod, vitest,
`security/guard.ts` + `security/sanitize.ts`, per-tool files, threat-model README).

---

## 1. Architecture: hub + optional probe (one image, two modes)

A pure per-pod sidecar can only see its own pod (localhost, /proc/net, its
container's logs). Microservice debugging is mostly cross-service: topology,
events, rollouts, metrics, traces, the database. So:

```
 Claude / OpenCode / any MCP client
        │  MCP over Streamable HTTP (bearer auth)      (stdio mode for local dev)
        ▼
 ┌──────────────────────────────┐   read-only RBAC (get/list/watch only, no secrets)
 │  HUB  (Deployment, 1 replica)│──► Kubernetes API + metrics.k8s.io
 │  the MCP server              │──► Prometheus HTTP API        (optional adapter)
 │  runbook tools live here     │──► Tempo/Jaeger trace API     (optional adapter)
 │                              │──► Loki                       (optional adapter)
 └───────┬──────────────────────┘
         │ HTTPS + shared token, restricted by NetworkPolicy (hub → probe only)
         ▼
 ┌──────────────────────────────┐  native sidecar (initContainer, restartPolicy: Always)
 │  PROBE  (per pod, optional)  │  shares the pod's NETWORK namespace → /proc/net/tcp,
 │  no k8s API access at all    │  listening ports, DNS from the app's point of view,
 │  tiny local HTTP API         │  TCP connect checks; optional shareProcessNamespace
 └──────────────────────────────┘  for process/fd/thread stats

 postgres-readonly-mcp runs separately; the model composes it with the hub.
 (We add a "diagnostics" tool group to it — see §4.)
```

- **Hub without probe still works**; probe-dependent tools return
  "probe not installed on this pod" instead of failing.
- **Why not one MCP server per sidecar?** N services = N MCP endpoints the
  client must be configured for, and no tool can correlate across pods.
- **Why not just use kubernetes-mcp-server + mcp-grafana?** They are generic
  resource/query proxies. The value here is (a) the composed runbook tools that
  return ranked hypotheses with evidence, (b) the in-pod network view, (c) the
  security/leak scans, (d) sanitized, size-capped output. We keep a *small* set
  of raw primitives so the model can dig when a runbook tool is not enough.

### Read-only, by construction (three layers, mirroring postgres-readonly-mcp)
1. **RBAC**: ServiceAccount bound to a Role/ClusterRole with verbs
   `get,list,watch` only. No `secrets` at all (secret *usage* is derived from
   pod specs). No `pods/exec`, `pods/portforward`, `pods/attach`. `pods/log` yes.
2. **Client wrapper**: the hub's Kubernetes client exposes only GET/LIST/WATCH
   methods; there is no code path that can send POST/PUT/PATCH/DELETE.
3. **Probe has no credentials**: no SA token mounted
   (`automountServiceAccountToken: false`), no write endpoints, listens only for
   the hub, drops all capabilities, runs non-root, read-only rootfs.

Plus defense-in-depth: `sanitize.ts` (ported from postgres-readonly-mcp, extended
with PII shapes) on every tool output; env-var values from `secretKeyRef` are
replaced with `<from secret NAME/KEY>`; env keys matching secret-ish names are
redacted even if literal; hard caps on log bytes/lines and result sizes; every
tool call audit-logged (never the output).

**"Active" checks** (`check_connectivity`, `resolve_dns`, synthetic GET) do not
change state but do generate traffic. Gated behind `DIAG_ALLOW_ACTIVE_CHECKS`,
off by default, and always labeled as active in tool descriptions.

### Auth for the hub (Streamable HTTP)
- v1: static bearer token from a Secret (same trust model as the other servers).
- v2: Kubernetes `TokenReview` — caller presents its own SA/user token, hub
  verifies it with the API server; lets you say "only group X may use this".
- Origin validation + `MCP-Session-Id` handling per the current transport spec.
- Stdio mode (kubeconfig) for local dev and for single-admin use, exactly like
  the existing servers.

---

## 2. Tool set

Grouped by the runbook step they serve. `MVP` = phase 1–2. `probe` = needs the
sidecar. `adapter` = needs Prometheus/Tempo/Loki configured.

### A. Orientation — "what is even running?"
| Tool | Purpose |
|---|---|
| `list_workloads(namespace?)` MVP | Deployments/StatefulSets/DaemonSets/Jobs with ready/desired, image tags, age, restart totals. |
| `get_topology(namespace?)` MVP | Service → selector → pods → endpoints graph, plus *inferred* dependencies from env/ConfigMap hostnames and (when available) probe connections or trace edges. |
| `get_service_overview(service)` MVP | One-call digest: replicas, restarts, last warning events, usage vs requests/limits, last rollout, golden signals (if adapter), probe summary (if probe). |

### B. Health & state — status → describe → events → logs → config
| Tool | Purpose |
|---|---|
| `get_pod_status(service\|pod)` MVP | Phases, container states, waiting/terminated reasons (CrashLoopBackOff, ImagePullBackOff, OOMKilled, exit codes), restart counts, probe failures, scheduling conditions. |
| `get_events(namespace, since?, object?)` MVP | Warning-first, deduplicated, counted, sorted. |
| `get_logs(pod\|service, container?, since?, grep?, tail?)` MVP | Sanitized, size-capped log fetch; `previous=true` for the crashed container. |
| `summarize_log_errors(service, since?)` MVP | Groups error/warn lines by message signature (numbers/ids normalized), returns counts + first/last seen + one redacted sample each. The model reads 20 lines instead of 20,000. |
| `get_config(service)` MVP | Resolved env (secret values redacted), ConfigMap refs, mounts, liveness/readiness/startup probes, resources, node selectors/tolerations, SA. |
| `get_rollout_history(deployment)` MVP | Revisions with image/config-hash diffs and timestamps. "What changed?" is the first question in every incident. |
| `what_changed(namespace\|service, since)` MVP | Rollouts, scale events, HPA actions, ConfigMap/Secret *metadata* updates (resourceVersion/time only), node changes, in one timeline. |

### C. Performance — golden signals → saturation → traces → DB
| Tool | Purpose |
|---|---|
| `get_resource_pressure(service\|pod)` MVP | CPU usage vs request/limit, **CFS throttling**, memory working set vs limit, OOM kills, restarts. metrics-server first, cAdvisor/Prometheus when available. |
| `compare_replicas(service)` MVP | Is one pod the outlier (hot pod, noisy node)? Per-pod usage, restarts, node, age. |
| `get_node_pressure(node?)` MVP | Memory/Disk/PID pressure conditions, allocatable vs requested, pods per node. |
| `get_hpa_status(namespace?)` MVP | Current/target metrics, at-max, scaling events, cooldown. |
| `get_golden_signals(service, window?)` adapter | RED: request rate, error rate, p50/p95/p99 via PromQL with a configurable metric-name map (apps differ). |
| `find_slow_traces(service, min_duration, window?)` adapter | Tempo/Jaeger search → compact list (trace id, duration, root op, slowest span). |
| `get_trace(trace_id)` adapter | Critical-path view: the spans that actually add up to the duration, not the whole tree. |
| `get_dependency_latency(service, window?)` adapter | Per-downstream latency/error rate (from spans or mesh metrics). Finds "it's not us, it's the payments service". |
| `query_metrics(promql, window?)` adapter | Raw PromQL escape hatch, result-size capped. |

### D. Connectivity & network — the "database connectivity failure" class
| Tool | Purpose |
|---|---|
| `get_endpoints(service)` MVP | Service → EndpointSlice ready/not-ready addresses. Catches selector/port-name mismatches (zero endpoints). |
| `get_network_policies(namespace, service?)` MVP | Effective allow-lists in/out; flags "no policy → wide open". |
| `get_ingress_routes(namespace?)` MVP | Hosts/paths → services, TLS present or not. |
| `get_open_connections(pod)` probe | From /proc/net/{tcp,tcp6,udp}: established by destination, TIME_WAIT/CLOSE_WAIT counts, pool exhaustion signs. Passive. |
| `get_listening_ports(pod)` probe | What the app actually binds vs what the Service targets. |
| `resolve_dns(pod, name)` probe, active | DNS as the app sees it (search domains, ndots). |
| `check_connectivity(pod, host, port)` probe, active | TCP connect + latency from inside the pod's network namespace. |
| `get_process_stats(pod)` probe (needs shareProcessNamespace) | RSS, threads, fd count vs limit, state, uptime. |

### E. Security, exposure, and leak detection
| Tool | Purpose |
|---|---|
| `security_posture(namespace\|service)` | Findings with severity: runs as root, privileged, hostPath/hostNetwork/hostPID, added capabilities, no seccomp, writable rootfs, secrets as env vars, SA token auto-mounted, no NetworkPolicy, no resource limits, `:latest` tag, missing probes. |
| `get_exposure(namespace?)` | LoadBalancer/NodePort services, Ingress hosts without TLS, which pods are reachable from outside the cluster. |
| `get_rbac_for_workload(service)` | What the workload's SA can do; flags wildcards, cluster-admin, secrets read. |
| `get_secret_usage(namespace)` | Which secrets are referenced by which pods and how (env vs volume) — names/keys only, never values; unreferenced secrets. |
| `get_tls_status(namespace?)` | Ingress cert expiry, self-signed, SAN mismatch. |
| `scan_logs_for_sensitive_data(service, since?)` | PII (email, phone, SSN, card+Luhn), secrets (JWT, AWS/GCP keys, Bearer, conn strings, PEM). Returns **counts and redacted samples**, never the values. |
| `get_egress_destinations(pod)` probe | External IPs/ports the pod talks to; anything outside cluster CIDR / allow-list flagged. Exfil and "why is this calling the internet?" signal. |
| `get_image_inventory(namespace?)` | Images, tags, digests, pull policy; hook for a later Trivy/Grype integration (not in scope now). |

### F. Composed runbooks — where "just have a conversation" happens
| Tool | Purpose |
|---|---|
| `diagnose_service(service)` MVP | Runs the runbook: status → events → resources/throttling → OOM/restarts → endpoints → golden signals → dependency latency → log error summary → (if configured) DB diagnostics. Returns ranked hypotheses, each with the evidence that supports it and the tool to dig deeper. |
| `diagnose_slow_requests(service, window?)` | Latency-focused variant: p99 trend, throttling, slow traces, slow downstreams, DB slow statements. |
| `health_report(namespace?)` | Maintenance digest: restarts, pending pods, pressure, near-limit resources, expiring certs, posture findings, HPA at max. The "Monday morning" tool. |

### G. Stack-specific: Java (Spring Boot / Micrometer) — probe hits localhost Actuator
The probe shares the pod's network namespace, so it can read `localhost:<port>/actuator/*`
even when Actuator is deliberately not exposed through the Service. Nothing is exposed
outside the pod. Actuator endpoints that dump state (`heapdump`, `env` with values,
`logfile`) are never proxied: they are large and full of PII/secrets.

| Tool | Purpose |
|---|---|
| `get_jvm_health(service\|pod)` probe | Heap used/committed/max, metaspace, GC pause p99 + count by collector, thread count, class count, uptime; flags heap-max vs container-limit mismatch (missing `MaxRAMPercentage`). |
| `get_thread_dump_summary(pod)` probe | `/actuator/threaddump` reduced to: threads by state, top blocked-on monitors, **deadlock detection**, pool threads (Tomcat/Jetty, executor) busy vs max, top 10 stack signatures. Never the raw dump. |
| `get_connection_pool_status(service)` probe/adapter | HikariCP active/idle/pending/timeout/acquire-time via Micrometer. Pool exhaustion is the #1 Java+Postgres slowness cause; pairs with `get_active_queries` on the DB side. |
| `get_endpoint_metrics(service, window?)` probe/adapter | Per-endpoint RED from `http_server_requests_seconds` (uri, method, status, outcome). Golden signals with no Prometheus needed. |
| `get_outbound_client_metrics(service)` probe/adapter | `http_client_requests_seconds` by client name/uri: which downstream is slow, from the caller's view. |
| `get_actuator_health(pod)` probe | Component health (db, diskSpace, redis, custom) and readiness/liveness groups. |
| `get_jvm_config(pod)` | Effective JVM flags from the pod spec (`JAVA_TOOL_OPTIONS`, `-Xmx`, GC), Spring profiles active, server threads/timeouts from resolved config (secrets redacted). |

`summarize_log_errors` groups Java stack traces by exception class + top app frame
(not by message text), so 500 identical `NullPointerException`s become one row.

### H. Stack-specific: Angular served through a reverse proxy (nginx assumed)
| Tool | Purpose |
|---|---|
| `get_proxy_status(pod)` probe | nginx `stub_status`: active/reading/writing/waiting, accepts vs handled (drops), requests. |
| `summarize_access_log(service, since?, route?)` | Parses the proxy access log: requests by route and status class, top API endpoints, p95 `$upstream_response_time` and `$request_time` per upstream (gap = proxy/network), 499s (client gave up = slowness), 502/504 by upstream, 4xx storms and scanner-like paths (security signal). Query strings dropped, IPs never returned. |
| `get_proxy_config_summary(service)` | From the nginx ConfigMap: upstreams/targets, `proxy_read/connect_timeout`, buffering, body size, gzip/brotli, `Cache-Control` for hashed Angular chunks vs `index.html` (no-cache), security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy), rate limits. Flags misconfigurations. |
| `get_static_bundle_stats(service)` probe | Served Angular build: chunk count, main/vendor/polyfills sizes, gzip on/off, hashed filenames present, source maps shipped to prod (leak). Reads the shared static volume or `index.html`. |
| `check_security_headers(url)` active | Synthetic GET against the proxy; reports missing/weak headers and TLS redirect. |

### I. Real-user monitoring (RUM) for the Angular app — page loads, vitals, most visited pages
SPA route changes never reach the server, so proxy logs cannot answer "most visited
pages". A browser-side collector is required. Design:

- **Collector**: a small script/Angular service (`rum-client`, ~3 KB) built on Google's
  `web-vitals` library. Collects: Core Web Vitals **LCP, INP, CLS**, plus **FCP, TTFB**;
  Navigation Timing phases (DNS, connect, TLS, TTFB, download, DOM interactive,
  DOMContentLoaded, load); Angular Router events (route views, route-change duration,
  lazy-chunk load time); Resource Timing for `fetch`/XHR to the API (browser-side latency
  per endpoint); JS errors (message + stack signature); coarse device class and
  effective connection type. Sent with `navigator.sendBeacon` on visibility change.
- **Privacy-first, by construction**: route params normalized from the Angular route config
  (`/users/123` → `/users/:id`), query strings and fragments dropped, no user identifiers,
  no cookies, client IP discarded at ingest, session = random id in `sessionStorage`
  that dies with the tab, configurable sampling, optional consent gate. The ingest
  accepts an allow-list of fields and rejects anything else.
- **Ingest**: the probe in the proxy pod gains a `rum` listener; nginx adds
  `location /__rum { proxy_pass http://127.0.0.1:<probe-port>; }` so beacons are
  same-origin (no CORS) and the probe is still not reachable from outside. Body cap 8 KB,
  rate-limited per source, schema-validated.
- **Storage**: in-memory rolling aggregates in the probe (t-digest per route × metric, page
  view counters, error signatures) for the last N hours, **exported as Prometheus
  histograms** on the probe's `/metrics` so long-term retention and dashboards ride on
  the Prometheus adapter instead of a new datastore. Hub merges across proxy replicas.

| Tool | Purpose |
|---|---|
| `get_web_vitals(route?, window?)` | p75 (the Web Vitals standard) LCP/INP/CLS/FCP/TTFB by route with good / needs-improvement / poor buckets and sample counts. |
| `get_page_views(window?)` | Most visited routes, route-change counts, entry routes, session depth, device split. |
| `get_page_load_breakdown(route, window?)` | Navigation Timing phases as p50/p75/p95 → is it TTFB (server/proxy), download (bundle size), or render (JS)? |
| `get_browser_api_latency(window?)` | Browser-observed p95 per API endpoint next to Java `http_server_requests` and proxy `upstream_response_time` for the same route: the three-way gap localizes the slowness (network, proxy, or service). |
| `get_frontend_errors(window?)` | JS errors grouped by signature with counts, first/last seen, affected routes; sanitized. |
| `diagnose_slow_page(route)` runbook | LCP → TTFB vs render split → bundle stats + cache headers → slowest API calls on that route → matching Java endpoint metrics → DB. One answer to "the checkout page is slow". |

Roughly 60 tools total; the MVP is 17. The runbook tools are thin
orchestrators over the primitives, so they stay cheap to build once the
primitives exist. Groups G–I are why the probe matters: Actuator on localhost,
nginx stub_status, and RUM ingest all need something inside the pod.

---

## 3. Suggested MCP resources and prompts (cheap, high leverage)
- Resource `diag://runbooks/slow-service` etc.: the written runbooks the tools
  encode, so the model can explain *why* it is looking where it looks.
- Prompt `investigate(service)`: seeds a session with `diagnose_service` and
  the follow-up decision tree.

---

## 4. postgres-readonly-mcp: add a `diagnostics` tool group
Same server, new tools (all plain SELECTs over pg_catalog / pg_stat_*):
- `get_active_queries()` — pg_stat_activity: running/waiting, duration, wait_event, state.
- `get_slow_statements(limit?)` — pg_stat_statements by mean/total time (if the extension exists; report if not).
- `get_blocking_locks()` — blocking chains from pg_locks + pg_stat_activity.
- `get_connection_usage()` — connections by state/app/user vs max_connections; idle-in-transaction count.
- `get_table_health(schema?)` — seq vs idx scans, dead tuples, last vacuum/analyze, bloat estimate.
- `get_replication_status()` — lag, replica state.
- `explain_query(sql)` — `EXPLAIN (FORMAT JSON)` **without ANALYZE** (ANALYZE executes the query; keep read-only semantics strict).

The hub's `diagnose_service` does not proxy postgres; it says "DB adapter not
configured, run get_active_queries / get_slow_statements on postgres-readonly-mcp"
unless a `DIAG_DB_MCP_URL` is configured, in which case it calls those tools
itself over MCP (hub as MCP client). Phase 5.

---

## 5. Phases

| # | Deliverable | Notes |
|---|---|---|
| 0 | Scaffold + fault lab | Repo mirrors the sibling layout. `kind` cluster (docker is present, kubectl/kind are not). Demo app that mirrors the real stack: **Angular app behind nginx + two Spring Boot services + Postgres**, with **injected faults**: CPU throttling, JVM heap vs limit mismatch, Hikari pool exhaustion, N+1 query, zero endpoints, no NetworkPolicy, secret in env, PII in logs, 499/504 at the proxy, unhashed uncached bundle, a route with bad LCP. Every tool gets an integration test against a known fault. |
| 1 | Hub MVP (groups A, B, D-cluster, C-resources) | Read-only client wrapper, RBAC manifests, stdio + Streamable HTTP, sanitizer, caps, audit log. |
| 2 | Probe + Java + proxy tools (groups D-probe, G, H) | Native sidecar manifest + Helm/Kustomize snippet, NetworkPolicy, token auth. Actuator and stub_status readers. This is the stack you actually run, so it comes before generic adapters. |
| 3 | Runbooks + Prometheus adapter | `diagnose_service`, `what_changed`, `health_report`, `compare_replicas`, golden signals (Micrometer metric names as the default map). |
| 4 | RUM (group I) | `rum-client` package for Angular, probe ingest, aggregates + Prometheus export, `diagnose_slow_page`. |
| 5 | Security & leak detection (group E) | Reuse/extend sanitizer patterns from postgres-readonly-mcp; access-log scanner signals. |
| 6 | Traces/logs adapters + Postgres diagnostics | Tempo/Jaeger, Loki, `postgres-readonly-mcp` diagnostics group, hub-as-MCP-client. |
| 7 | Hardening & release | TokenReview auth, distroless image, README threat model in the sibling style, gitleaks config, MIT license. |

---

## 6. Decisions (defaults chosen; say if you want otherwise)
1. **Name**: `kube-diagnostics-mcp` (fits the `-mcp` family; not `-readonly-`
   because the probe has opt-in active checks).
2. **Language**: TypeScript, to reuse the sanitizer, config, logger, and test
   patterns from the two existing servers. Go would give a smaller sidecar
   image (~10 MB vs ~60 MB); worth revisiting only if sidecar footprint
   becomes a complaint.
3. **Observability adapters**: assume kube-prometheus-stack shapes
   (Prometheus, Tempo, Loki) first, OpenTelemetry-collector metric names as
   the default metric map. Jaeger as second trace backend.
4. **Secrets**: hub has zero RBAC on Secrets. If you ever want
   `get_secret_usage` to include key names for volume-mounted secrets, that
   needs `get` on secrets and should be a separate, off-by-default flag.
5. **Passive HTTP response inspection** (scanning real responses for PII)
   needs CAP_NET_RAW packet capture in the probe and only works for plaintext.
   Deferred; `scan_logs_for_sensitive_data` and a synthetic-GET variant cover
   most of the value without it.
6. **Dev environment**: install `kubectl` + `kind` locally (phase 0).
7. **Java assumptions**: Spring Boot with Actuator + Micrometer, HikariCP, Tomcat.
   If any service is Quarkus/Micronaut or has no Actuator, group G degrades to
   what Prometheus/JMX exporter provides. Tell me which.
8. **Proxy assumption**: nginx (stub_status + standard/combined log format with
   `$upstream_response_time` added). Envoy/Traefik/HAProxy would swap the reader
   in `get_proxy_status` / `summarize_access_log`; the tool contracts stay the same.
9. **RUM client**: built on the `web-vitals` library, shipped as a tiny package the
   Angular app imports once in `main.ts`; no third-party RUM SaaS, no user identifiers,
   sampling default 100% (tune down for high traffic).

---

## 7. Research sources
- CNCF step-by-step troubleshooting guide (status → describe/events → logs → config → connectivity):
  https://www.cncf.io/blog/2025/03/13/kubernetes-troubleshooting-a-step-by-step-guide/
- SUSE: troubleshooting slow services (golden signals, dependency chain, DB/N+1/GC root causes):
  https://www.suse.com/c/observability-how-to-troubleshoot-slow-services-in-your-kubernetes-cluster/
- Komodor troubleshooting guide: https://komodor.com/learn/kubernetes-troubleshooting-the-complete-guide/
- Spacelift common errors (CrashLoopBackOff, OOM, throttling, secrets, DB connectivity):
  https://spacelift.io/blog/kubernetes-troubleshooting
- Golden signals / RED / USE: https://www.sysdig.com/blog/golden-signals-kubernetes
- Native sidecars (KEP-753, stable in 1.33): https://www.systemshardening.com/articles/kubernetes/native-sidecar-containers/
- shareProcessNamespace cross-container visibility: https://oneuptime.com/blog/post/2026-02-09-share-process-namespace-cross-container/view
- Existing servers (what not to rebuild): Red Hat kubernetes-mcp-server
  https://developers.redhat.com/articles/2025/09/25/kubernetes-mcp-server-ai-powered-cluster-management ,
  jhmorimoto/kubernetes-readonly-mcp https://glama.ai/mcp/servers/jhmorimoto/kubernetes-readonly-mcp ,
  grafana/mcp-grafana https://github.com/grafana/mcp-grafana
- Security checklist (root, secrets-in-env, NetworkPolicy, exposure):
  https://dev.to/orthogonalinfo/kubernetes-security-checklist-for-production-2026-1j2j
- Leak detection in logs/responses: https://ammune.ai/blog/api-token-and-secrets-leakage-detection ,
  https://www.nightfall.ai/blog/application-log-security-for-developer-platform
- MCP TypeScript SDK, Streamable HTTP + auth: https://ts.sdk.modelcontextprotocol.io/documents/server.html

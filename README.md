# kube-diagnostics-mcp

A read-only [MCP](https://modelcontextprotocol.io) diagnostics service for microservices on Kubernetes.
It turns the debugging runbook into tools so that *"why is checkout slow?"*, *"what changed?"*,
and *"is anything leaking?"* become a conversation with a model instead of an hour of `kubectl`,
dashboards, and log greps.

Sibling of [`postgres-readonly-mcp`](https://github.com/ranson21/postgres-readonly-mcp) and
[`jira-readonly-mcp`](https://github.com/ranson21/jira-readonly-mcp): the server owns the credentials,
calls the real backends, and hands the model compact, sanitized, size-capped results. The model never
sees a kubeconfig, a ServiceAccount token, or a Secret.

```
Claude Code / OpenCode / any MCP client
        │  MCP over Streamable HTTP (bearer token)        or stdio for local use
        ▼
┌──────────────────────────────┐   read-only RBAC: get/list/watch, no Secrets, no exec
│  HUB  (Deployment)           │──► Kubernetes API + metrics.k8s.io
│  encodes the runbook         │──► Prometheus            (optional provider)
│  ~55 tools, 4 runbooks       │──► Datadog / Splunk      (provider stubs, see below)
└──────────┬───────────────────┘
           │ HTTP + shared token, restricted by NetworkPolicy
           ▼
┌──────────────────────────────┐   native sidecar (initContainer, restartPolicy: Always)
│  PROBE  (per pod, optional)  │   shares the pod's network namespace:
│  no Kubernetes credentials   │   /proc/net, DNS, TCP checks, Actuator on localhost,
│  ~40 MB, distroless          │   nginx stub_status, access log, static build, RUM ingest
└──────────────────────────────┘
```

**Status:** v0.1.0. Everything documented below runs end to end against the included fault lab
(kind + Angular/nginx + two Spring Boot services + Postgres with 29 injected faults); the CI
workflow runs the unit tests, builds the image, renders the manifests, and scans for leaked
secrets. Datadog and Splunk providers are interface placeholders; tracing tools return guidance
until a tracing provider exists. The container image is published to GHCR by the release workflow
on `v*` tags; until the first tag, build it locally.

## Contents

- [Why this and not kubectl-as-MCP](#why-this-and-not-kubectl-as-mcp)
- [Threat and security model](#threat-and-security-model)
- [Quick start (local, stdio)](#quick-start-local-stdio)
- [Deploying in a cluster](#deploying-in-a-cluster)
- [The probe sidecar](#the-probe-sidecar)
- [Tools](#tools)
- [Signal providers (Prometheus, Datadog, Splunk)](#signal-providers)
- [Real-user monitoring for the Angular app](#real-user-monitoring)
- [The fault lab](#the-fault-lab)
- [Configuration reference](#configuration-reference)
- [Development](#development)
- [Design notes and limits](#design-notes-and-limits)

## Why this and not kubectl-as-MCP

Generic Kubernetes MCP servers give a model `get pods` and `get logs`. That is table stakes, and this
server has a small set of those primitives too. The value is in three other things:

1. **Composed runbook tools.** `diagnose_service` runs status → events → resources → OOM/crash →
   endpoints → JVM/pool/downstreams → log errors → golden signals → recent changes, and returns
   *ranked hypotheses with evidence and the next tool to call*. `diagnose_slow_requests`,
   `diagnose_slow_page`, and `health_report` do the same for latency, a slow frontend route, and the
   Monday-morning digest.
2. **The in-pod view.** A tiny probe sidecar sees what nothing outside the pod can: sockets in
   `/proc/net`, DNS as the app resolves it, Actuator on localhost when it is deliberately not exposed,
   nginx `stub_status`, the served static build, and browser beacons for real-user monitoring.
3. **Stack-aware analysis.** Spring Boot heap-vs-limit mismatches, HikariCP pool exhaustion, thread
   dump deadlock detection, Java stack-trace grouping, nginx config linting (timeouts, caching,
   security headers), Angular bundle stats, Core Web Vitals per route.

Everything returned is shaped for a model: grouped, counted, capped, and scrubbed.

## Threat and security model

This project is read-only by construction, with independent layers:

1. **RBAC** ([`deploy/hub/rbac.yaml`](deploy/hub/rbac.yaml)): the hub's ServiceAccount gets
   `get`/`list`/`watch` on workloads, pods, `pods/log`, events, ConfigMaps, Services, EndpointSlices,
   NetworkPolicies, Ingresses, HPAs, PDBs, RBAC objects, nodes, and `metrics.k8s.io`. It has **no
   access to Secrets at all**, and no `pods/exec`, `pods/attach`, or `pods/portforward`. Secret
   *usage* is derived from pod specs (which Secret, which key, env or volume), never contents.
2. **A client wrapper with no write methods** ([`src/k8s/client.ts`](src/k8s/client.ts)): every
   Kubernetes call goes through `ReadOnlyKubeClient`, which exposes only get/list/log methods. There
   is no code path that can send a POST, PUT, PATCH, or DELETE, so a bug in a tool cannot mutate the
   cluster even if RBAC were misconfigured.
3. **The probe has no credentials.** It runs as a native sidecar with
   `automountServiceAccountToken` irrelevant (it never talks to the API server), non-root, read-only
   root filesystem, all capabilities dropped. It answers only the hub (shared bearer token, compared in
   constant time) and only on the paths listed in [`src/probe/server.ts`](src/probe/server.ts).
   Actuator endpoints that dump state (`heapdump`, `env`, `logfile`, `shutdown`, ...) are on a deny
   list and are never proxied.
4. **Input guard** ([`src/security/guard.ts`](src/security/guard.ts)): every name, namespace,
   selector, hostname, and port that ends up in an API path or a probe URL is validated against
   Kubernetes naming rules. Fails closed.

On top of those, defense in depth:

- **Sanitizer** ([`src/security/sanitize.ts`](src/security/sanitize.ts)), applied to every tool
  result and every log line: connection strings with credentials (any scheme, plus `jdbc:`), `Bearer`
  and `Basic` tokens, JWTs, `password=`/`api_key=`-style assignments (including `SPRING_DATASOURCE_PASSWORD=`),
  PEM private keys, AWS/GCP/GitHub/Slack/Stripe key shapes. Values stored under credential-looking
  keys are replaced outright. This is a heuristic scrubber, not a guarantee.
- **Env values from Secrets are never resolved.** `get_config` shows them as
  `from: secret:NAME/KEY`. Literal env values under credential-looking names are redacted too, and
  flagged as a finding.
- **Sensitive-data scanning returns counts and masked samples only**
  ([`src/security/sensitive.ts`](src/security/sensitive.ts)): `ja***@***.com`,
  `41** **** **** 11`. The matched value is never returned.
- **Size caps.** Logs are capped by lines and bytes; every result is capped by
  `DIAG_MAX_RESULT_BYTES`; thread dumps and access logs are summarized, never returned raw.
- **Active checks are off by default.** `resolve_dns`, `check_connectivity`,
  `check_security_headers`, and the TLS handshake in `get_tls_status` generate traffic. They require
  `DIAG_ALLOW_ACTIVE_CHECKS=true` on the hub (and on the probe for the in-pod ones) and are labeled
  `[ACTIVE]` in their descriptions.
- **Audit log.** Every tool call is logged with its arguments (free-text arguments omitted), never its
  output.

**What this does not protect against.** Anyone who can call the hub can read anything its RBAC can
read, which includes application logs and ConfigMaps. Treat the hub token like a read-only cluster
credential. Log scrubbing is best-effort; if your application logs raw card numbers, the
`scan_logs_for_sensitive_data` tool will tell you, but `get_logs` will also have shown masked
versions of them to the model. Restrict the hub with `DIAG_NAMESPACES` and a namespaced Role instead
of the ClusterRole when you can.

## Quick start (local, stdio)

Requirements: Node 20+, a kubeconfig with read access.

```sh
git clone https://github.com/ranson21/kube-diagnostics-mcp.git
cd kube-diagnostics-mcp
npm ci && npm run build
```

Register it with your MCP client. Claude Code:

```sh
claude mcp add kube-diagnostics -e DIAG_DEFAULT_NAMESPACE=myapp -- node /path/to/kube-diagnostics-mcp/dist/index.js
```

OpenCode (`opencode.json`):

```json
{
  "mcp": {
    "kube-diagnostics": {
      "type": "local",
      "command": ["node", "/path/to/kube-diagnostics-mcp/dist/index.js"],
      "environment": { "DIAG_DEFAULT_NAMESPACE": "myapp" }
    }
  }
}
```

Then ask: *"run health_report on myapp"*, *"diagnose_service checkout"*, *"what changed in the last
6 hours?"*. In stdio mode the hub uses your kubeconfig's current context and whatever it can read.
Without probes, the probe-backed tools explain what is missing instead of failing.

## Deploying in a cluster

```sh
# 1. Tokens: one for MCP clients, one shared between the hub and every probe.
HUB=$(openssl rand -hex 32); PROBE=$(openssl rand -hex 32)
kubectl kustomize deploy/hub \
  | sed -e "s/REPLACE_WITH_RANDOM_HUB_TOKEN/$HUB/" -e "s/REPLACE_WITH_RANDOM_PROBE_TOKEN/$PROBE/" \
  | kubectl apply -f -

# 2. Reach it (port-forward for a try; an Ingress with TLS for real use).
kubectl -n kube-diagnostics port-forward svc/kube-diagnostics-hub 8090:8090
```

The hub speaks MCP Streamable HTTP at `http://localhost:8090/mcp` with `Authorization: Bearer $HUB`.
Claude Code: `claude mcp add --transport http kube-diagnostics http://localhost:8090/mcp --header "Authorization: Bearer $HUB"`.

[`deploy/hub/deployment.yaml`](deploy/hub/deployment.yaml) runs one replica as non-root with a
read-only root filesystem and a NetworkPolicy that only admits port 8090. Scope it with
`DIAG_NAMESPACES=team-a,team-b` (comma-separated) and, if you prefer, replace the
ClusterRoleBinding with RoleBindings in those namespaces.

The image is `ghcr.io/ranson21/kube-diagnostics-mcp:0.1.0` (distroless Node 22, non-root), or build
your own with `docker build -t kube-diagnostics-mcp:dev .`.

## The probe sidecar

The same image with `DIAG_MODE=probe`. Add it to a workload as a **native sidecar** (Kubernetes
1.29+; an init container with `restartPolicy: Always`, which starts before the app and stays up):

```sh
kubectl -n myapp apply -f deploy/probe/token-secret.yaml      # same value as the hub's probe-token
kubectl -n myapp patch deployment checkout --patch-file deploy/probe/sidecar-patch.yaml
kubectl -n myapp apply -f deploy/probe/networkpolicy.yaml     # only the hub may reach :9911
```

[`deploy/probe/sidecar-patch.yaml`](deploy/probe/sidecar-patch.yaml) documents every knob. The
useful ones:

| Env | Enables |
|---|---|
| `DIAG_PROBE_ACTUATOR_URL=http://127.0.0.1:8080/actuator` | JVM health, thread dumps, HikariCP, per-endpoint metrics, Actuator health (Spring Boot) |
| `DIAG_PROBE_NGINX_STATUS_URL=http://127.0.0.1:8081/stub_status` | `get_proxy_status` |
| `DIAG_PROBE_ACCESS_LOG_PATH=/var/log/nginx/access.json` | `summarize_access_log` (share the log dir via an emptyDir) |
| `DIAG_PROBE_STATIC_DIR=/static` | `get_static_bundle_stats` (share the build dir via a volume) |
| `DIAG_PROBE_RUM_ENABLED=true` | RUM ingest on `POST /rum` and Prometheus metrics on `/metrics` |
| `DIAG_ALLOW_ACTIVE_CHECKS=true` | `resolve_dns`, `check_connectivity` |
| `shareProcessNamespace: true` on the pod | `get_process_stats` sees the app's process |

The hub discovers probes by container name (`diag-probe` by default) and talks to `podIP:9911`.
The probe listens on the pod IP because the hub is in another pod; the NetworkPolicy is what keeps
everyone else out. `/proc/net` needs no special privileges: a sidecar shares the network namespace.

## Tools

Every tool takes `namespace` (optional when `DIAG_DEFAULT_NAMESPACE` is set) and most take
`service`, which is resolved as a Deployment, StatefulSet, DaemonSet, Service, or Pod name, in
that order. `[probe]` tools need the sidecar; `[ACTIVE]` tools need `DIAG_ALLOW_ACTIVE_CHECKS`.
Tools that need a provider that is not configured say so and suggest what to configure.

### Runbooks (start here)

| Tool | Answers |
|---|---|
| `diagnose_service(service)` | "Why is X broken or slow?" Ranked hypotheses with evidence: OOM, crash loops, scheduling, probe failures, image pulls, no endpoints, CPU throttling, JVM pressure, pool exhaustion, slow downstreams, log error clusters, elevated error rate, recent changes, config smells. |
| `diagnose_slow_requests(service, proxy_service?)` | Latency-focused: per-endpoint latency, throttling, GC, HikariCP, thread pool/lock/deadlock, downstream latency, proxy 504/499. |
| `diagnose_slow_page(route, proxy_service?, api_service?)` | A slow Angular route: TTFB vs render split, bundle and caching, browser-side API latency vs service-side metrics, CLS/INP. |
| `health_report(namespace)` | The maintenance digest: unhealthy pods, restarts, warnings, resource pressure, HPA at max, node pressure, endpoint problems, missing NetworkPolicies, security findings, TLS gaps, suggested actions. |

### Orientation

`list_providers`, `list_namespaces`, `list_workloads`, `get_topology` (Service → pods → workloads plus
dependencies inferred from env/ConfigMap references and probe-observed connections),
`get_service_overview`.

### Health and state

`get_pod_status`, `get_events` (deduplicated, warnings first), `get_logs` (sanitized, capped,
`previous=true` for the crashed container, `grep` accepts `/regex/i`), `summarize_log_errors`
(groups by signature; Java stack traces by exception class + first application frame),
`get_config` (resolved env with secret references, probes, resources, mounts, and findings such as
`-Xmx` larger than the memory limit), `get_rollout_history` (revision diffs), `what_changed` (one
timeline of rollouts, scaling, HPA actions, ConfigMap updates, restarts, notable events).

### Performance

`get_resource_pressure` (usage vs requests/limits, CFS throttling ratio via Prometheus, OOM kills),
`compare_replicas` (hot pod, leak, stuck rollout, no node spread), `get_node_pressure`,
`get_hpa_status`, `get_golden_signals`, `query_metrics` (raw PromQL, compacted),
`find_slow_traces` and `get_trace` (need a tracing provider).

### Connectivity

`get_endpoints` (selector mismatches, targetPort vs containerPort), `get_network_policies`,
`get_ingress_routes`, `[probe] get_open_connections` (TIME_WAIT/CLOSE_WAIT storms, connections per
destination resolved to Services), `[probe] get_listening_ports`, `[probe, ACTIVE] resolve_dns`,
`[probe, ACTIVE] check_connectivity` (with a diagnosis: refused vs timeout vs DNS),
`[probe] get_process_stats` (fd count vs limit, threads, zombies).

### Java / Spring Boot

`[probe] get_jvm_health`, `[probe] get_thread_dump_summary` (deadlock detection, pool saturation,
lock contention, top stacks; never the raw dump), `[probe] get_connection_pool_status` (HikariCP),
`get_endpoint_metrics`, `[probe] get_outbound_client_metrics` (`http.client.requests` by target),
`[probe] get_actuator_health`, `get_jvm_config`.

### Proxy / Angular

`[probe] get_proxy_status`, `[probe] summarize_access_log` (status classes, p50/p95 per path,
per-upstream 504s, 499s meaning clients gave up, proxy-vs-upstream gap, scanner-like paths,
sensitive data in the log), `get_proxy_config_summary` (lints the nginx ConfigMap: timeouts,
buffering, gzip, cache headers for hashed chunks vs `index.html`, security headers, rate limits),
`[probe] get_static_bundle_stats`, `[ACTIVE] check_security_headers`.

### Real-user monitoring

`[probe RUM] get_web_vitals` (p75/p95 per route with Google's good/needs-improvement/poor ratings),
`get_page_views`, `get_page_load_breakdown` (Navigation Timing phases), `get_browser_api_latency`
(browser-observed latency per API path, to compare with proxy and service numbers),
`get_frontend_errors`.

### Security

`security_posture` (privileged, root, host namespaces, capabilities, seccomp, writable rootfs,
secrets as env, unpinned images, no limits, SA token automount, missing NetworkPolicy, over-privileged
RBAC; severities critical..info), `get_exposure` (LoadBalancer/NodePort, Ingress with/without TLS,
management paths exposed), `get_rbac_for_workload`, `get_secret_usage` (names and keys only),
`get_tls_status`, `scan_logs_for_sensitive_data`, `[probe] get_egress_destinations` (public
internet and cloud-metadata destinations flagged), `get_image_inventory`.

## Signal providers

The runbooks need a few *signals*: resource usage, golden signals, log search, slow traces, web
vitals. Where they come from is a deployment detail behind
[`src/providers/types.ts`](src/providers/types.ts). The registry asks providers in priority order
and reports which one answered.

| Provider | Configured by | Provides today |
|---|---|---|
| `native` | always | resource usage from metrics-server; golden signals from Micrometer via the probe (cumulative since JVM start, so p50 is the mean and p99 the max); log search from pod logs |
| `prometheus` | `DIAG_PROMETHEUS_URL` | windowed golden signals (`http_server_requests_seconds`, configurable), cAdvisor usage and CFS throttling ratio, raw PromQL |
| `datadog` | `DIAG_DATADOG_API_KEY` + `DIAG_DATADOG_APP_KEY` (+ `DIAG_DATADOG_SITE`) | **placeholder**: validates config, reports "not implemented". The intended API mapping is documented in [`src/providers/datadog/index.ts`](src/providers/datadog/index.ts). |
| `splunk` | `DIAG_SPLUNK_URL` + `DIAG_SPLUNK_TOKEN` (+ `DIAG_SPLUNK_INDEX`) | **placeholder**, same shape, in [`src/providers/splunk/index.ts`](src/providers/splunk/index.ts). |

Why placeholders: in the environment this was built for, the Datadog and Splunk endpoints (and their
official MCP servers) are not reachable yet. When they are, implementing a provider is filling in the
methods of one class; nothing in the tools changes. If you *can* reach the official
[Datadog](https://docs.datadoghq.com/mcp_server/) or
[Splunk](https://help.splunk.com/en/splunk-cloud-platform/mcp-server-for-splunk-platform) MCP
servers, run them alongside this one: they cover ad-hoc log/metric/trace exploration far more
completely, and this server covers what they do not (cluster state, in-pod view, runbooks, security
posture).

## Real-user monitoring

[`rum-client/`](rum-client/) is a ~3 KB browser package built on Google's `web-vitals`. It collects
LCP, INP, CLS, FCP, TTFB, Navigation Timing phases, SPA route views, same-origin API timings, and JS
errors, and beacons them to `/__rum`, which nginx forwards to the probe in the same pod. See
[`rum-client/README.md`](rum-client/README.md) for the Angular Router hook.

Privacy by construction: routes are reported as patterns (`/products/:id`), query strings and
fragments are dropped, there are no cookies and no user identifiers, the session id lives in
`sessionStorage`, and the probe's ingest accepts an allow-list of fields and discards everything
else. Aggregates are kept in memory for `DIAG_PROBE_RUM_RETENTION_MINUTES` (default 6 h) and
exported as Prometheus metrics (`rum_web_vital`, `rum_page_views_total`,
`rum_frontend_errors_total`, `rum_sessions`) for long-term retention.

If you already run Datadog RUM, use it instead and let the (future) Datadog provider answer the
same tools; this client exists because that path was not available.

## The fault lab

[`faultlab/`](faultlab/) is a small but realistic stack: an Angular 20 app behind nginx, two Spring
Boot 3.5 services (Java 21, JPA, Actuator, Micrometer), and Postgres 16 with `pg_stat_statements` and
a read-only role for `postgres-readonly-mcp`. It carries **29 deliberately injected faults**
(CPU throttling, `-Xmx` above the memory limit, a memory leak that ends in OOMKilled, HikariCP pool
exhaustion, an N+1 query, a Java deadlock, a Service selector that matches nothing, no
NetworkPolicy, a root container with a literal password in env, wildcard RBAC on Secrets, a liveness
probe on the wrong path, `proxy_read_timeout 2s` producing 504s, no cache headers, source maps in
prod, a 3.4 MB hero image without dimensions, an 800 ms busy loop in a route, PII in logs, ...).
Every fault is listed in [`faultlab/README.md`](faultlab/README.md) with its symptom, and marked in
source with `FAULT`/`FIX` comments.

```sh
kind create cluster --config deploy/kind/kind-config.yaml
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
kubectl -n kube-system patch deploy metrics-server --type=json \
  -p='[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--kubelet-insecure-tls"}]'

# hub + probes share one probe token; the hub token is what MCP clients present
export HUB_TOKEN=$(openssl rand -hex 32) PROBE_TOKEN=$(openssl rand -hex 32)
docker build -t kube-diagnostics-mcp:dev . && kind load docker-image --name kube-diag kube-diagnostics-mcp:dev
kubectl kustomize deploy/hub \
  | sed -e "s/REPLACE_WITH_RANDOM_HUB_TOKEN/$HUB_TOKEN/" -e "s/REPLACE_WITH_RANDOM_PROBE_TOKEN/$PROBE_TOKEN/" \
        -e "s|ghcr.io/ranson21/kube-diagnostics-mcp:0.1.0|kube-diagnostics-mcp:dev|" \
  | kubectl apply -f -
kubectl -n kube-diagnostics set env deploy/kube-diagnostics-hub DIAG_ALLOW_ACTIVE_CHECKS=true DIAG_DEFAULT_NAMESPACE=faultlab

make -C faultlab build load          # ~5 min cold: Maven and Angular build inside Docker
make -C faultlab deploy              # applies faultlab/k8s-probe: the lab + probe sidecars + RUM (uses $PROBE_TOKEN)
open http://localhost:30080/         # click around to generate RUM data (in a visible window: hidden tabs never paint)
make -C faultlab load-test DURATION=120

kubectl -n kube-diagnostics port-forward svc/kube-diagnostics-hub 8090:8090 &
SMOKE_URL=http://localhost:8090/mcp SMOKE_TOKEN=$HUB_TOKEN npx tsx scripts/smoke.ts faultlab
```

The smoke script calls 35 tools and prints compact results. It talks to the *in-cluster* hub because
kind pod IPs are not routable from the host, and the probe-backed tools need to reach `podIP:9911`.
Without `SMOKE_URL` it spawns a local stdio hub instead, which is fine for everything that only
needs the API server.

What the runbooks find in the lab, unprompted: HikariCP acquisition timeouts and 5-second
connection holds on `order-service`; the `-Xmx900m` vs 512 MiB mismatch and a 1-CPU JVM on
`catalog-service`; per-endpoint p95s for `/reviews` (N+1) and `/products/slow`; 504s per upstream at
the proxy with `proxy_read_timeout 2s`; 16 card numbers and 16 emails in the catalog logs;
`reviews-service` with zero endpoints; wildcard RBAC on Secrets for the order-service
ServiceAccount; no NetworkPolicy; source maps and a 3 MiB hero image in the served build; poor LCP
and CLS on `/products/:id` and poor INP on `/checkout` from RUM.

## Configuration reference

All configuration is environment variables. See [`.env.example`](.env.example).

| Variable | Default | Meaning |
|---|---|---|
| `DIAG_MODE` | `hub` | `hub` or `probe` |
| `DIAG_TRANSPORT` | `stdio` | hub: `stdio` or `http` |
| `DIAG_HTTP_HOST` / `DIAG_HTTP_PORT` | `0.0.0.0` / `8090` | hub HTTP bind |
| `DIAG_HTTP_TOKEN` | | bearer token MCP clients must present (required for http unless `DIAG_HTTP_ALLOW_UNAUTHENTICATED=true`) |
| `DIAG_NAMESPACES` | all | comma-separated allow-list; lists are then done per namespace, so a namespaced Role suffices |
| `DIAG_DEFAULT_NAMESPACE` | | used when a tool call omits `namespace` (defaults to the single allow-listed namespace) |
| `DIAG_ALLOW_ACTIVE_CHECKS` | `false` | enable DNS/TCP/HTTP/TLS checks that generate traffic |
| `DIAG_LOG_MAX_LINES` / `DIAG_LOG_MAX_BYTES` | `500` / `262144` | per-pod log fetch caps |
| `DIAG_MAX_RESULT_BYTES` | `204800` | per-tool result cap |
| `DIAG_PROBE_CONTAINER_NAME` / `DIAG_PROBE_PORT` | `diag-probe` / `9911` | how the hub finds probes |
| `DIAG_PROBE_TOKEN` | | shared hub↔probe token |
| `DIAG_PROBE_TIMEOUT_MS` / `DIAG_K8S_TIMEOUT_MS` | `5000` / `15000` | call timeouts |
| `DIAG_PROMETHEUS_URL`, `DIAG_PROM_HTTP_METRIC`, `DIAG_PROM_SERVICE_LABEL` | | Prometheus provider |
| `DIAG_DATADOG_*`, `DIAG_SPLUNK_*` | | placeholder providers |
| `DIAG_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` (stderr only; stdout is the MCP stream in stdio mode) |
| probe: `DIAG_PROBE_HOST`, `DIAG_PROBE_ACTUATOR_URL`, `DIAG_PROBE_NGINX_STATUS_URL`, `DIAG_PROBE_STATIC_DIR`, `DIAG_PROBE_ACCESS_LOG_PATH`, `DIAG_PROBE_RUM_ENABLED`, `DIAG_PROBE_RUM_MAX_BODY_BYTES` (8192), `DIAG_PROBE_RUM_RETENTION_MINUTES` (360), `DIAG_POD_NAME`, `DIAG_POD_NAMESPACE` | | see [The probe sidecar](#the-probe-sidecar) |

## Development

```sh
npm ci
npm run typecheck
npm test                 # vitest: sanitizer, scanner, guard, config, /proc/net parsing, access log, RUM, thread dumps, nginx conf, model
npm run dev              # stdio hub against your current kubeconfig
DIAG_MODE=probe DIAG_PROBE_ALLOW_UNAUTHENTICATED=true npm run dev   # a local probe on :9911
npx tsx scripts/smoke.ts <namespace> [tool ...]                     # end-to-end against a cluster
```

Layout mirrors the sibling projects: `src/security/` (guard, sanitize, sensitive), `src/k8s/`
(read-only client), `src/probe/` (sidecar server, `/proc/net`, access log, RUM aggregator, hub-side
client), `src/providers/` (signal providers), `src/hub/tools/*` (one file per tool group),
`src/hub/runbooks.ts`, `src/hub/server.ts` (registration), `src/hub/transport/http.ts`.

## Design notes and limits

- **Hub + probe, not sidecar-only.** A sidecar alone sees one pod. Cross-service questions
  (topology, rollouts, events, endpoints, RBAC) need the API server, so the MCP server is a hub and the
  sidecar is a thin probe the hub fans out to. The hub works without any probes.
- **Micrometer's default meters are cumulative.** Without Prometheus, `get_golden_signals` reports
  mean and max since JVM start and says so. Configure `DIAG_PROMETHEUS_URL` for windowed percentiles.
- **`/proc/net` is a snapshot.** `get_open_connections` and `get_egress_destinations` see sockets that
  exist at that instant. Short-lived connections between calls are not seen.
- **Static bundle stats need a shared volume.** Containers do not share filesystems; the fault lab
  copies the build into an emptyDir with an init container. In production, serve from a volume or
  skip that tool.
- **No Secret contents, ever.** `get_tls_status` therefore cannot read certificates from Secrets; with
  active checks it performs a TLS handshake against a host you name instead.
- **Tracing is provider-only.** `find_slow_traces`/`get_trace` return guidance until a Tempo, Jaeger,
  or Datadog provider is implemented.
- **Pattern matching has false positives.** The sensitive-data scanner labels confidence per kind and
  keeps the phone-number detector deliberately narrow.

## License

Apache-2.0. See [LICENSE](LICENSE).

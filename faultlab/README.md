# faultlab

A small, realistic demo stack with **deliberately injected faults**, used to integration-test the
`kube-diagnostics-mcp` tools against known problems. It runs in a local `kind` cluster.

```
browser ── proxy (nginx 1.27, NodePort 30080) ──┬── catalog-service (Spring Boot 3.5, :8080) ──┐
   Angular 20 SPA                               └── order-service   (Spring Boot 3.5, :8080) ──┴── postgres:16-alpine
```

Everything lives in this directory; nothing here touches the rest of the repo.

## Layout

| Path | What |
|---|---|
| `angular-app/` | Angular 20 SPA (standalone components, zoneless, Router). Built inside the proxy image. |
| `proxy/Dockerfile` | node:22 build of the SPA → `nginx:1.27-alpine`. Build context is `faultlab/`. |
| `k8s/nginx.conf` | The nginx config: baked into the image **and** mounted from the `proxy-nginx-conf` ConfigMap. |
| `catalog-service/` | Spring Boot 3.5 / Java 21: products + reviews (Spring Web, Data JPA, Actuator, Micrometer Prometheus). |
| `order-service/` | Spring Boot 3.5 / Java 21: cart, checkout, admin report, deadlock. |
| `k8s/` | Plain manifests + `kustomization.yaml`, namespace `faultlab`. |
| `kind-config.yaml` | kind cluster `kube-diag` with host `30080` → NodePort `30080`. |
| `scripts/load-test.sh` | curl loop that triggers every runtime fault. |
| `Makefile` | `cluster build load deploy status load-test undeploy clean`. |

Images: `faultlab/proxy:dev`, `faultlab/catalog-service:dev`, `faultlab/order-service:dev`
(+ `faultlab/order-service:latest`, which is what the Deployment references — that tag *is* a fault).

## Quick start

```sh
cd faultlab
make cluster            # kind create cluster --config kind-config.yaml  (name: kube-diag)
make build              # three docker builds; Maven + Angular run inside the builds, ~3-5 min cold
make load               # kind load docker-image ...
make deploy             # kubectl apply -k k8s, waits for rollouts (catalog-service is CPU-throttled: 1-3 min)
open http://localhost:30080/
make load-test DURATION=120
```

Prerequisites: Docker, `kind` ≥ 0.20, `kubectl`. No local JDK/Maven/Node/Angular CLI needed.

The Angular app can also be built locally for iteration: `cd angular-app && npm ci && npm run gen-hero && npm run build`.

## Routing table (nginx → services)

| Browser path | Upstream | Notes |
|---|---|---|
| `/` , `/products`, `/products/:id`, `/checkout`, `/admin` | static SPA (`try_files … /index.html`) | Angular routes |
| `/assets/hero-large.png` | static | 3.4 MB generated PNG (LCP fault) |
| `/api/catalog/products` | `catalog-service:8080/products` | list (50 products) |
| `/api/catalog/products/{id}` | `catalog-service:8080/products/{id}` | logs PII |
| `/api/catalog/products/slow` | `catalog-service:8080/products/slow` | sleeps 3 s → **504** |
| `/api/catalog/reviews?productId=` | `catalog-service:8080/reviews?productId=` | N+1 |
| `/api/cart` | `order-service:8080/cart` | static cart |
| `/api/checkout` (POST) | `order-service:8080/checkout` | holds a DB connection 5 s → **504** + pool exhaustion |
| `/api/orders/` | `order-service:8080/orders/` | `/api/orders` lists orders; `/api/orders/deadlock` creates a thread deadlock |
| `/api/admin/report` | `order-service:8080/admin/report` | memory leak |
| `/api/*` (anything else) | — | JSON 404 |
| `/nginx-health` | nginx | the real health endpoint (200) |
| `/healthz` | nginx | 404 — the liveness probe points here (fault) |
| `127.0.0.1:8081/stub_status` | nginx | loopback only, for a sidecar probe |
| `*/actuator/{health,health/liveness,health/readiness,metrics,prometheus,threaddump,env,info,loggers}` | each Spring service, port 8080 | not proxied; reach via `kubectl port-forward` or from inside the cluster |

Postgres: service `postgres:5432`, database `faultlab`, app user `faultlab`, read-only role
`mcp_readonly` (SELECT on all current and future tables, `pg_read_all_stats`), extension
`pg_stat_statements` preloaded. Passwords are in Secret `postgres-credentials`.

## Injected faults

Categories: **pod**, **config**, **network**, **performance**, **security**, **frontend**.
Every fault is marked in source with a `FAULT` comment and a commented `FIX`.

| # | Category | Where | Fault | Symptom |
|---|---|---|---|---|
| 1 | performance | `k8s/catalog-service.yaml` resources | CPU request `50m`, limit `100m` on a JVM | Startup takes 1-3 min; `container_cpu_cfs_throttled_periods_total` climbs; p99 latency balloons under `load-test` |
| 2 | config | `k8s/catalog-service.yaml` env | `JAVA_TOOL_OPTIONS=-Xmx900m` with memory limit `512Mi` | Heap max > container limit; OOMKill would precede any `OutOfMemoryError`; `jvm_memory_max_bytes{area="heap"}` > limit |
| 3 | pod | `k8s/order-service.yaml` resources + `OrderController.adminReport()` | Static list retains 512 KiB per `/admin/report` call; memory limit `256Mi`, heap allowed 90 % of it | After ~60-100 calls the container is **OOMKilled** (exit 137), RESTARTS climbs, `kube_pod_container_status_last_terminated_reason="OOMKilled"` |
| 4 | config | `k8s/order-service.yaml` resources | No `resources.requests` at all (only a memory limit) | Scheduler places it blind; no CPU guarantee; QoS is Burstable-without-requests |
| 5 | config | `k8s/order-service.yaml` image | `faultlab/order-service:latest` | Mutable tag: rollouts not reproducible, "what changed" unanswerable from the image ref |
| 6 | security | `order-service/Dockerfile` + `k8s/order-service.yaml` | No `USER` in the image and no `securityContext` | JVM runs as uid 0 (`kubectl exec … id -u` → 0) |
| 7 | security | `k8s/order-service.yaml` env | `DB_PASSWORD` is a plain literal (`faultlab-dev-password`) next to a `secretKeyRef` | Secret visible in `kubectl get deploy -o yaml`, git, `/actuator/env` (masked there by Boot, but present) |
| 8 | security | `k8s/order-service.yaml` | `automountServiceAccountToken` left default (true) | Over-privileged token (see 9) is mounted at `/var/run/secrets/kubernetes.io/serviceaccount` |
| 9 | security | `k8s/order-service.yaml` ClusterRole/Binding | SA `order-service` bound to ClusterRole with `verbs: ["*"]` on `secrets` | `kubectl auth can-i --as=system:serviceaccount:faultlab:order-service list secrets -A` → yes |
| 10 | network | `k8s/reviews-service.yaml` | Service selector `app: reviews-servcie` (typo) matches nothing | `kubectl get endpoints reviews-service` is empty; callers get connection refused |
| 11 | network | `k8s/networkpolicy.yaml` (commented out) | No NetworkPolicy in the namespace | Every pod can reach every pod and Postgres; cross-namespace ingress unrestricted |
| 12 | pod | `k8s/proxy.yaml` livenessProbe + `k8s/nginx.conf` | Liveness path `/healthz` returns 404 (real endpoint is `/nginx-health`); `periodSeconds: 30`, `failureThreshold: 10` | Proxy restarts every ~5 min; events say `Liveness probe failed: HTTP probe failed with statuscode: 404`; RESTARTS climbs slowly |
| 13 | security | `k8s/ingress.yaml` | Ingress `faultlab.local` with no `tls:` section | Plaintext-only ingress (inert on kind, but visible) |
| 14 | security | `k8s/namespace.yaml` | No `pod-security.kubernetes.io/enforce` label | Root containers and missing securityContexts are admitted silently |
| 15 | performance | `k8s/nginx.conf` `proxy_read_timeout 2s` | Upstream read timeout shorter than `/products/slow` (3 s) and `/checkout` (5 s) | Proxy access log `status:504`, `upstream_status:"504"`, `request_time≈2.0`; backend still completes the work (orders row is written after the 504) |
| 16 | performance | `k8s/nginx.conf` | No `Cache-Control`/`Expires` on content-hashed chunks | Browser revalidates every chunk on every visit |
| 17 | performance | `k8s/nginx.conf` | `index.html` has no `no-cache` | A cached shell can reference chunk hashes that no longer exist after a deploy |
| 18 | security | `k8s/nginx.conf` | No CSP / HSTS / X-Frame-Options / X-Content-Type-Options | `curl -I /` shows none of them |
| 19 | frontend | `proxy/Dockerfile` (`ng build --source-map`) + `nginx.conf` | Source maps shipped and served | `GET /main-*.js.map` → 200 (1.5 MB) |
| 20 | performance | `k8s/nginx.conf` `gzip off` | No compression | ~700 kB of JS served uncompressed |
| 21 | performance | `catalog-service` `CatalogController.reviews()` | **N+1**: 1 query for reviews, then 1 `select … from authors where id=$1` per review | `pg_stat_statements` shows the authors lookup with calls ≈ 10× the reviews query; ~11 round-trips per page |
| 22 | performance | `catalog-service` `/products/slow` | `Thread.sleep(3000)` | 3 s latency → proxy 504 (see 15) |
| 23 | security | `catalog-service` `CatalogController.get()` | INFO log line with `jane.doe@example.com` and `4111 1111 1111 1111` on every `/products/{id}` | PII / PAN-like data in pod logs (`kubectl logs deploy/catalog-service \| grep jane.doe`) |
| 24 | performance | `order-service` `CheckoutService.checkout()` + `application.yml` | `SELECT pg_sleep(5)` inside a transaction; `hikari.maximum-pool-size=2`, `connection-timeout=3000` | 3rd concurrent checkout → HTTP 500 `Connection is not available, request timed out after 3000ms`; `hikaricp_connections_pending` > 0; `/actuator/health` `db` component can time out |
| 25 | performance | `order-service` `GET /orders/deadlock` | Two threads lock two monitors in opposite order | Threads `deadlock-worker-a-N`/`-b-N` stay `BLOCKED` in `/actuator/threaddump`; `jvm_threads_states_threads{state="blocked"}` ≥ 2 |
| 26 | frontend | `angular-app/src/app/pages/product-detail.ts` | 3.4 MB `<img>` hero with no `width`/`height`, not lazy | Poor LCP and CLS on `/products/:id` |
| 27 | frontend | `angular-app/src/app/pages/checkout.ts` `ngOnInit` | Synchronous 800 ms busy loop on the main thread | Poor INP / TBT on `/checkout` (long task ≥ 800 ms) |
| 28 | frontend | `angular-app/src/main.ts` | Imports all of `lodash`, `moment` and every moment locale (CommonJS, not tree-shakable) | Initial bundle ≈ 700 kB raw; `ng build` warns "CommonJS or AMD dependencies can cause optimization bailouts" |
| 29 | frontend | `angular-app/src/app/pages/admin.ts` | ~30 % of `/admin` visits throw `TypeError` from a `setTimeout` callback | Uncaught error visible to `window.onerror` / `error` event (escapes Angular's ErrorHandler) |

Notes:
- Fault 3 needs swap to be disabled for the container to be *OOMKilled* rather than swapping; kubelet
  runs pods with swap off, so in kind it is deterministic. (With plain `docker run`, add `--memory-swap=256m`.)
- Faults 15 and 24 compound: the browser sees a 504 after 2 s while the backend still holds the
  connection for the full 5 s and commits the order, so retries make exhaustion worse.
- The proxy Deployment (fault 12) keeps running between probe failures, so the lab remains usable.

## Frontend

`angular-app/src/main.ts` contains the marker `// RUM client will be bootstrapped here` for the RUM
agent that another component adds later. `index.html` is deliberately free of telemetry.

## Verifying the images without a cluster

```sh
docker network create fl-test
docker run -d --name fl-pg --network fl-test -e POSTGRES_DB=faultlab -e POSTGRES_USER=faultlab \
  -e POSTGRES_PASSWORD=faultlab-dev-password -e MCP_READONLY_PASSWORD=readonly-dev-password \
  -v "$PWD/k8s/init-db.sh:/docker-entrypoint-initdb.d/init-db.sh:ro" \
  postgres:16-alpine -c shared_preload_libraries=pg_stat_statements
docker run -d --name catalog-service --network fl-test -e DB_HOST=fl-pg -e DB_PASSWORD=faultlab-dev-password faultlab/catalog-service:dev
docker run -d --name order-service   --network fl-test -e DB_HOST=fl-pg -e DB_PASSWORD=faultlab-dev-password faultlab/order-service:dev
docker run -d --name fl-proxy --network fl-test -p 127.0.0.1:38080:80 faultlab/proxy:dev
curl -s http://127.0.0.1:38080/api/catalog/products | head -c 200
docker rm -f fl-proxy order-service catalog-service fl-pg; docker network rm fl-test
```

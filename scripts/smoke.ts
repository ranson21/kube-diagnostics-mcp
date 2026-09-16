/**
 * End-to-end smoke test: spawns the hub over stdio against the current
 * kubeconfig and calls a list of tools, printing compact results.
 *   npx tsx scripts/smoke.ts [namespace] [tool ...]
 * With SMOKE_URL=http://localhost:8090/mcp and SMOKE_TOKEN=..., talks to a running (in-cluster,
 * port-forwarded) hub over Streamable HTTP instead - required for probe-backed tools when pod IPs
 * are not routable from your machine (kind, most clouds).
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const ns = process.argv[2] ?? "faultlab";
const only = process.argv.slice(3);

const calls: Array<[string, Record<string, unknown>]> = [
  ["list_providers", {}],
  ["list_workloads", { namespace: ns }],
  ["get_topology", { namespace: ns, include_connections: true }],
  ["get_pod_status", { namespace: ns }],
  ["get_events", { namespace: ns, since: "2h" }],
  ["get_endpoints", { namespace: ns }],
  ["get_config", { namespace: ns, service: "catalog-service" }],
  ["get_resource_pressure", { namespace: ns, service: "catalog-service" }],
  ["security_posture", { namespace: ns, min_severity: "medium" }],
  ["get_network_policies", { namespace: ns, service: "order-service" }],
  ["get_exposure", { namespace: ns }],
  ["get_rbac_for_workload", { namespace: ns, service: "order-service" }],
  ["get_secret_usage", { namespace: ns }],
  ["get_image_inventory", { namespace: ns }],
  ["scan_logs_for_sensitive_data", { namespace: ns, service: "catalog-service", since: "1h" }],
  ["summarize_log_errors", { namespace: ns, service: "order-service", since: "1h", include_warnings: true }],
  ["get_jvm_health", { namespace: ns, service: "catalog-service" }],
  ["get_connection_pool_status", { namespace: ns, service: "order-service" }],
  ["get_thread_dump_summary", { namespace: ns, service: "order-service" }],
  ["get_endpoint_metrics", { namespace: ns, service: "catalog-service" }],
  ["get_actuator_health", { namespace: ns, service: "order-service" }],
  ["get_open_connections", { namespace: ns, service: "order-service" }],
  ["get_egress_destinations", { namespace: ns, service: "catalog-service" }],
  ["get_proxy_status", { namespace: ns, service: "proxy" }],
  ["get_proxy_config_summary", { namespace: ns, service: "proxy" }],
  ["get_static_bundle_stats", { namespace: ns, service: "proxy" }],
  ["summarize_access_log", { namespace: ns, service: "proxy", since: "1h" }],
  ["get_web_vitals", { namespace: ns }],
  ["get_page_views", { namespace: ns }],
  ["get_browser_api_latency", { namespace: ns }],
  ["what_changed", { namespace: ns, since: "24h" }],
  ["diagnose_service", { namespace: ns, service: "order-service" }],
  ["diagnose_slow_requests", { namespace: ns, service: "catalog-service", proxy_service: "proxy" }],
  ["diagnose_slow_page", { namespace: ns, route: "/products/:id", proxy_service: "proxy", api_service: "catalog-service" }],
  ["health_report", { namespace: ns }],
];

async function main() {
  const transport = process.env.SMOKE_URL
    ? new StreamableHTTPClientTransport(new URL(process.env.SMOKE_URL), { requestInit: { headers: process.env.SMOKE_TOKEN ? { authorization: `Bearer ${process.env.SMOKE_TOKEN}` } : {} } })
    : new StdioClientTransport({ command: "node", args: ["dist/index.js"], env: { ...process.env, DIAG_MODE: "hub", DIAG_TRANSPORT: "stdio", DIAG_LOG_LEVEL: process.env.DIAG_LOG_LEVEL ?? "warn" } as Record<string, string>, stderr: "inherit" });
  const client = new Client({ name: "smoke", version: "0" });
  await client.connect(transport);
  const tools = await client.listTools();
  console.log(`tools registered: ${tools.tools.length}`);
  let failed = 0;
  for (const [name, args] of calls) {
    if (only.length && !only.includes(name)) continue;
    const t = Date.now();
    const r = await client.callTool({ name, arguments: args }, undefined, { timeout: 120_000 });
    const text = (r.content as Array<{ type: string; text?: string }>).map((c) => c.text ?? "").join("");
    const ms = Date.now() - t;
    if (r.isError) {
      failed++;
      console.log(`\n### ${name} FAILED (${ms}ms)\n${text.slice(0, 600)}`);
      continue;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = text;
    }
    console.log(`\n### ${name} (${ms}ms, ${text.length} bytes)`);
    console.log(process.env.SMOKE_FULL ? text : compact(parsed));
  }
  await client.close();
  console.log(`\n${failed ? `${failed} tool(s) failed` : "all tools succeeded"}`);
  process.exit(failed ? 1 : 0);
}

function compact(v: unknown): string {
  const o = v as Record<string, unknown>;
  if (!o || typeof o !== "object") return String(v).slice(0, 400);
  const keys = ["findings", "problems", "hypotheses", "verdict", "totalsByKind", "summary", "suggestedActions", "note", "available", "dependencies", "groups", "routes", "pools", "jvms", "deadlocks", "permissions", "images", "destinations", "configs", "pods", "unhealthy", "changes"];
  const out: Record<string, unknown> = {};
  for (const k of keys) if (o[k] !== undefined) out[k] = o[k];
  if (!Object.keys(out).length) return JSON.stringify(o).slice(0, 800);
  const s = JSON.stringify(out, null, 1);
  return s.length > 3500 ? `${s.slice(0, 3500)}\n...` : s;
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

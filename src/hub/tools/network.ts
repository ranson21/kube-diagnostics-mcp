import type { V1NetworkPolicy, V1Pod } from "@kubernetes/client-node";
import type { ToolContext } from "../context.js";
import { nsOf, requireActive } from "../context.js";
import { labelsMatch, resolveWorkload } from "../model.js";
import { assertHostname, assertPort } from "../../security/guard.js";

export async function getEndpoints(ctx: ToolContext, args: { namespace?: string; service?: string }) {
  const ns = nsOf(ctx, args.namespace);
  const [services, slices, pods] = await Promise.all([ctx.k8s.listServices(ns), ctx.k8s.listEndpointSlices(ns), ctx.k8s.listPods(ns)]);
  const rows = services
    .filter((s) => !args.service || s.metadata?.name === args.service)
    .map((s) => {
      const name = s.metadata?.name ?? "";
      const eps = slices.filter((sl) => sl.metadata?.labels?.["kubernetes.io/service-name"] === name).flatMap((sl) => (sl.endpoints ?? []).map((e) => ({ addresses: e.addresses, ready: e.conditions?.ready ?? false, serving: e.conditions?.serving, terminating: e.conditions?.terminating, target: e.targetRef ? `${e.targetRef.kind}/${e.targetRef.name}` : undefined, ports: (sl.ports ?? []).map((p) => `${p.name ?? ""}:${p.port}`) })));
      const matching = pods.filter((p) => labelsMatch(p.metadata?.labels, s.spec?.selector));
      const findings: string[] = [];
      if (s.spec?.selector && !matching.length) findings.push(`selector ${JSON.stringify(s.spec.selector)} matches no pods - check labels on the workload's pod template.`);
      if (matching.length && !eps.some((e) => e.ready)) findings.push(`${matching.length} pods match but none is a ready endpoint - readiness probe failing or pods not Running.`);
      for (const port of s.spec?.ports ?? []) {
        const tp = port.targetPort;
        if (tp !== undefined && matching.length) {
          const first = matching[0];
          const containerPorts = (first.spec?.containers ?? []).flatMap((c) => (c.ports ?? []).map((cp) => ({ name: cp.name, port: cp.containerPort })));
          const ok = typeof tp === "number" ? containerPorts.some((cp) => cp.port === tp) || containerPorts.length === 0 : containerPorts.some((cp) => cp.name === tp);
          if (!ok) findings.push(`targetPort ${tp} does not match any declared containerPort on the pods (${containerPorts.map((c) => `${c.name ?? ""}:${c.port}`).join(", ") || "none declared"}).`);
        }
      }
      if (s.spec?.type === "ExternalName") findings.push(`ExternalName -> ${s.spec.externalName}`);
      return { service: name, type: s.spec?.type, clusterIP: s.spec?.clusterIP, ports: (s.spec?.ports ?? []).map((p) => `${p.name ?? ""} ${p.port}->${p.targetPort ?? p.port}/${p.protocol ?? "TCP"}`), selector: s.spec?.selector, matchingPods: matching.length, endpoints: eps, readyEndpoints: eps.filter((e) => e.ready).length, findings };
    });
  return { namespace: ns, services: rows, problems: rows.flatMap((r) => r.findings.map((f) => `${r.service}: ${f}`)) };
}

function describePolicy(p: V1NetworkPolicy) {
  const types = p.spec?.policyTypes ?? ["Ingress"];
  const peer = (x: { podSelector?: { matchLabels?: Record<string, string> }; namespaceSelector?: { matchLabels?: Record<string, string> }; ipBlock?: { cidr?: string; except?: string[] } }) =>
    x.ipBlock ? `cidr ${x.ipBlock.cidr}${x.ipBlock.except?.length ? ` except ${x.ipBlock.except.join(",")}` : ""}` : `${x.namespaceSelector ? `ns${JSON.stringify(x.namespaceSelector.matchLabels ?? {})}` : "same-ns"} pods${JSON.stringify(x.podSelector?.matchLabels ?? {})}`;
  return {
    name: p.metadata?.name,
    appliesTo: p.spec?.podSelector?.matchLabels && Object.keys(p.spec.podSelector.matchLabels).length ? p.spec.podSelector.matchLabels : "ALL pods in namespace",
    policyTypes: types,
    ingress: types.includes("Ingress") ? (p.spec?.ingress ?? []).map((r) => ({ from: (r._from ?? []).map(peer).join(" | ") || "ANY", ports: (r.ports ?? []).map((pt) => `${pt.port ?? "*"}/${pt.protocol ?? "TCP"}`) })) : undefined,
    egress: types.includes("Egress") ? (p.spec?.egress ?? []).map((r) => ({ to: (r.to ?? []).map(peer).join(" | ") || "ANY", ports: (r.ports ?? []).map((pt) => `${pt.port ?? "*"}/${pt.protocol ?? "TCP"}`) })) : undefined,
    isDefaultDeny: !!(p.spec?.podSelector && !Object.keys(p.spec.podSelector.matchLabels ?? {}).length && (!p.spec?.ingress || !p.spec.ingress.length) && types.includes("Ingress")),
  };
}

export async function getNetworkPolicies(ctx: ToolContext, args: { namespace?: string; service?: string }) {
  const ns = nsOf(ctx, args.namespace);
  const policies = await ctx.k8s.listNetworkPolicies(ns);
  const findings: string[] = [];
  if (!policies.length) findings.push(`namespace "${ns}" has NO NetworkPolicy: every pod in the cluster can reach every pod here, and these pods can reach anything (lateral movement / exfil is unrestricted). Start with a default-deny ingress+egress policy and allow what is needed.`);
  const hasDefaultDeny = policies.some((p) => describePolicy(p).isDefaultDeny);
  if (policies.length && !hasDefaultDeny) findings.push("no default-deny policy: pods not selected by any policy remain wide open.");
  let target;
  if (args.service) {
    const w = await resolveWorkload(ctx.k8s, ns, args.service);
    const labels = w.templateMeta?.labels ?? w.pods[0]?.metadata?.labels;
    const applying = policies.filter((p) => !Object.keys(p.spec?.podSelector?.matchLabels ?? {}).length || labelsMatch(labels, p.spec?.podSelector?.matchLabels));
    const ingressCovered = applying.some((p) => (p.spec?.policyTypes ?? ["Ingress"]).includes("Ingress"));
    const egressCovered = applying.some((p) => (p.spec?.policyTypes ?? ["Ingress"]).includes("Egress"));
    if (!ingressCovered) findings.push(`${w.name}: no policy restricts INGRESS to it.`);
    if (!egressCovered) findings.push(`${w.name}: no policy restricts EGRESS from it (can reach the internet, other namespaces, the metadata service...).`);
    target = { workload: `${w.kind}/${w.name}`, labels, policiesApplying: applying.map((p) => p.metadata?.name), ingressRestricted: ingressCovered, egressRestricted: egressCovered };
  }
  return { namespace: ns, policies: policies.map(describePolicy), target, findings };
}

export async function getIngressRoutes(ctx: ToolContext, args: { namespace?: string }) {
  const ns = nsOf(ctx, args.namespace);
  const [ingresses, services] = await Promise.all([ctx.k8s.listIngresses(ns), ctx.k8s.listServices(ns)]);
  const svcNames = new Set(services.map((s) => s.metadata?.name));
  const findings: string[] = [];
  const rows = ingresses.map((ing) => {
    const tlsHosts = new Set((ing.spec?.tls ?? []).flatMap((t) => t.hosts ?? []));
    const rules = (ing.spec?.rules ?? []).map((r) => ({
      host: r.host ?? "*",
      tls: r.host ? tlsHosts.has(r.host) : (ing.spec?.tls ?? []).length > 0,
      paths: (r.http?.paths ?? []).map((p) => {
        const svc = p.backend?.service?.name;
        if (svc && !svcNames.has(svc)) findings.push(`${ing.metadata?.name}: path ${p.path} -> Service "${svc}" does not exist.`);
        return { path: p.path ?? "/", pathType: p.pathType, service: svc, port: p.backend?.service?.port?.number ?? p.backend?.service?.port?.name };
      }),
    }));
    for (const r of rules) if (!r.tls) findings.push(`${ing.metadata?.name}: host ${r.host} has no TLS block - served over plain HTTP unless the controller forces redirect/termination elsewhere.`);
    return { name: ing.metadata?.name, className: ing.spec?.ingressClassName ?? ing.metadata?.annotations?.["kubernetes.io/ingress.class"], rules, tls: (ing.spec?.tls ?? []).map((t) => ({ hosts: t.hosts, secret: t.secretName })), loadBalancer: (ing.status?.loadBalancer?.ingress ?? []).map((l) => l.ip ?? l.hostname), annotations: Object.keys(ing.metadata?.annotations ?? {}) };
  });
  return { namespace: ns, ingresses: rows, findings };
}

async function podArg(ctx: ToolContext, ns: string, args: { pod?: string; service?: string }): Promise<V1Pod> {
  if (args.pod) return ctx.k8s.getPod(ns, args.pod);
  if (args.service) {
    const w = await resolveWorkload(ctx.k8s, ns, args.service);
    const p = w.pods.find((p) => p.status?.phase === "Running") ?? w.pods[0];
    if (!p) throw new Error(`${w.kind}/${w.name} has no pods.`);
    return p;
  }
  throw new Error("Provide `pod` or `service`.");
}

export async function getOpenConnections(ctx: ToolContext, args: { namespace?: string; pod?: string; service?: string }) {
  const ns = nsOf(ctx, args.namespace);
  const pod = await podArg(ctx, ns, args);
  const [conns, services, pods] = await Promise.all([ctx.probe.connections(pod), ctx.k8s.listServices(ns), ctx.k8s.listPods(ns)]);
  const svcByIp = new Map(services.map((s) => [s.spec?.clusterIP ?? "", s.metadata?.name ?? ""]));
  const podByIp = new Map(pods.map((p) => [p.status?.podIP ?? "", p.metadata?.name ?? ""]));
  const findings: string[] = [];
  const tw = conns.states.TIME_WAIT ?? 0;
  const cw = conns.states.CLOSE_WAIT ?? 0;
  const est = conns.states.ESTABLISHED ?? 0;
  if (tw > 1000) findings.push(`${tw} sockets in TIME_WAIT: a client is opening a new connection per request (no keep-alive / no pooling); ephemeral-port exhaustion risk.`);
  if (cw > 50) findings.push(`${cw} sockets in CLOSE_WAIT: the application is not closing connections the peer closed - fd leak (check fd count with get_process_stats).`);
  for (const e of conns.established) if (e.count > 50) findings.push(`${e.count} established connections to ${svcByIp.get(e.remote) ?? podByIp.get(e.remote) ?? e.remote}:${e.port} - pool larger than expected or connection leak.`);
  return {
    pod: pod.metadata?.name,
    namespace: ns,
    available: conns.available,
    note: conns.note,
    states: conns.states,
    established: conns.established.map((e) => ({ ...e, resolved: svcByIp.get(e.remote) ? `service/${svcByIp.get(e.remote)}` : podByIp.get(e.remote) ? `pod/${podByIp.get(e.remote)}` : isPrivate(e.remote) ? undefined : "EXTERNAL" })),
    listening: conns.listening,
    totals: { ...conns.totals, established: est },
    findings,
  };
}

export function isPrivate(ip: string): boolean {
  if (ip === "127.0.0.1" || ip === "::1" || ip.startsWith("127.")) return true;
  if (/^10\./.test(ip)) return true;
  if (/^192\.168\./.test(ip)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return true;
  if (/^169\.254\./.test(ip)) return true; // link-local (cloud metadata lives here: flag separately)
  if (/^fd|^fe80|^fc/i.test(ip)) return true;
  if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(ip)) return true; // CGNAT, used by some CNIs
  return false;
}

export async function resolveDns(ctx: ToolContext, args: { namespace?: string; pod?: string; service?: string; name: string }) {
  requireActive(ctx, "resolve_dns");
  const ns = nsOf(ctx, args.namespace);
  const pod = await podArg(ctx, ns, args);
  const r = await ctx.probe.dns(pod, assertHostname(args.name));
  const findings: string[] = [];
  if (r.error) findings.push(`resolution failed: ${r.error}. If the name is a Service in another namespace use name.namespace.svc; check ndots (${r.resolvConf?.options.join(" ")}) and search domains.`);
  if (r.durationMs > 500) findings.push(`DNS took ${r.durationMs}ms - CoreDNS overloaded or ndots:5 causing 4-5 failed lookups before the FQDN.`);
  return { pod: pod.metadata?.name, ...r, findings };
}

export async function checkConnectivity(ctx: ToolContext, args: { namespace?: string; pod?: string; service?: string; host: string; port: number }) {
  requireActive(ctx, "check_connectivity");
  const ns = nsOf(ctx, args.namespace);
  const pod = await podArg(ctx, ns, args);
  const r = await ctx.probe.connect(pod, assertHostname(args.host), assertPort(args.port));
  const findings: string[] = [];
  if (!r.ok) {
    if (/ECONNREFUSED/.test(r.error ?? "")) findings.push("connection refused: the host is reachable but nothing listens on that port (wrong port? app not started? Service targetPort mismatch?).");
    else if (/timeout|ETIMEDOUT/.test(r.error ?? "")) findings.push("timeout: packets are dropped - a NetworkPolicy, security group, or firewall in the path, or the host is down.");
    else if (/ENOTFOUND|EAI_AGAIN/.test(r.error ?? "")) findings.push("DNS failure - run resolve_dns for this name from the same pod.");
  } else if (r.durationMs > 200) findings.push(`TCP connect took ${r.durationMs}ms - cross-region or overloaded target.`);
  return { pod: pod.metadata?.name, ...r, findings };
}

export async function getProcessStats(ctx: ToolContext, args: { namespace?: string; pod?: string; service?: string }) {
  const ns = nsOf(ctx, args.namespace);
  const pod = await podArg(ctx, ns, args);
  const r = await ctx.probe.processes(pod);
  const findings: string[] = [];
  for (const p of r.processes) {
    if (p.fdCount !== undefined && p.fdLimit !== undefined && p.fdCount > p.fdLimit * 0.8) findings.push(`${p.comm}[${p.pid}]: ${p.fdCount}/${p.fdLimit} file descriptors - about to hit "Too many open files".`);
    if (p.threads > 2000) findings.push(`${p.comm}[${p.pid}]: ${p.threads} threads - unbounded thread creation.`);
    if (p.state === "Z") findings.push(`${p.comm}[${p.pid}] is a zombie.`);
    if (p.state === "D") findings.push(`${p.comm}[${p.pid}] is in uninterruptible sleep (blocked on I/O).`);
  }
  return { pod: pod.metadata?.name, namespace: ns, ...r, findings };
}

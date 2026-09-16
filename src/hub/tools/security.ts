import type { V1Container, V1PodSpec, V1PolicyRule } from "@kubernetes/client-node";
import { connect as tlsConnect } from "node:tls";
import type { ToolContext } from "../context.js";
import { nsOf, requireActive } from "../context.js";
import { labelsMatch, resolveWorkload, ageSeconds, humanDuration } from "../model.js";
import { isSensitiveKey } from "../../security/sanitize.js";
import { assertHostname, assertPort } from "../../security/guard.js";
import { isPrivate } from "./network.js";

type Severity = "critical" | "high" | "medium" | "low" | "info";
interface Finding {
  severity: Severity;
  check: string;
  object: string;
  detail: string;
  fix?: string;
}

function checkContainer(c: V1Container, pod: V1PodSpec, object: string, out: Finding[]) {
  const sc = c.securityContext ?? {};
  const psc = pod.securityContext ?? {};
  const runAsNonRoot = sc.runAsNonRoot ?? psc.runAsNonRoot;
  const runAsUser = sc.runAsUser ?? psc.runAsUser;
  if (sc.privileged) out.push({ severity: "critical", check: "privileged", object, detail: `${c.name} runs privileged (full host access)`, fix: "remove privileged: true; grant specific capabilities if truly needed" });
  if (!runAsNonRoot && (runAsUser === undefined || runAsUser === 0)) out.push({ severity: "high", check: "runs-as-root", object, detail: `${c.name} may run as root (no runAsNonRoot/runAsUser)`, fix: "set securityContext.runAsNonRoot: true and runAsUser: <uid> (or USER in the Dockerfile)" });
  if (sc.allowPrivilegeEscalation !== false) out.push({ severity: "medium", check: "privilege-escalation", object, detail: `${c.name} allows privilege escalation`, fix: "securityContext.allowPrivilegeEscalation: false" });
  if (sc.readOnlyRootFilesystem !== true) out.push({ severity: "low", check: "writable-rootfs", object, detail: `${c.name} has a writable root filesystem`, fix: "securityContext.readOnlyRootFilesystem: true + emptyDir for /tmp" });
  const added = sc.capabilities?.add ?? [];
  const dropped = sc.capabilities?.drop ?? [];
  if (added.length) out.push({ severity: added.some((x) => /SYS_ADMIN|NET_ADMIN|SYS_PTRACE|ALL/i.test(x)) ? "high" : "medium", check: "capabilities-added", object, detail: `${c.name} adds capabilities ${added.join(",")}` });
  if (!dropped.some((x) => x.toUpperCase() === "ALL")) out.push({ severity: "low", check: "capabilities-not-dropped", object, detail: `${c.name} does not drop ALL capabilities`, fix: "securityContext.capabilities.drop: [ALL]" });
  const seccomp = sc.seccompProfile?.type ?? psc.seccompProfile?.type;
  if (!seccomp || seccomp === "Unconfined") out.push({ severity: "low", check: "no-seccomp", object, detail: `${c.name} has no seccomp profile`, fix: "seccompProfile.type: RuntimeDefault" });
  const literalSecrets = (c.env ?? []).filter((e) => e.value !== undefined && isSensitiveKey(e.name)).map((e) => e.name);
  if (literalSecrets.length) out.push({ severity: "high", check: "secret-literal-in-env", object, detail: `${c.name}: ${literalSecrets.join(", ")} set as plain env values in the pod spec`, fix: "move to a Secret and mount as a file (or at least secretKeyRef)" });
  const secretEnv = (c.env ?? []).filter((e) => e.valueFrom?.secretKeyRef).map((e) => e.name);
  const secretEnvFrom = (c.envFrom ?? []).filter((e) => e.secretRef).map((e) => e.secretRef!.name);
  if (secretEnv.length || secretEnvFrom.length) out.push({ severity: "medium", check: "secret-as-env", object, detail: `${c.name}: secrets exposed as env vars (${[...secretEnv, ...secretEnvFrom.map((n) => `envFrom:${n}`)].slice(0, 6).join(", ")})`, fix: "mount secrets as volumes; env is visible in /proc, crash dumps, and child processes" });
  if (!c.resources?.limits?.memory || !c.resources?.limits?.cpu) out.push({ severity: "low", check: "no-limits", object, detail: `${c.name} lacks ${!c.resources?.limits?.memory ? "memory" : ""}${!c.resources?.limits?.memory && !c.resources?.limits?.cpu ? "+" : ""}${!c.resources?.limits?.cpu ? "cpu" : ""} limits (DoS amplification / noisy neighbour)` });
  if (/:latest$/.test(c.image ?? "") || !/[:@]/.test(c.image ?? "")) out.push({ severity: "medium", check: "mutable-image-tag", object, detail: `${c.name} image ${c.image} is unpinned`, fix: "pin to a version tag or digest" });
  if (c.imagePullPolicy === "Always" && /@sha256:/.test(c.image ?? "")) out.push({ severity: "info", check: "pull-always-with-digest", object, detail: `${c.name} pulls Always despite a digest` });
}

export async function securityPosture(ctx: ToolContext, args: { namespace?: string; service?: string; min_severity?: Severity }) {
  const ns = nsOf(ctx, args.namespace);
  const [deps, sts, ds, pods, policies, sas, rbs, crbs, roles, croles] = await Promise.all([
    ctx.k8s.listDeployments(ns),
    ctx.k8s.listStatefulSets(ns),
    ctx.k8s.listDaemonSets(ns),
    ctx.k8s.listPods(ns),
    ctx.k8s.listNetworkPolicies(ns),
    ctx.k8s.listServiceAccounts(ns),
    ctx.k8s.listRoleBindings(ns),
    ctx.k8s.listClusterRoleBindings().catch(() => []),
    ctx.k8s.listRoles(ns),
    ctx.k8s.listClusterRoles().catch(() => []),
  ]);
  const findings: Finding[] = [];
  const workloads = [
    ...deps.map((d) => ({ object: `Deployment/${d.metadata?.name}`, name: d.metadata?.name ?? "", spec: d.spec?.template?.spec })),
    ...sts.map((s) => ({ object: `StatefulSet/${s.metadata?.name}`, name: s.metadata?.name ?? "", spec: s.spec?.template?.spec })),
    ...ds.map((d) => ({ object: `DaemonSet/${d.metadata?.name}`, name: d.metadata?.name ?? "", spec: d.spec?.template?.spec })),
    ...pods.filter((p) => !p.metadata?.ownerReferences?.length).map((p) => ({ object: `Pod/${p.metadata?.name}`, name: p.metadata?.name ?? "", spec: p.spec })),
  ].filter((w) => !args.service || w.name === args.service);

  for (const w of workloads) {
    const spec = w.spec;
    if (!spec) continue;
    if (spec.hostNetwork) findings.push({ severity: "high", check: "host-network", object: w.object, detail: "uses hostNetwork (sees all node traffic, bypasses NetworkPolicy)" });
    if (spec.hostPID) findings.push({ severity: "high", check: "host-pid", object: w.object, detail: "uses hostPID (can see/signal every process on the node)" });
    if (spec.hostIPC) findings.push({ severity: "medium", check: "host-ipc", object: w.object, detail: "uses hostIPC" });
    for (const v of spec.volumes ?? []) {
      if (v.hostPath) findings.push({ severity: /^\/(etc|var\/run|proc|sys|$)/.test(v.hostPath.path ?? "") ? "critical" : "high", check: "hostpath-volume", object: w.object, detail: `mounts hostPath ${v.hostPath.path}`, fix: "use a PVC/ConfigMap/emptyDir instead" });
    }
    if (spec.automountServiceAccountToken !== false) {
      const sa = sas.find((s) => s.metadata?.name === (spec.serviceAccountName ?? "default"));
      if (sa?.automountServiceAccountToken !== false) findings.push({ severity: "low", check: "sa-token-automount", object: w.object, detail: `ServiceAccount token auto-mounted (${spec.serviceAccountName ?? "default"}) - an RCE in the app becomes an API token`, fix: "automountServiceAccountToken: false unless the app calls the Kubernetes API" });
    }
    for (const c of [...(spec.initContainers ?? []), ...(spec.containers ?? [])]) checkContainer(c, spec, w.object, findings);
    const labels = w.spec ? (w.object.startsWith("Pod/") ? pods.find((p) => p.metadata?.name === w.name)?.metadata?.labels : [...deps, ...sts, ...ds].find((x) => x.metadata?.name === w.name)?.spec?.template?.metadata?.labels) : undefined;
    const covered = policies.some((p) => !Object.keys(p.spec?.podSelector?.matchLabels ?? {}).length || labelsMatch(labels, p.spec?.podSelector?.matchLabels));
    if (!covered) findings.push({ severity: policies.length ? "medium" : "high", check: "no-network-policy", object: w.object, detail: policies.length ? "no NetworkPolicy selects these pods" : "namespace has no NetworkPolicy at all", fix: "add default-deny ingress/egress and explicit allows" });
    // RBAC for the workload's SA
    const saName = spec.serviceAccountName ?? "default";
    const rules = rulesForSubject(saName, ns, rbs, crbs, roles, croles);
    for (const r of rules) {
      const verbs = r.verbs ?? [];
      const resources = r.resources ?? [];
      if (verbs.includes("*") && resources.includes("*")) findings.push({ severity: "critical", check: "rbac-wildcard", object: w.object, detail: `ServiceAccount ${saName} has * on * (${r.scope})`, fix: "scope the role to the exact resources and verbs the app needs" });
      else if (resources.includes("secrets") && verbs.some((v) => ["*", "get", "list", "watch"].includes(v))) findings.push({ severity: "high", check: "rbac-secrets-read", object: w.object, detail: `ServiceAccount ${saName} can read secrets (${r.scope}: ${verbs.join(",")})` });
      else if (verbs.some((v) => ["create", "patch", "update", "delete", "*"].includes(v)) && resources.some((x) => ["pods", "deployments", "daemonsets", "clusterrolebindings", "rolebindings", "*"].includes(x))) findings.push({ severity: "high", check: "rbac-write", object: w.object, detail: `ServiceAccount ${saName} can ${verbs.join(",")} ${resources.join(",")} (${r.scope})` });
      if (resources.includes("pods/exec") || resources.includes("pods/attach")) findings.push({ severity: "high", check: "rbac-exec", object: w.object, detail: `ServiceAccount ${saName} can exec into pods` });
    }
  }
  const order: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const min = order[args.min_severity ?? "low"];
  const filtered = findings.filter((f) => order[f.severity] <= min).sort((a, b) => order[a.severity] - order[b.severity]);
  const counts: Record<string, number> = {};
  for (const f of filtered) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  return { namespace: ns, workloadsChecked: workloads.length, summary: counts, findings: filtered, note: "Static checks on pod specs, NetworkPolicies, and RBAC. No Secret contents are read. Complements (does not replace) admission policy and image scanning." };
}

function rulesForSubject(sa: string, ns: string, rbs: Awaited<ReturnType<ToolContext["k8s"]["listRoleBindings"]>>, crbs: Awaited<ReturnType<ToolContext["k8s"]["listClusterRoleBindings"]>>, roles: Awaited<ReturnType<ToolContext["k8s"]["listRoles"]>>, croles: Awaited<ReturnType<ToolContext["k8s"]["listClusterRoles"]>>) {
  const out: Array<V1PolicyRule & { scope: string }> = [];
  const matches = (subjects?: Array<{ kind?: string; name?: string; namespace?: string }>) => (subjects ?? []).some((s) => (s.kind === "ServiceAccount" && s.name === sa && (s.namespace ?? ns) === ns) || (s.kind === "Group" && (s.name === "system:serviceaccounts" || s.name === `system:serviceaccounts:${ns}`)) || (s.kind === "Group" && s.name === "system:authenticated"));
  for (const rb of rbs) {
    if (!matches(rb.subjects)) continue;
    const ref = rb.roleRef;
    const rules = ref.kind === "ClusterRole" ? croles.find((r) => r.metadata?.name === ref.name)?.rules : roles.find((r) => r.metadata?.name === ref.name)?.rules;
    for (const r of rules ?? []) out.push({ ...r, scope: `RoleBinding/${rb.metadata?.name} -> ${ref.kind}/${ref.name}` });
  }
  for (const crb of crbs) {
    if (!matches(crb.subjects)) continue;
    const rules = croles.find((r) => r.metadata?.name === crb.roleRef.name)?.rules;
    for (const r of rules ?? []) out.push({ ...r, scope: `ClusterRoleBinding/${crb.metadata?.name} -> ClusterRole/${crb.roleRef.name} (cluster-wide)` });
  }
  return out;
}

export async function getRbacForWorkload(ctx: ToolContext, args: { namespace?: string; service: string }) {
  const ns = nsOf(ctx, args.namespace);
  const w = await resolveWorkload(ctx.k8s, ns, args.service);
  const sa = w.serviceAccountName ?? "default";
  const [rbs, crbs, roles, croles] = await Promise.all([ctx.k8s.listRoleBindings(ns), ctx.k8s.listClusterRoleBindings().catch(() => []), ctx.k8s.listRoles(ns), ctx.k8s.listClusterRoles().catch(() => [])]);
  const rules = rulesForSubject(sa, ns, rbs, crbs, roles, croles);
  return {
    workload: `${w.kind}/${w.name}`,
    serviceAccount: sa,
    tokenAutomounted: (w.deployment?.spec?.template?.spec?.automountServiceAccountToken ?? w.pods[0]?.spec?.automountServiceAccountToken ?? true) !== false,
    permissions: rules.map((r) => ({ scope: r.scope, apiGroups: r.apiGroups, resources: r.resources, verbs: r.verbs, resourceNames: r.resourceNames })),
    verdict: !rules.length ? "no RBAC grants (good, unless the app needs the API)" : rules.some((r) => (r.verbs ?? []).includes("*") || (r.resources ?? []).includes("*")) ? "OVER-PRIVILEGED (wildcards)" : rules.some((r) => (r.resources ?? []).includes("secrets")) ? "can read secrets - review" : "scoped grants - review verbs",
  };
}

export async function getSecretUsage(ctx: ToolContext, args: { namespace?: string }) {
  const ns = nsOf(ctx, args.namespace);
  const [deps, sts, ds, pods] = await Promise.all([ctx.k8s.listDeployments(ns), ctx.k8s.listStatefulSets(ns), ctx.k8s.listDaemonSets(ns), ctx.k8s.listPods(ns)]);
  const usage = new Map<string, Array<{ workload: string; how: string }>>();
  const add = (secret: string | undefined, workload: string, how: string) => {
    if (!secret) return;
    const l = usage.get(secret) ?? [];
    l.push({ workload, how });
    usage.set(secret, l);
  };
  const scan = (object: string, spec?: V1PodSpec) => {
    if (!spec) return;
    for (const c of [...(spec.initContainers ?? []), ...(spec.containers ?? [])]) {
      for (const e of c.env ?? []) add(e.valueFrom?.secretKeyRef?.name, object, `env ${e.name} <- key ${e.valueFrom?.secretKeyRef?.key}`);
      for (const e of c.envFrom ?? []) add(e.secretRef?.name, object, `envFrom (all keys as env)`);
    }
    for (const v of spec.volumes ?? []) {
      add(v.secret?.secretName, object, `volume ${v.name}`);
      for (const s of v.projected?.sources ?? []) add(s.secret?.name, object, `projected volume ${v.name}`);
    }
    for (const ips of spec.imagePullSecrets ?? []) add(ips.name, object, "imagePullSecret");
  };
  for (const d of deps) scan(`Deployment/${d.metadata?.name}`, d.spec?.template?.spec);
  for (const s of sts) scan(`StatefulSet/${s.metadata?.name}`, s.spec?.template?.spec);
  for (const d of ds) scan(`DaemonSet/${d.metadata?.name}`, d.spec?.template?.spec);
  for (const p of pods.filter((p) => !p.metadata?.ownerReferences?.length)) scan(`Pod/${p.metadata?.name}`, p.spec);
  const rows = [...usage.entries()].map(([secret, refs]) => ({ secret, referencedBy: refs, exposedAsEnv: refs.some((r) => r.how.startsWith("env")), workloads: [...new Set(refs.map((r) => r.workload))].length }));
  return { namespace: ns, secrets: rows, findings: rows.filter((r) => r.exposedAsEnv).map((r) => `${r.secret} is exposed as environment variables in ${r.referencedBy.filter((x) => x.how.startsWith("env")).map((x) => x.workload).join(", ")}`), note: "Derived from pod specs only; Secret contents and unreferenced Secrets are not visible to this server (no RBAC on secrets)." };
}

export async function getExposure(ctx: ToolContext, args: { namespace?: string }) {
  const ns = nsOf(ctx, args.namespace);
  const [services, ingresses, pods] = await Promise.all([ctx.k8s.listServices(ns), ctx.k8s.listIngresses(ns), ctx.k8s.listPods(ns)]);
  const findings: string[] = [];
  const exposed = services
    .filter((s) => s.spec?.type === "LoadBalancer" || s.spec?.type === "NodePort" || (s.spec?.externalIPs ?? []).length)
    .map((s) => {
      const backing = pods.filter((p) => labelsMatch(p.metadata?.labels, s.spec?.selector)).map((p) => p.metadata?.ownerReferences?.[0]?.name ?? p.metadata?.name);
      const ports = (s.spec?.ports ?? []).map((p) => `${p.port}${p.nodePort ? ` nodePort=${p.nodePort}` : ""}/${p.protocol ?? "TCP"}`);
      if (s.spec?.type === "NodePort") findings.push(`Service ${s.metadata?.name} is NodePort (${ports.join(", ")}): reachable on every node's IP, usually bypassing the ingress/WAF.`);
      if (s.spec?.type === "LoadBalancer" && !(s.metadata?.annotations && Object.keys(s.metadata.annotations).some((k) => /internal/i.test(k)))) findings.push(`Service ${s.metadata?.name} is a public LoadBalancer (${(s.status?.loadBalancer?.ingress ?? []).map((i) => i.ip ?? i.hostname).join(",") || "pending"}).`);
      if ((s.spec?.loadBalancerSourceRanges ?? []).length === 0 && s.spec?.type === "LoadBalancer") findings.push(`Service ${s.metadata?.name}: no loadBalancerSourceRanges - open to 0.0.0.0/0.`);
      return { service: s.metadata?.name, type: s.spec?.type, ports, external: (s.status?.loadBalancer?.ingress ?? []).map((i) => i.ip ?? i.hostname), externalIPs: s.spec?.externalIPs, sourceRanges: s.spec?.loadBalancerSourceRanges, backingWorkloads: [...new Set(backing)] };
    });
  const viaIngress = ingresses.flatMap((ing) =>
    (ing.spec?.rules ?? []).flatMap((r) =>
      (r.http?.paths ?? []).map((p) => {
        const svc = p.backend?.service?.name;
        const s = services.find((x) => x.metadata?.name === svc);
        const backing = s ? [...new Set(pods.filter((pp) => labelsMatch(pp.metadata?.labels, s.spec?.selector)).map((pp) => pp.metadata?.ownerReferences?.[0]?.name ?? pp.metadata?.name))] : [];
        const tls = (ing.spec?.tls ?? []).some((t) => (t.hosts ?? []).includes(r.host ?? "")) || (!r.host && (ing.spec?.tls ?? []).length > 0);
        if (/actuator|admin|metrics|debug|swagger|api-docs/i.test(p.path ?? "") || /actuator|admin|debug/i.test(svc ?? "")) findings.push(`Ingress ${ing.metadata?.name} exposes ${r.host ?? "*"}${p.path} -> ${svc}: management/admin surface reachable from outside.`);
        return { ingress: ing.metadata?.name, host: r.host ?? "*", path: p.path ?? "/", tls, service: svc, backingWorkloads: backing };
      }),
    ),
  );
  const hostNetworkPods = pods.filter((p) => p.spec?.hostNetwork).map((p) => p.metadata?.name);
  if (hostNetworkPods.length) findings.push(`pods on hostNetwork: ${hostNetworkPods.join(", ")}`);
  const pubWorkloads = new Set([...exposed.flatMap((e) => e.backingWorkloads), ...viaIngress.flatMap((v) => v.backingWorkloads)]);
  return { namespace: ns, exposedServices: exposed, ingressRoutes: viaIngress, workloadsReachableFromOutside: [...pubWorkloads], findings };
}

export async function getTlsStatus(ctx: ToolContext, args: { namespace?: string; host?: string; port?: number }) {
  const ns = nsOf(ctx, args.namespace);
  const ingresses = await ctx.k8s.listIngresses(ns);
  const coverage = ingresses.map((ing) => {
    const tlsHosts = new Set((ing.spec?.tls ?? []).flatMap((t) => t.hosts ?? []));
    return { ingress: ing.metadata?.name, hosts: (ing.spec?.rules ?? []).map((r) => ({ host: r.host ?? "*", tls: r.host ? tlsHosts.has(r.host) : tlsHosts.size > 0, secret: (ing.spec?.tls ?? []).find((t) => (t.hosts ?? []).includes(r.host ?? ""))?.secretName })) };
  });
  let handshake;
  if (args.host) {
    requireActive(ctx, "TLS handshake in get_tls_status");
    const host = assertHostname(args.host);
    const port = assertPort(args.port ?? 443);
    handshake = await new Promise<Record<string, unknown>>((resolve) => {
      const sock = tlsConnect({ host, port, servername: host, rejectUnauthorized: false, timeout: 5000 }, () => {
        const cert = sock.getPeerCertificate();
        const validTo = cert.valid_to ? new Date(cert.valid_to) : undefined;
        const days = validTo ? Math.round((validTo.getTime() - Date.now()) / 86400000) : undefined;
        resolve({ host, port, protocol: sock.getProtocol(), cipher: sock.getCipher()?.name, authorized: sock.authorized, authorizationError: sock.authorizationError ? String(sock.authorizationError) : undefined, subject: cert.subject?.CN, issuer: cert.issuer?.CN ?? cert.issuer?.O, validFrom: cert.valid_from, validTo: cert.valid_to, daysUntilExpiry: days, san: cert.subjectaltname, selfSigned: cert.issuer && cert.subject && JSON.stringify(cert.issuer) === JSON.stringify(cert.subject), findings: [...(days !== undefined && days < 14 ? [`certificate expires in ${days} days`] : []), ...(sock.authorized ? [] : [`chain not trusted: ${String(sock.authorizationError)}`]), ...(/TLSv1(\.0|\.1)?$/.test(sock.getProtocol() ?? "") ? ["legacy TLS version negotiated"] : [])] });
        sock.end();
      });
      sock.on("error", (e) => resolve({ host, port, error: e.message }));
      sock.on("timeout", () => {
        sock.destroy();
        resolve({ host, port, error: "timeout" });
      });
    });
  }
  return { namespace: ns, ingressTls: coverage, findings: coverage.flatMap((c) => c.hosts.filter((h) => !h.tls).map((h) => `${c.ingress}: ${h.host} has no TLS`)), handshake, note: "Certificate contents live in Secrets, which this server cannot read; pass host (and optionally port) with active checks enabled to inspect the served certificate instead." };
}

export async function getImageInventory(ctx: ToolContext, args: { namespace?: string }) {
  const ns = nsOf(ctx, args.namespace);
  const pods = await ctx.k8s.listPods(ns);
  const images = new Map<string, { workloads: Set<string>; pullPolicy: Set<string>; digests: Set<string> }>();
  for (const p of pods) {
    const owner = p.metadata?.ownerReferences?.[0]?.name ?? p.metadata?.name ?? "";
    for (const c of [...(p.spec?.initContainers ?? []), ...(p.spec?.containers ?? [])]) {
      const e = images.get(c.image ?? "") ?? { workloads: new Set(), pullPolicy: new Set(), digests: new Set() };
      e.workloads.add(owner);
      if (c.imagePullPolicy) e.pullPolicy.add(c.imagePullPolicy);
      const st = [...(p.status?.initContainerStatuses ?? []), ...(p.status?.containerStatuses ?? [])].find((s) => s.name === c.name);
      if (st?.imageID) e.digests.add(st.imageID.replace(/^.*@/, "").slice(0, 19));
      images.set(c.image ?? "", e);
    }
  }
  const rows = [...images.entries()].map(([image, e]) => {
    const m = /^(?:(?<registry>[^/]+\.[^/]+|localhost(?::\d+)?)\/)?(?<repo>[^:@]+)(?::(?<tag>[^@]+))?(?:@(?<digest>.+))?$/.exec(image);
    const findings: string[] = [];
    const tag = m?.groups?.tag;
    if (!tag && !m?.groups?.digest) findings.push("no tag (implicit :latest)");
    if (tag === "latest") findings.push(":latest tag");
    if (!m?.groups?.registry) findings.push("Docker Hub (no explicit registry) - rate limits and supply-chain exposure");
    if (e.digests.size > 1) findings.push(`${e.digests.size} different digests running for the same tag - tag was moved`);
    return { image, registry: m?.groups?.registry ?? "docker.io", repository: m?.groups?.repo, tag, pinnedByDigest: Boolean(m?.groups?.digest), runningDigests: [...e.digests], workloads: [...e.workloads], pullPolicy: [...e.pullPolicy], findings };
  });
  return { namespace: ns, images: rows, findings: rows.flatMap((r) => r.findings.map((f) => `${r.image}: ${f}`)), note: "For CVE scanning run trivy/grype against the digests listed here; this tool inventories only." };
}

export async function getEgressDestinations(ctx: ToolContext, args: { namespace?: string; pod?: string; service?: string }) {
  const ns = nsOf(ctx, args.namespace);
  let pod;
  if (args.pod) pod = await ctx.k8s.getPod(ns, args.pod);
  else if (args.service) {
    const w = await resolveWorkload(ctx.k8s, ns, args.service);
    pod = w.pods.find((p) => p.status?.phase === "Running") ?? w.pods[0];
    if (!pod) throw new Error(`${w.kind}/${w.name} has no pods.`);
  } else throw new Error("Provide `pod` or `service`.");
  const [conns, services, pods] = await Promise.all([ctx.probe.connections(pod), ctx.k8s.listServices(ns), ctx.k8s.listPods(ns)]);
  const svcByIp = new Map(services.map((s) => [s.spec?.clusterIP ?? "", s.metadata?.name ?? ""]));
  const podByIp = new Map(pods.map((p) => [p.status?.podIP ?? "", p.metadata?.name ?? ""]));
  const findings: string[] = [];
  const dests = conns.established.map((e) => {
    const svc = svcByIp.get(e.remote);
    const p = podByIp.get(e.remote);
    const cls = svc ? "cluster-service" : p ? "cluster-pod" : e.remote.startsWith("169.254.") ? "LINK-LOCAL (cloud metadata?)" : isPrivate(e.remote) ? "private-network" : "PUBLIC INTERNET";
    if (cls === "PUBLIC INTERNET") findings.push(`${e.count} connection(s) to public address ${e.remote}:${e.port} - verify this destination is expected (exfil / unexpected SaaS / crypto-miner check).`);
    if (cls.startsWith("LINK-LOCAL")) findings.push(`connection to ${e.remote}:${e.port} - cloud metadata endpoint; apps should not talk to it (credential theft vector).`);
    return { remote: e.remote, port: e.port, count: e.count, classification: cls, resolved: svc ? `service/${svc}` : p ? `pod/${p}` : undefined };
  });
  return { pod: pod.metadata?.name, namespace: ns, available: conns.available, note: conns.note, destinations: dests, findings, caveat: "Snapshot of currently-established sockets only; short-lived connections between snapshots are not seen. NetworkPolicy egress rules are the enforcement, this is the observation." };
}

export function severityOrder(s: Severity): number {
  return { critical: 0, high: 1, medium: 2, low: 3, info: 4 }[s];
}
export { ageSeconds, humanDuration };

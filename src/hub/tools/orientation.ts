import type { V1Pod } from "@kubernetes/client-node";
import type { ToolContext } from "../context.js";
import { nsOf } from "../context.js";
import { ageSeconds, humanDuration, labelsMatch, summarizePod, resolveWorkload } from "../model.js";

export async function listNamespaces(ctx: ToolContext) {
  const nss = await ctx.k8s.listNamespaces();
  return {
    context: ctx.k8s.contextName,
    namespaces: nss.map((n) => ({ name: n.metadata?.name, status: n.status?.phase, age: humanDuration(ageSeconds(n.metadata?.creationTimestamp)) })),
    defaultNamespace: ctx.config.defaultNamespace,
  };
}

export async function listWorkloads(ctx: ToolContext, args: { namespace?: string }) {
  const ns = nsOf(ctx, args.namespace);
  const [deps, sts, ds, jobs, cron, pods] = await Promise.all([
    ctx.k8s.listDeployments(ns),
    ctx.k8s.listStatefulSets(ns),
    ctx.k8s.listDaemonSets(ns),
    ctx.k8s.listJobs(ns),
    ctx.k8s.listCronJobs(ns),
    ctx.k8s.listPods(ns),
  ]);
  const restartsFor = (selector?: Record<string, string>) =>
    pods.filter((p) => labelsMatch(p.metadata?.labels, selector)).reduce((a, p) => a + (p.status?.containerStatuses ?? []).reduce((b, c) => b + (c.restartCount ?? 0), 0), 0);
  const images = (containers?: Array<{ image?: string }>) => (containers ?? []).map((c) => c.image).filter(Boolean);
  return {
    namespace: ns,
    deployments: deps.map((d) => ({
      name: d.metadata?.name,
      ready: `${d.status?.readyReplicas ?? 0}/${d.spec?.replicas ?? 0}`,
      updated: d.status?.updatedReplicas ?? 0,
      available: d.status?.availableReplicas ?? 0,
      restarts: restartsFor(d.spec?.selector?.matchLabels),
      images: images(d.spec?.template?.spec?.containers),
      age: humanDuration(ageSeconds(d.metadata?.creationTimestamp)),
      hasProbe: (d.spec?.template?.spec?.initContainers ?? []).some((c) => c.name === ctx.config.probeContainerName),
      conditions: (d.status?.conditions ?? []).filter((c) => c.status !== "True" || c.type === "Progressing").map((c) => `${c.type}=${c.status}${c.reason ? ` (${c.reason})` : ""}`),
    })),
    statefulSets: sts.map((s) => ({
      name: s.metadata?.name,
      ready: `${s.status?.readyReplicas ?? 0}/${s.spec?.replicas ?? 0}`,
      restarts: restartsFor(s.spec?.selector?.matchLabels),
      images: images(s.spec?.template?.spec?.containers),
      age: humanDuration(ageSeconds(s.metadata?.creationTimestamp)),
    })),
    daemonSets: ds.map((d) => ({
      name: d.metadata?.name,
      ready: `${d.status?.numberReady ?? 0}/${d.status?.desiredNumberScheduled ?? 0}`,
      images: images(d.spec?.template?.spec?.containers),
      age: humanDuration(ageSeconds(d.metadata?.creationTimestamp)),
    })),
    jobs: jobs
      .filter((j) => !j.status?.succeeded || ageSeconds(j.status?.completionTime) === undefined || (ageSeconds(j.status?.completionTime) ?? 0) < 86400)
      .map((j) => ({ name: j.metadata?.name, active: j.status?.active ?? 0, succeeded: j.status?.succeeded ?? 0, failed: j.status?.failed ?? 0, age: humanDuration(ageSeconds(j.metadata?.creationTimestamp)) })),
    cronJobs: cron.map((c) => ({ name: c.metadata?.name, schedule: c.spec?.schedule, suspend: c.spec?.suspend ?? false, lastSchedule: c.status?.lastScheduleTime, active: (c.status?.active ?? []).length })),
    unownedPods: pods.filter((p) => !p.metadata?.ownerReferences?.length).map((p) => summarizePod(p, ctx.config.probeContainerName)),
  };
}

const HOST_ENV = /(host|url|uri|endpoint|addr|address|server|broker|bootstrap|dsn)/i;

/**
 * Builds Service -> pods -> workload graph plus *inferred* dependencies from
 * env vars / ConfigMap values that mention another Service's name, and from
 * probe-observed connections when probes exist.
 */
export async function getTopology(ctx: ToolContext, args: { namespace?: string; include_connections?: boolean }) {
  const ns = nsOf(ctx, args.namespace);
  const [services, pods, deps, sts, slices, cms] = await Promise.all([
    ctx.k8s.listServices(ns),
    ctx.k8s.listPods(ns),
    ctx.k8s.listDeployments(ns),
    ctx.k8s.listStatefulSets(ns),
    ctx.k8s.listEndpointSlices(ns),
    ctx.k8s.listConfigMaps(ns),
  ]);
  const serviceNames = services.map((s) => s.metadata?.name ?? "").filter(Boolean);
  const serviceIps = new Map(services.map((s) => [s.spec?.clusterIP ?? "", s.metadata?.name ?? ""]));
  const podIpToWorkload = new Map<string, string>();
  const workloadOfPod = (p: V1Pod) => {
    const owner = p.metadata?.ownerReferences?.[0];
    if (owner?.kind === "ReplicaSet") return owner.name.replace(/-[a-z0-9]{5,10}$/, "");
    return owner?.name ?? p.metadata?.name ?? "?";
  };
  for (const p of pods) if (p.status?.podIP) podIpToWorkload.set(p.status.podIP, workloadOfPod(p));

  const cmText = new Map<string, string>();
  for (const cm of cms) cmText.set(cm.metadata?.name ?? "", Object.values(cm.data ?? {}).join("\n"));

  const workloads = [
    ...deps.map((d) => ({ kind: "Deployment", name: d.metadata?.name ?? "", selector: d.spec?.selector?.matchLabels, spec: d.spec?.template?.spec })),
    ...sts.map((s) => ({ kind: "StatefulSet", name: s.metadata?.name ?? "", selector: s.spec?.selector?.matchLabels, spec: s.spec?.template?.spec })),
  ];

  const edges: Array<{ from: string; to: string; via: string }> = [];
  const mentions = (text: string | undefined, from: string) => {
    if (!text) return;
    for (const svc of serviceNames) {
      if (svc === from) continue;
      const re = new RegExp(`(^|[^a-z0-9-])${svc.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}([^a-z0-9-]|$)`, "i");
      if (re.test(text)) edges.push({ from, to: svc, via: "config" });
    }
  };
  for (const w of workloads) {
    for (const c of w.spec?.containers ?? []) {
      for (const e of c.env ?? []) {
        if (e.value && HOST_ENV.test(e.name)) mentions(e.value, w.name);
        if (e.valueFrom?.configMapKeyRef) mentions(cmText.get(e.valueFrom.configMapKeyRef.name ?? ""), w.name);
      }
      for (const ef of c.envFrom ?? []) if (ef.configMapRef?.name) mentions(cmText.get(ef.configMapRef.name), w.name);
    }
    for (const v of w.spec?.volumes ?? []) if (v.configMap?.name) mentions(cmText.get(v.configMap.name), w.name);
  }

  if (args.include_connections) {
    for (const p of pods) {
      try {
        const conns = await ctx.probe.connections(p);
        for (const e of conns.established) {
          const to = serviceIps.get(e.remote) ?? podIpToWorkload.get(e.remote);
          if (to && to !== workloadOfPod(p)) edges.push({ from: workloadOfPod(p), to, via: `observed:${e.port}` });
        }
      } catch {
        /* no probe */
      }
    }
  }

  const dedup = new Map<string, { from: string; to: string; via: string[] }>();
  for (const e of edges) {
    const k = `${e.from}->${e.to}`;
    const d = dedup.get(k) ?? { from: e.from, to: e.to, via: [] };
    if (!d.via.includes(e.via)) d.via.push(e.via);
    dedup.set(k, d);
  }

  return {
    namespace: ns,
    services: services.map((s) => {
      const backing = pods.filter((p) => labelsMatch(p.metadata?.labels, s.spec?.selector));
      const ready = slices.filter((sl) => sl.metadata?.labels?.["kubernetes.io/service-name"] === s.metadata?.name).flatMap((sl) => sl.endpoints ?? []).filter((e) => e.conditions?.ready).length;
      return {
        name: s.metadata?.name,
        type: s.spec?.type,
        clusterIP: s.spec?.clusterIP,
        ports: (s.spec?.ports ?? []).map((p) => `${p.port}${p.targetPort !== undefined && String(p.targetPort) !== String(p.port) ? `->${p.targetPort}` : ""}/${p.protocol ?? "TCP"}`),
        selector: s.spec?.selector,
        backingPods: backing.length,
        readyEndpoints: ready,
        workloads: [...new Set(backing.map(workloadOfPod))],
        warning: s.spec?.selector && !backing.length ? "selector matches no pods" : s.spec?.selector && !ready ? "no ready endpoints" : undefined,
      };
    }),
    workloads: workloads.map((w) => ({ kind: w.kind, name: w.name, pods: pods.filter((p) => labelsMatch(p.metadata?.labels, w.selector)).length })),
    dependencies: [...dedup.values()],
    note: "dependencies are inferred from env/ConfigMap references to Service names" + (args.include_connections ? " and from probe-observed connections" : "; pass include_connections=true to add probe-observed connections"),
  };
}

export async function getServiceOverview(ctx: ToolContext, args: { namespace?: string; service: string }) {
  const ns = nsOf(ctx, args.namespace);
  const w = await resolveWorkload(ctx.k8s, ns, args.service);
  const pods = w.pods.map((p) => summarizePod(p, ctx.config.probeContainerName));
  const events = (await ctx.k8s.listEvents(ns)).filter((e) => e.type === "Warning" && (w.pods.some((p) => p.metadata?.name === e.involvedObject?.name) || e.involvedObject?.name === w.name)).sort((a, b) => Date.parse(String(b.lastTimestamp ?? b.eventTime ?? 0)) - Date.parse(String(a.lastTimestamp ?? a.eventTime ?? 0))).slice(0, 10);
  const usage = await ctx.providers.first("resourceUsage", (p) => p.resourceUsage!({ namespace: ns, service: w.name, pods: w.pods.map((p) => p.metadata?.name ?? ""), windowSeconds: 300 }));
  const golden = await ctx.providers.first("goldenSignals", (p) => p.goldenSignals!({ namespace: ns, service: w.name, pods: w.pods.map((p) => p.metadata?.name ?? ""), windowSeconds: 900 }));
  const limits = w.containers.map((c) => ({ container: c.name, requests: c.resources?.requests, limits: c.resources?.limits, image: c.image }));
  const dep = w.deployment;
  return {
    kind: w.kind,
    name: w.name,
    namespace: ns,
    replicas: w.desiredReplicas !== undefined ? { desired: w.desiredReplicas, ready: w.readyReplicas, updated: w.updatedReplicas, available: w.availableReplicas } : undefined,
    lastRollout: dep?.status?.conditions?.find((c) => c.type === "Progressing")?.lastUpdateTime,
    generation: dep ? { observed: dep.status?.observedGeneration, current: dep.metadata?.generation, revision: dep.metadata?.annotations?.["deployment.kubernetes.io/revision"] } : undefined,
    pods,
    problems: pods.flatMap((p) => p.problems.map((x) => `${p.name}: ${x}`)),
    resources: limits,
    usage: usage.result ?? { note: usage.errors.length ? usage.errors.join("; ") : "no resource usage source (install metrics-server or configure Prometheus)" },
    goldenSignals: golden.result ?? { note: golden.errors.length ? golden.errors.join("; ") : "no golden-signals source (add the probe to Spring Boot pods or configure Prometheus)" },
    recentWarnings: events.map((e) => ({ reason: e.reason, message: e.message?.slice(0, 300), count: e.count, last: e.lastTimestamp ?? e.eventTime, object: `${e.involvedObject?.kind}/${e.involvedObject?.name}` })),
    probes: pods.filter((p) => p.hasProbe).length,
  };
}

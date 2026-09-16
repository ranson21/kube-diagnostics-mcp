import type { CoreV1Event } from "@kubernetes/client-node";
import type { ToolContext } from "../context.js";
import { nsOf } from "../context.js";
import { ageSeconds, humanDuration, resolveWorkload, summarizePod } from "../model.js";
import { parseWindowSeconds } from "../../security/guard.js";

function eventTime(e: CoreV1Event): number {
  return Date.parse(String(e.lastTimestamp ?? e.eventTime ?? e.firstTimestamp ?? 0)) || 0;
}

export async function getPodStatus(ctx: ToolContext, args: { namespace?: string; service?: string; pod?: string }) {
  const ns = nsOf(ctx, args.namespace);
  if (args.pod) {
    const pod = await ctx.k8s.getPod(ns, args.pod);
    return { namespace: ns, pods: [summarizePod(pod, ctx.config.probeContainerName)] };
  }
  if (args.service) {
    const w = await resolveWorkload(ctx.k8s, ns, args.service);
    const pods = w.pods.map((p) => summarizePod(p, ctx.config.probeContainerName));
    return {
      namespace: ns,
      workload: { kind: w.kind, name: w.name, desired: w.desiredReplicas, ready: w.readyReplicas },
      pods,
      problems: pods.flatMap((p) => p.problems.map((x) => `${p.name}: ${x}`)),
    };
  }
  const pods = (await ctx.k8s.listPods(ns)).map((p) => summarizePod(p, ctx.config.probeContainerName));
  const unhealthy = pods.filter((p) => p.problems.length);
  return {
    namespace: ns,
    total: pods.length,
    healthy: pods.length - unhealthy.length,
    unhealthy,
    restartsTop: [...pods].sort((a, b) => b.restarts - a.restarts).slice(0, 5).map((p) => ({ pod: p.name, restarts: p.restarts })),
  };
}

export async function getEvents(ctx: ToolContext, args: { namespace?: string; since?: string; object?: string; warnings_only?: boolean; limit?: number }) {
  const ns = nsOf(ctx, args.namespace);
  const since = parseWindowSeconds(args.since, 3600);
  const cutoff = Date.now() - since * 1000;
  let events = (await ctx.k8s.listEvents(ns)).filter((e) => eventTime(e) >= cutoff);
  if (args.warnings_only !== false) events = events.filter((e) => e.type === "Warning");
  if (args.object) events = events.filter((e) => (e.involvedObject?.name ?? "").startsWith(args.object!));

  // Dedupe by (object, reason, message prefix); sum counts.
  const grouped = new Map<string, { object: string; reason?: string; message?: string; count: number; first: number; last: number; type?: string }>();
  for (const e of events) {
    const object = `${e.involvedObject?.kind}/${e.involvedObject?.name}`;
    const key = `${object}|${e.reason}|${(e.message ?? "").slice(0, 80)}`;
    const g = grouped.get(key) ?? { object, reason: e.reason, message: e.message?.slice(0, 400), count: 0, first: Number.MAX_SAFE_INTEGER, last: 0, type: e.type };
    g.count += e.count ?? 1;
    g.first = Math.min(g.first, Date.parse(String(e.firstTimestamp ?? e.eventTime ?? 0)) || eventTime(e));
    g.last = Math.max(g.last, eventTime(e));
    grouped.set(key, g);
  }
  const out = [...grouped.values()].sort((a, b) => b.last - a.last).slice(0, args.limit ?? 50);
  return {
    namespace: ns,
    since: `${since}s`,
    events: out.map((g) => ({ ...g, first: new Date(g.first).toISOString(), last: new Date(g.last).toISOString() })),
    byReason: Object.fromEntries([...out.reduce((m, g) => m.set(g.reason ?? "?", (m.get(g.reason ?? "?") ?? 0) + g.count), new Map<string, number>())].sort((a, b) => b[1] - a[1])),
  };
}

export async function getRolloutHistory(ctx: ToolContext, args: { namespace?: string; deployment: string; limit?: number }) {
  const ns = nsOf(ctx, args.namespace);
  const deps = await ctx.k8s.listDeployments(ns);
  const dep = deps.find((d) => d.metadata?.name === args.deployment);
  if (!dep) throw new Error(`Deployment "${args.deployment}" not found in ${ns}. Known: ${deps.map((d) => d.metadata?.name).join(", ") || "(none)"}`);
  const rss = (await ctx.k8s.listReplicaSets(ns)).filter((rs) => rs.metadata?.ownerReferences?.some((o) => o.uid === dep.metadata?.uid));
  const revisions = rss
    .map((rs) => ({
      revision: Number(rs.metadata?.annotations?.["deployment.kubernetes.io/revision"] ?? 0),
      replicaSet: rs.metadata?.name,
      created: rs.metadata?.creationTimestamp,
      age: humanDuration(ageSeconds(rs.metadata?.creationTimestamp)),
      replicas: `${rs.status?.readyReplicas ?? 0}/${rs.spec?.replicas ?? 0}`,
      images: (rs.spec?.template?.spec?.containers ?? []).map((c) => `${c.name}=${c.image}`),
      changeCause: rs.metadata?.annotations?.["kubernetes.io/change-cause"],
      env: (rs.spec?.template?.spec?.containers ?? []).flatMap((c) => (c.env ?? []).map((e) => `${e.name}=${e.valueFrom ? `<${e.valueFrom.secretKeyRef ? "secret" : e.valueFrom.configMapKeyRef ? "configmap" : "ref"}>` : e.value}`)),
      resources: (rs.spec?.template?.spec?.containers ?? []).map((c) => ({ container: c.name, requests: c.resources?.requests, limits: c.resources?.limits })),
      active: (rs.spec?.replicas ?? 0) > 0,
    }))
    .sort((a, b) => b.revision - a.revision)
    .slice(0, args.limit ?? 10);

  const diffs: Array<{ from: number; to: number; changes: string[] }> = [];
  for (let i = 0; i < revisions.length - 1; i++) {
    const newer = revisions[i];
    const older = revisions[i + 1];
    const changes: string[] = [];
    for (const img of newer.images) if (!older.images.includes(img)) changes.push(`image: ${img}`);
    for (const e of newer.env) if (!older.env.includes(e)) changes.push(`env added/changed: ${e.split("=")[0]}`);
    for (const e of older.env) if (!newer.env.some((n) => n.split("=")[0] === e.split("=")[0])) changes.push(`env removed: ${e.split("=")[0]}`);
    if (JSON.stringify(newer.resources) !== JSON.stringify(older.resources)) changes.push("resources changed");
    diffs.push({ from: older.revision, to: newer.revision, changes });
  }
  return {
    deployment: args.deployment,
    namespace: ns,
    currentRevision: dep.metadata?.annotations?.["deployment.kubernetes.io/revision"],
    strategy: dep.spec?.strategy?.type,
    conditions: (dep.status?.conditions ?? []).map((c) => ({ type: c.type, status: c.status, reason: c.reason, lastUpdate: c.lastUpdateTime, message: c.message?.slice(0, 200) })),
    revisions: revisions.map(({ env, ...r }) => ({ ...r, envKeys: env.map((e) => e.split("=")[0]) })),
    diffs,
  };
}

/** One timeline of things that changed: rollouts, scaling, HPA, config metadata, node events. */
export async function whatChanged(ctx: ToolContext, args: { namespace?: string; service?: string; since?: string }) {
  const ns = nsOf(ctx, args.namespace);
  const since = parseWindowSeconds(args.since, 6 * 3600);
  const cutoff = Date.now() - since * 1000;
  const timeline: Array<{ time: string; kind: string; object: string; detail: string }> = [];
  const push = (t: string | Date | undefined, kind: string, object: string, detail: string) => {
    const ms = t ? (t instanceof Date ? t.getTime() : Date.parse(String(t))) : NaN;
    if (Number.isFinite(ms) && ms >= cutoff) timeline.push({ time: new Date(ms).toISOString(), kind, object, detail });
  };

  const [deps, rss, hpas, cms, events, pods] = await Promise.all([
    ctx.k8s.listDeployments(ns),
    ctx.k8s.listReplicaSets(ns),
    ctx.k8s.listHpas(ns),
    ctx.k8s.listConfigMaps(ns),
    ctx.k8s.listEvents(ns),
    ctx.k8s.listPods(ns),
  ]);
  const filter = (name: string | undefined) => !args.service || (name ?? "").startsWith(args.service);

  for (const rs of rss) {
    const owner = rs.metadata?.ownerReferences?.[0]?.name;
    if (!filter(owner)) continue;
    push(rs.metadata?.creationTimestamp, "rollout", `Deployment/${owner}`, `new ReplicaSet ${rs.metadata?.name} (rev ${rs.metadata?.annotations?.["deployment.kubernetes.io/revision"]}) images=${(rs.spec?.template?.spec?.containers ?? []).map((c) => c.image).join(",")}`);
  }
  for (const d of deps) {
    if (!filter(d.metadata?.name)) continue;
    for (const c of d.status?.conditions ?? []) {
      if (c.type === "Progressing" && c.reason === "NewReplicaSetAvailable") push(c.lastUpdateTime, "rollout-complete", `Deployment/${d.metadata?.name}`, c.message ?? "");
      if (c.type === "Available" && c.status === "False") push(c.lastTransitionTime, "unavailable", `Deployment/${d.metadata?.name}`, c.message ?? "");
    }
  }
  for (const h of hpas) {
    if (!filter(h.spec?.scaleTargetRef?.name)) continue;
    push(h.status?.lastScaleTime, "hpa-scale", `HPA/${h.metadata?.name}`, `scaled ${h.spec?.scaleTargetRef?.kind}/${h.spec?.scaleTargetRef?.name} to ${h.status?.desiredReplicas} (current ${h.status?.currentReplicas})`);
  }
  for (const cm of cms) {
    // ConfigMaps have no update timestamp; managedFields carries the last operation time.
    const last = (cm.metadata?.managedFields ?? []).map((f) => f.time).filter(Boolean).sort().pop();
    push(last, "configmap-updated", `ConfigMap/${cm.metadata?.name}`, `keys=${Object.keys(cm.data ?? {}).join(",")}`);
  }
  for (const e of events) {
    const name = e.involvedObject?.name;
    if (!filter(name)) continue;
    if (["ScalingReplicaSet", "SuccessfulCreate", "SuccessfulDelete", "Killing", "BackOff", "Unhealthy", "OOMKilling", "NodeNotReady", "Evicted", "FailedScheduling", "Preempted", "Rebooted"].includes(e.reason ?? "")) {
      push(e.lastTimestamp ?? e.eventTime, `event:${e.reason}`, `${e.involvedObject?.kind}/${name}`, `${e.message?.slice(0, 200)}${(e.count ?? 1) > 1 ? ` (x${e.count})` : ""}`);
    }
  }
  for (const p of pods) {
    if (!filter(p.metadata?.name)) continue;
    for (const c of p.status?.containerStatuses ?? []) {
      if (c.lastState?.terminated) push(c.lastState.terminated.finishedAt, "container-restart", `Pod/${p.metadata?.name}`, `${c.name} restarted: ${c.lastState.terminated.reason} (exit ${c.lastState.terminated.exitCode})`);
    }
    push(p.metadata?.creationTimestamp, "pod-created", `Pod/${p.metadata?.name}`, `on ${p.spec?.nodeName ?? "?"}`);
  }
  timeline.sort((a, b) => b.time.localeCompare(a.time));
  return { namespace: ns, since: `${since}s`, service: args.service, changes: timeline.slice(0, 100), total: timeline.length };
}

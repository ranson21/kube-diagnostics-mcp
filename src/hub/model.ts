/**
 * Shared shaping helpers: Kubernetes quantities, workload resolution
 * ("service" as the user says it -> the pods behind it), and compact pod
 * summaries. Every tool builds on these so results look the same everywhere.
 */
import type { V1Container, V1Pod, V1Deployment, V1StatefulSet, V1DaemonSet, V1Service, V1ObjectMeta } from "@kubernetes/client-node";
import type { ReadOnlyKubeClient } from "../k8s/client.js";
import { assertName } from "../security/guard.js";

// ---- quantities --------------------------------------------------------

const BINARY: Record<string, number> = { Ki: 2 ** 10, Mi: 2 ** 20, Gi: 2 ** 30, Ti: 2 ** 40, Pi: 2 ** 50, Ei: 2 ** 60 };
const DECIMAL: Record<string, number> = { n: 1e-9, u: 1e-6, m: 1e-3, "": 1, k: 1e3, M: 1e6, G: 1e9, T: 1e12, P: 1e15, E: 1e18 };

/** Parses a Kubernetes quantity ("100m", "512Mi", "1.5", "2G") into a base-unit number. */
export function parseQuantity(q: string | undefined): number | undefined {
  if (q === undefined || q === null || q === "") return undefined;
  const m = /^([+-]?[0-9.]+)([A-Za-z]*)$/.exec(String(q).trim());
  if (!m) return undefined;
  const n = Number(m[1]);
  const unit = m[2];
  if (!Number.isFinite(n)) return undefined;
  if (unit in BINARY) return n * BINARY[unit];
  if (unit in DECIMAL) return n * DECIMAL[unit];
  return undefined;
}

export function cpuMillicores(q: string | undefined): number | undefined {
  const v = parseQuantity(q);
  return v === undefined ? undefined : Math.round(v * 1000);
}

export function memoryBytes(q: string | undefined): number | undefined {
  const v = parseQuantity(q);
  return v === undefined ? undefined : Math.round(v);
}

export function humanBytes(bytes: number | undefined): string | undefined {
  if (bytes === undefined) return undefined;
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)}${units[i]}`;
}

export function ageSeconds(ts: Date | string | undefined, now = Date.now()): number | undefined {
  if (!ts) return undefined;
  const t = ts instanceof Date ? ts.getTime() : Date.parse(ts);
  return Number.isFinite(t) ? Math.max(0, Math.round((now - t) / 1000)) : undefined;
}

export function humanDuration(seconds: number | undefined): string | undefined {
  if (seconds === undefined) return undefined;
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h${Math.floor((seconds % 3600) / 60)}m`;
  return `${Math.floor(seconds / 86400)}d${Math.floor((seconds % 86400) / 3600)}h`;
}

export function percentile(sorted: number[], p: number): number {
  if (!sorted.length) return 0;
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[idx];
}

// ---- selectors ----------------------------------------------------------

export function selectorToString(matchLabels: Record<string, string> | undefined): string | undefined {
  if (!matchLabels || !Object.keys(matchLabels).length) return undefined;
  return Object.entries(matchLabels)
    .map(([k, v]) => `${k}=${v}`)
    .join(",");
}

export function labelsMatch(labels: Record<string, string> | undefined, selector: Record<string, string> | undefined): boolean {
  if (!selector || !Object.keys(selector).length) return false;
  if (!labels) return false;
  return Object.entries(selector).every(([k, v]) => labels[k] === v);
}

// ---- workload resolution -----------------------------------------------

export type WorkloadKind = "Deployment" | "StatefulSet" | "DaemonSet" | "Service" | "Pod";

export interface ResolvedWorkload {
  kind: WorkloadKind;
  name: string;
  namespace: string;
  selector?: Record<string, string>;
  pods: V1Pod[];
  desiredReplicas?: number;
  readyReplicas?: number;
  updatedReplicas?: number;
  availableReplicas?: number;
  deployment?: V1Deployment;
  statefulSet?: V1StatefulSet;
  daemonSet?: V1DaemonSet;
  service?: V1Service;
  /** The pod template's containers (from the controller), for config/limits. */
  containers: V1Container[];
  initContainers: V1Container[];
  templateMeta?: V1ObjectMeta;
  serviceAccountName?: string;
}

/**
 * Resolves "what the user calls a service" to a workload and its pods. Order:
 * Deployment, StatefulSet, DaemonSet, Service (by selector), then a single
 * Pod by exact name. Throws with the available names if nothing matches.
 */
export async function resolveWorkload(k8s: ReadOnlyKubeClient, namespace: string, name: string): Promise<ResolvedWorkload> {
  assertName(name, "service/workload name");
  const allPods = await k8s.listPods(namespace);

  const deployments = await k8s.listDeployments(namespace);
  const dep = deployments.find((d) => d.metadata?.name === name);
  if (dep) {
    const selector = dep.spec?.selector?.matchLabels;
    return {
      kind: "Deployment",
      name,
      namespace,
      selector,
      pods: allPods.filter((p) => labelsMatch(p.metadata?.labels, selector)),
      desiredReplicas: dep.spec?.replicas ?? 1,
      readyReplicas: dep.status?.readyReplicas ?? 0,
      updatedReplicas: dep.status?.updatedReplicas ?? 0,
      availableReplicas: dep.status?.availableReplicas ?? 0,
      deployment: dep,
      containers: dep.spec?.template?.spec?.containers ?? [],
      initContainers: dep.spec?.template?.spec?.initContainers ?? [],
      templateMeta: dep.spec?.template?.metadata,
      serviceAccountName: dep.spec?.template?.spec?.serviceAccountName,
    };
  }

  const statefulSets = await k8s.listStatefulSets(namespace);
  const sts = statefulSets.find((s) => s.metadata?.name === name);
  if (sts) {
    const selector = sts.spec?.selector?.matchLabels;
    return {
      kind: "StatefulSet",
      name,
      namespace,
      selector,
      pods: allPods.filter((p) => labelsMatch(p.metadata?.labels, selector)),
      desiredReplicas: sts.spec?.replicas ?? 1,
      readyReplicas: sts.status?.readyReplicas ?? 0,
      updatedReplicas: sts.status?.updatedReplicas ?? 0,
      availableReplicas: sts.status?.availableReplicas ?? 0,
      statefulSet: sts,
      containers: sts.spec?.template?.spec?.containers ?? [],
      initContainers: sts.spec?.template?.spec?.initContainers ?? [],
      templateMeta: sts.spec?.template?.metadata,
      serviceAccountName: sts.spec?.template?.spec?.serviceAccountName,
    };
  }

  const daemonSets = await k8s.listDaemonSets(namespace);
  const ds = daemonSets.find((d) => d.metadata?.name === name);
  if (ds) {
    const selector = ds.spec?.selector?.matchLabels;
    return {
      kind: "DaemonSet",
      name,
      namespace,
      selector,
      pods: allPods.filter((p) => labelsMatch(p.metadata?.labels, selector)),
      desiredReplicas: ds.status?.desiredNumberScheduled,
      readyReplicas: ds.status?.numberReady ?? 0,
      updatedReplicas: ds.status?.updatedNumberScheduled ?? 0,
      availableReplicas: ds.status?.numberAvailable ?? 0,
      daemonSet: ds,
      containers: ds.spec?.template?.spec?.containers ?? [],
      initContainers: ds.spec?.template?.spec?.initContainers ?? [],
      templateMeta: ds.spec?.template?.metadata,
      serviceAccountName: ds.spec?.template?.spec?.serviceAccountName,
    };
  }

  const services = await k8s.listServices(namespace);
  const svc = services.find((s) => s.metadata?.name === name);
  if (svc) {
    const selector = svc.spec?.selector;
    const pods = allPods.filter((p) => labelsMatch(p.metadata?.labels, selector));
    const first = pods[0];
    return {
      kind: "Service",
      name,
      namespace,
      selector,
      pods,
      service: svc,
      containers: first?.spec?.containers ?? [],
      initContainers: first?.spec?.initContainers ?? [],
      serviceAccountName: first?.spec?.serviceAccountName,
    };
  }

  const pod = allPods.find((p) => p.metadata?.name === name);
  if (pod) {
    return {
      kind: "Pod",
      name,
      namespace,
      pods: [pod],
      containers: pod.spec?.containers ?? [],
      initContainers: pod.spec?.initContainers ?? [],
      serviceAccountName: pod.spec?.serviceAccountName,
    };
  }

  const known = [
    ...deployments.map((d) => `Deployment/${d.metadata?.name}`),
    ...statefulSets.map((s) => `StatefulSet/${s.metadata?.name}`),
    ...daemonSets.map((d) => `DaemonSet/${d.metadata?.name}`),
    ...services.map((s) => `Service/${s.metadata?.name}`),
  ];
  throw new Error(`No Deployment, StatefulSet, DaemonSet, Service, or Pod named "${name}" in namespace "${namespace}". Known: ${known.join(", ") || "(none)"}`);
}

// ---- pod summaries -------------------------------------------------------

export interface ContainerStateSummary {
  name: string;
  ready: boolean;
  restarts: number;
  state: string;
  reason?: string;
  message?: string;
  exitCode?: number;
  startedAt?: string;
  lastTermination?: { reason?: string; exitCode?: number; finishedAt?: string; message?: string };
  image?: string;
}

export interface PodSummary {
  name: string;
  namespace: string;
  phase?: string;
  ready: string; // "1/2"
  restarts: number;
  age?: string;
  node?: string;
  podIP?: string;
  containers: ContainerStateSummary[];
  conditions?: Array<{ type: string; status: string; reason?: string; message?: string }>;
  problems: string[];
  ownerKind?: string;
  ownerName?: string;
  hasProbe?: boolean;
}

export function summarizePod(pod: V1Pod, probeContainerName = "diag-probe"): PodSummary {
  const statuses = [...(pod.status?.initContainerStatuses ?? []), ...(pod.status?.containerStatuses ?? [])];
  const specContainers = [...(pod.spec?.initContainers ?? []), ...(pod.spec?.containers ?? [])];
  const isSidecarInit = (name: string) => (pod.spec?.initContainers ?? []).some((c) => c.name === name && c.restartPolicy === "Always");
  const isRegular = (name: string) => (pod.spec?.containers ?? []).some((c) => c.name === name);

  const containers: ContainerStateSummary[] = statuses
    .filter((s) => isRegular(s.name) || isSidecarInit(s.name))
    .map((s) => {
      const st = s.state ?? {};
      let state = "unknown";
      let reason: string | undefined;
      let message: string | undefined;
      let exitCode: number | undefined;
      let startedAt: string | undefined;
      if (st.running) {
        state = "running";
        startedAt = st.running.startedAt ? new Date(st.running.startedAt).toISOString() : undefined;
      } else if (st.waiting) {
        state = "waiting";
        reason = st.waiting.reason;
        message = st.waiting.message;
      } else if (st.terminated) {
        state = "terminated";
        reason = st.terminated.reason;
        message = st.terminated.message;
        exitCode = st.terminated.exitCode;
      }
      const lt = s.lastState?.terminated;
      return {
        name: s.name,
        ready: Boolean(s.ready),
        restarts: s.restartCount ?? 0,
        state,
        reason,
        message: message?.slice(0, 300),
        exitCode,
        startedAt,
        lastTermination: lt
          ? { reason: lt.reason, exitCode: lt.exitCode, finishedAt: lt.finishedAt ? new Date(lt.finishedAt).toISOString() : undefined, message: lt.message?.slice(0, 300) }
          : undefined,
        image: specContainers.find((c) => c.name === s.name)?.image,
      };
    });

  const readyCount = containers.filter((c) => c.ready).length;
  const restarts = containers.reduce((a, c) => a + c.restarts, 0);
  const problems: string[] = [];
  for (const c of containers) {
    if (c.state === "waiting" && c.reason) problems.push(`${c.name}: ${c.reason}${c.message ? ` - ${c.message}` : ""}`);
    if (c.state === "terminated" && c.reason && c.reason !== "Completed") problems.push(`${c.name}: terminated (${c.reason}, exit ${c.exitCode})`);
    if (c.lastTermination?.reason === "OOMKilled") problems.push(`${c.name}: previous container was OOMKilled`);
    if (c.lastTermination?.reason === "Error" && c.restarts > 0) problems.push(`${c.name}: previous container exited with code ${c.lastTermination.exitCode}`);
    if (c.restarts >= 5) problems.push(`${c.name}: ${c.restarts} restarts`);
  }
  for (const cond of pod.status?.conditions ?? []) {
    if (cond.status !== "True" && (cond.type === "PodScheduled" || cond.type === "Ready" || cond.type === "ContainersReady")) {
      if (cond.reason && cond.reason !== "ContainersNotReady") problems.push(`${cond.type}=False (${cond.reason}${cond.message ? `: ${cond.message.slice(0, 200)}` : ""})`);
      else if (cond.type === "PodScheduled") problems.push(`Unschedulable${cond.message ? `: ${cond.message.slice(0, 200)}` : ""}`);
    }
  }
  if (pod.status?.phase === "Pending" && !problems.length) problems.push("Pending");
  if (pod.status?.phase === "Failed") problems.push(`Failed${pod.status.reason ? ` (${pod.status.reason})` : ""}`);
  if (pod.metadata?.deletionTimestamp) problems.push("Terminating");

  const owner = pod.metadata?.ownerReferences?.[0];
  return {
    name: pod.metadata?.name ?? "",
    namespace: pod.metadata?.namespace ?? "",
    phase: pod.status?.phase,
    ready: `${readyCount}/${containers.length}`,
    restarts,
    age: humanDuration(ageSeconds(pod.metadata?.creationTimestamp)),
    node: pod.spec?.nodeName,
    podIP: pod.status?.podIP,
    containers,
    conditions: (pod.status?.conditions ?? [])
      .filter((c) => c.status !== "True")
      .map((c) => ({ type: c.type, status: c.status, reason: c.reason, message: c.message?.slice(0, 200) })),
    problems,
    ownerKind: owner?.kind,
    ownerName: owner?.name,
    hasProbe: hasProbeContainer(pod, probeContainerName),
  };
}

export function hasProbeContainer(pod: V1Pod, probeContainerName: string): boolean {
  return (
    (pod.spec?.initContainers ?? []).some((c) => c.name === probeContainerName) ||
    (pod.spec?.containers ?? []).some((c) => c.name === probeContainerName)
  );
}

/** "main" application container: first non-probe regular container. */
export function appContainerName(pod: V1Pod, probeContainerName: string): string | undefined {
  return (pod.spec?.containers ?? []).map((c) => c.name).find((n) => n !== probeContainerName);
}

export function truncate(text: string, max: number): { text: string; truncated: boolean } {
  if (text.length <= max) return { text, truncated: false };
  return { text: text.slice(0, max), truncated: true };
}

import type { V1Container, V1EnvVar, V1Probe } from "@kubernetes/client-node";
import type { ToolContext } from "../context.js";
import { nsOf } from "../context.js";
import { resolveWorkload } from "../model.js";
import { isSensitiveKey, redactText, REDACTED } from "../../security/sanitize.js";

export function describeEnv(env: V1EnvVar[] | undefined, cmData: Map<string, Record<string, string>>): Array<{ name: string; value?: string; from?: string }> {
  return (env ?? []).map((e) => {
    if (e.valueFrom?.secretKeyRef) return { name: e.name, from: `secret:${e.valueFrom.secretKeyRef.name}/${e.valueFrom.secretKeyRef.key}` };
    if (e.valueFrom?.configMapKeyRef) {
      const ref = e.valueFrom.configMapKeyRef;
      const v = cmData.get(ref.name ?? "")?.[ref.key];
      return { name: e.name, from: `configmap:${ref.name}/${ref.key}`, value: v === undefined ? undefined : isSensitiveKey(e.name) || isSensitiveKey(ref.key) ? REDACTED : redactText(v).slice(0, 300) };
    }
    if (e.valueFrom?.fieldRef) return { name: e.name, from: `field:${e.valueFrom.fieldRef.fieldPath}` };
    if (e.valueFrom?.resourceFieldRef) return { name: e.name, from: `resource:${e.valueFrom.resourceFieldRef.resource}` };
    return { name: e.name, value: e.value === undefined ? undefined : isSensitiveKey(e.name) ? REDACTED : redactText(e.value).slice(0, 300) };
  });
}

function describeProbe(p: V1Probe | undefined) {
  if (!p) return undefined;
  const handler = p.httpGet
    ? `httpGet ${p.httpGet.scheme ?? "HTTP"} :${p.httpGet.port}${p.httpGet.path ?? "/"}`
    : p.tcpSocket
      ? `tcpSocket :${p.tcpSocket.port}`
      : p.exec
        ? `exec ${(p.exec.command ?? []).join(" ").slice(0, 100)}`
        : p.grpc
          ? `grpc :${p.grpc.port}`
          : "unknown";
  return { handler, initialDelay: p.initialDelaySeconds ?? 0, period: p.periodSeconds ?? 10, timeout: p.timeoutSeconds ?? 1, failureThreshold: p.failureThreshold ?? 3, successThreshold: p.successThreshold ?? 1 };
}

export function jvmFindings(c: V1Container, env: Array<{ name: string; value?: string }>): string[] {
  const findings: string[] = [];
  const opts = env.filter((e) => /^(JAVA_TOOL_OPTIONS|JAVA_OPTS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS|CATALINA_OPTS)$/.test(e.name)).map((e) => e.value ?? "").join(" ");
  const limit = c.resources?.limits?.memory;
  const xmx = /-Xmx(\d+)([kmgKMG]?)/.exec(opts);
  if (xmx && limit) {
    const mult: Record<string, number> = { k: 1024, m: 1024 ** 2, g: 1024 ** 3, "": 1 };
    const heap = Number(xmx[1]) * mult[xmx[2].toLowerCase()];
    const lim = parseMem(limit);
    if (lim && heap >= lim * 0.85) findings.push(`-Xmx (${xmx[1]}${xmx[2]}) is >= 85% of the container memory limit (${limit}): metaspace/threads/native memory will push the container past its limit -> OOMKilled. Use -XX:MaxRAMPercentage=60-75 or lower -Xmx.`);
  }
  if (!xmx && !/MaxRAMPercentage/.test(opts) && limit) findings.push(`no -Xmx or -XX:MaxRAMPercentage set with a memory limit of ${limit}; the JVM defaults to 25% of the limit for heap (often too small) - set MaxRAMPercentage explicitly.`);
  if (!limit && (xmx || /java|jre|jdk|spring|tomcat/i.test(c.image ?? ""))) findings.push("no memory limit on a JVM container: the JVM will size its heap from the node, and the pod can be evicted under node pressure.");
  if (/-XX:\+UseSerialGC/.test(opts)) findings.push("SerialGC is in use (also the JVM default when it sees < 2 CPUs / < 2GB): latency-sensitive services usually want G1 or ZGC and >= 2 CPUs.");
  const cpuLimit = c.resources?.limits?.cpu;
  if (cpuLimit && parseCpuMillis(cpuLimit) !== undefined && parseCpuMillis(cpuLimit)! < 1000) findings.push(`CPU limit ${cpuLimit} < 1 core: the JVM sees 1 available processor, uses SerialGC by default, and gets CFS-throttled during GC/JIT bursts. Consider a request without a limit, or >= 2 cores.`);
  return findings;
}

function parseMem(q: string): number | undefined {
  const m = /^([0-9.]+)(Ki|Mi|Gi|Ti|k|M|G|T)?$/.exec(q);
  if (!m) return undefined;
  const mult: Record<string, number> = { Ki: 1024, Mi: 1024 ** 2, Gi: 1024 ** 3, Ti: 1024 ** 4, k: 1e3, M: 1e6, G: 1e9, T: 1e12 };
  return Number(m[1]) * (m[2] ? mult[m[2]] : 1);
}
function parseCpuMillis(q: string): number | undefined {
  const m = /^([0-9.]+)(m)?$/.exec(q);
  if (!m) return undefined;
  return m[2] ? Number(m[1]) : Number(m[1]) * 1000;
}

export async function getConfig(ctx: ToolContext, args: { namespace?: string; service: string }) {
  const ns = nsOf(ctx, args.namespace);
  const w = await resolveWorkload(ctx.k8s, ns, args.service);
  const cms = await ctx.k8s.listConfigMaps(ns);
  const cmData = new Map(cms.map((c) => [c.metadata?.name ?? "", c.data ?? {}]));
  const spec = w.deployment?.spec?.template?.spec ?? w.statefulSet?.spec?.template?.spec ?? w.daemonSet?.spec?.template?.spec ?? w.pods[0]?.spec;
  const findings: string[] = [];
  const containers = [...(spec?.initContainers ?? []).map((c) => ({ c, init: true })), ...(spec?.containers ?? []).map((c) => ({ c, init: false }))].map(({ c, init }) => {
    const env = describeEnv(c.env, cmData);
    const envFrom = (c.envFrom ?? []).map((e) => (e.configMapRef ? `configmap:${e.configMapRef.name}` : e.secretRef ? `secret:${e.secretRef.name}` : "?"));
    const literalSecrets = env.filter((e) => e.value !== undefined && !e.from && isSensitiveKey(e.name)).map((e) => e.name);
    if (literalSecrets.length) findings.push(`${c.name}: credential-looking env vars set as literal values (${literalSecrets.join(", ")}) - they are visible in the pod spec and to anyone with get on pods; use a Secret.`);
    const secretEnv = env.filter((e) => e.from?.startsWith("secret:")).map((e) => e.name);
    if (secretEnv.length) findings.push(`${c.name}: secrets exposed as env vars (${secretEnv.slice(0, 8).join(", ")}${secretEnv.length > 8 ? ", ..." : ""}) - env is visible in /proc and often ends up in logs/crash dumps; prefer volume mounts.`);
    if (!c.resources?.requests) findings.push(`${c.name}: no resource requests - the scheduler cannot place it sensibly and it gets BestEffort QoS (first to be evicted).`);
    if (!c.resources?.limits?.memory) findings.push(`${c.name}: no memory limit.`);
    if (!init && !c.readinessProbe) findings.push(`${c.name}: no readiness probe - the Service will route traffic to it before it can serve.`);
    if (!init && !c.livenessProbe) findings.push(`${c.name}: no liveness probe.`);
    if (/:latest$/.test(c.image ?? "") || !/[:@]/.test(c.image ?? "")) findings.push(`${c.name}: image "${c.image}" uses :latest or no tag - rollbacks and "what changed?" are impossible.`);
    if (!init) findings.push(...jvmFindings(c, env).map((f) => `${c.name}: ${f}`));
    return {
      name: c.name,
      init,
      restartPolicy: c.restartPolicy,
      image: c.image,
      imagePullPolicy: c.imagePullPolicy,
      command: c.command?.map(redactText),
      args: c.args?.map(redactText),
      ports: (c.ports ?? []).map((p) => `${p.name ? `${p.name}:` : ""}${p.containerPort}/${p.protocol ?? "TCP"}`),
      env,
      envFrom,
      resources: c.resources,
      probes: { liveness: describeProbe(c.livenessProbe), readiness: describeProbe(c.readinessProbe), startup: describeProbe(c.startupProbe) },
      volumeMounts: (c.volumeMounts ?? []).map((m) => `${m.name} -> ${m.mountPath}${m.readOnly ? " (ro)" : ""}`),
      securityContext: c.securityContext,
    };
  });
  const volumes = (spec?.volumes ?? []).map((v) => ({
    name: v.name,
    type: v.configMap ? `configMap:${v.configMap.name}` : v.secret ? `secret:${v.secret.secretName}` : v.persistentVolumeClaim ? `pvc:${v.persistentVolumeClaim.claimName}` : v.emptyDir ? "emptyDir" : v.hostPath ? `hostPath:${v.hostPath.path}` : v.projected ? "projected" : Object.keys(v).filter((k) => k !== "name")[0],
  }));
  const referencedCms = new Set<string>();
  for (const c of spec?.containers ?? []) {
    for (const e of c.env ?? []) if (e.valueFrom?.configMapKeyRef?.name) referencedCms.add(e.valueFrom.configMapKeyRef.name);
    for (const e of c.envFrom ?? []) if (e.configMapRef?.name) referencedCms.add(e.configMapRef.name);
  }
  for (const v of spec?.volumes ?? []) if (v.configMap?.name) referencedCms.add(v.configMap.name);
  const configMaps = [...referencedCms].map((name) => {
    const data = cmData.get(name);
    if (!data) return { name, missing: true };
    return { name, keys: Object.entries(data).map(([k, v]) => ({ key: k, bytes: v.length, preview: isSensitiveKey(k) ? REDACTED : redactText(v).slice(0, 200) })) };
  });
  if (configMaps.some((c) => "missing" in c)) findings.push(`referenced ConfigMaps are missing: ${configMaps.filter((c) => "missing" in c).map((c) => c.name).join(", ")}`);

  return {
    kind: w.kind,
    name: w.name,
    namespace: ns,
    serviceAccount: spec?.serviceAccountName ?? "default",
    automountServiceAccountToken: spec?.automountServiceAccountToken ?? true,
    podSecurityContext: spec?.securityContext,
    shareProcessNamespace: spec?.shareProcessNamespace ?? false,
    hostNetwork: spec?.hostNetwork ?? false,
    nodeSelector: spec?.nodeSelector,
    tolerations: spec?.tolerations?.length,
    affinity: spec?.affinity ? Object.keys(spec.affinity) : undefined,
    priorityClassName: spec?.priorityClassName,
    terminationGracePeriodSeconds: spec?.terminationGracePeriodSeconds,
    labels: w.templateMeta?.labels ?? w.pods[0]?.metadata?.labels,
    annotations: Object.keys(w.templateMeta?.annotations ?? {}),
    containers,
    volumes,
    configMaps,
    findings,
    note: "Secret values are never resolved; env vars sourced from Secrets show as from=secret:NAME/KEY. Credential-looking keys are redacted even when literal.",
  };
}

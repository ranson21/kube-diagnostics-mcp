/**
 * Read-only Kubernetes client.
 *
 * This wrapper is the code-level read-only boundary: it only exposes
 * get/list/log methods. There is deliberately no method on this class that
 * can create, patch, delete, exec, attach, or port-forward, so no tool can
 * mutate the cluster even if it wanted to. RBAC (deploy/hub/rbac.yaml) is the
 * second, independent boundary. Secrets are never read: the wrapper has no
 * Secret methods and the RBAC grants none.
 */
import {
  AppsV1Api,
  AutoscalingV2Api,
  BatchV1Api,
  CoreV1Api,
  DiscoveryV1Api,
  KubeConfig,
  Metrics,
  NetworkingV1Api,
  PolicyV1Api,
  RbacAuthorizationV1Api,
  VersionApi,
  type V1ConfigMap,
  type V1CronJob,
  type V1DaemonSet,
  type V1Deployment,
  type V1EndpointSlice,
  type CoreV1Event,
  type V2HorizontalPodAutoscaler,
  type V1Ingress,
  type V1Job,
  type V1Namespace,
  type V1NetworkPolicy,
  type V1Node,
  type V1Pod,
  type V1PodDisruptionBudget,
  type V1ReplicaSet,
  type V1Role,
  type V1RoleBinding,
  type V1ClusterRole,
  type V1ClusterRoleBinding,
  type V1Service,
  type V1ServiceAccount,
  type V1StatefulSet,
  type V1ResourceQuota,
  type PodMetricsList,
  type NodeMetricsList,
} from "@kubernetes/client-node";
import { ApiException } from "@kubernetes/client-node";
import { assertNamespaceAllowed, assertName, assertContainerName, assertLabelSelector, GuardError } from "../security/guard.js";
import { redactText } from "../security/sanitize.js";

export class KubeError extends Error {
  constructor(
    message: string,
    public readonly status?: number,
  ) {
    super(message);
  }
}

export interface ListOpts {
  labelSelector?: string;
  fieldSelector?: string;
  limit?: number;
}

export interface LogOpts {
  container?: string;
  tailLines?: number;
  sinceSeconds?: number;
  previous?: boolean;
  limitBytes?: number;
  timestamps?: boolean;
}

export interface ReadOnlyKubeClientOptions {
  /** Namespace allow-list; empty means anything RBAC permits. */
  namespaces?: string[];
  timeoutMs?: number;
}

function withTimeout<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new KubeError(`Kubernetes API call timed out after ${ms}ms: ${what}`, 504)), ms);
  });
  return Promise.race([p, timeout]).finally(() => clearTimeout(timer)) as Promise<T>;
}

function toKubeError(err: unknown, what: string): KubeError {
  if (err instanceof KubeError || err instanceof GuardError) return err as KubeError;
  if (err instanceof ApiException) {
    let reason = "";
    try {
      const body = typeof err.body === "string" ? JSON.parse(err.body) : err.body;
      reason = (body as { message?: string })?.message ?? "";
    } catch {
      reason = typeof err.body === "string" ? err.body.slice(0, 200) : "";
    }
    const hint =
      err.code === 403
        ? " (RBAC denied: this is expected for anything the hub's read-only role does not grant)"
        : err.code === 404
          ? " (not found)"
          : "";
    return new KubeError(redactText(`${what}: HTTP ${err.code}${hint}${reason ? ` - ${reason}` : ""}`), err.code);
  }
  const message = err instanceof Error ? err.message : String(err);
  return new KubeError(redactText(`${what}: ${message}`));
}

/** Builds a KubeConfig from the environment: in-cluster if available, else kubeconfig. */
export function loadKubeConfig(): KubeConfig {
  const kc = new KubeConfig();
  kc.loadFromDefault();
  return kc;
}

export class ReadOnlyKubeClient {
  private readonly core: CoreV1Api;
  private readonly apps: AppsV1Api;
  private readonly batch: BatchV1Api;
  private readonly networking: NetworkingV1Api;
  private readonly autoscaling: AutoscalingV2Api;
  private readonly discovery: DiscoveryV1Api;
  private readonly rbac: RbacAuthorizationV1Api;
  private readonly policy: PolicyV1Api;
  private readonly version: VersionApi;
  private readonly metrics: Metrics;
  readonly namespaces: string[];
  private readonly timeoutMs: number;

  constructor(
    private readonly kc: KubeConfig,
    opts: ReadOnlyKubeClientOptions = {},
  ) {
    this.core = kc.makeApiClient(CoreV1Api);
    this.apps = kc.makeApiClient(AppsV1Api);
    this.batch = kc.makeApiClient(BatchV1Api);
    this.networking = kc.makeApiClient(NetworkingV1Api);
    this.autoscaling = kc.makeApiClient(AutoscalingV2Api);
    this.discovery = kc.makeApiClient(DiscoveryV1Api);
    this.rbac = kc.makeApiClient(RbacAuthorizationV1Api);
    this.policy = kc.makeApiClient(PolicyV1Api);
    this.version = kc.makeApiClient(VersionApi);
    this.metrics = new Metrics(kc);
    this.namespaces = opts.namespaces ?? [];
    this.timeoutMs = opts.timeoutMs ?? 15000;
  }

  get contextName(): string {
    return this.kc.getCurrentContext();
  }

  get clusterServer(): string | undefined {
    return this.kc.getCurrentCluster()?.server;
  }

  private ns(namespace: string): string {
    return assertNamespaceAllowed(namespace, this.namespaces);
  }

  private async call<T>(what: string, fn: () => Promise<T>): Promise<T> {
    try {
      return await withTimeout(fn(), this.timeoutMs, what);
    } catch (err) {
      throw toKubeError(err, what);
    }
  }

  private listArgs(namespace: string, opts: ListOpts) {
    return {
      namespace: this.ns(namespace),
      labelSelector: opts.labelSelector ? assertLabelSelector(opts.labelSelector) : undefined,
      fieldSelector: opts.fieldSelector,
      limit: opts.limit,
    };
  }

  /**
   * Lists across namespaces honoring the allow-list: with an allow-list we
   * query each namespace (so RBAC can be namespaced), without one we use the
   * cluster-wide list (needs a ClusterRole).
   */
  private async acrossNamespaces<T>(
    all: () => Promise<{ items: T[] }>,
    perNs: (ns: string) => Promise<{ items: T[] }>,
  ): Promise<T[]> {
    if (!this.namespaces.length) return (await all()).items;
    const results = await Promise.all(this.namespaces.map((ns) => perNs(ns)));
    return results.flatMap((r) => r.items);
  }

  // ---- cluster ---------------------------------------------------------

  async serverVersion(): Promise<{ gitVersion?: string; platform?: string }> {
    return this.call("get server version", async () => {
      const v = await this.version.getCode();
      return { gitVersion: v.gitVersion, platform: v.platform };
    });
  }

  async listNamespaces(): Promise<V1Namespace[]> {
    return this.call("list namespaces", async () => {
      const list = await this.core.listNamespace();
      const items = list.items;
      return this.namespaces.length ? items.filter((n) => this.namespaces.includes(n.metadata?.name ?? "")) : items;
    });
  }

  async listNodes(): Promise<V1Node[]> {
    return this.call("list nodes", async () => (await this.core.listNode()).items);
  }

  // ---- workloads -------------------------------------------------------

  async listPods(namespace: string, opts: ListOpts = {}): Promise<V1Pod[]> {
    return this.call(`list pods in ${namespace}`, async () => (await this.core.listNamespacedPod(this.listArgs(namespace, opts))).items);
  }

  async listPodsAll(opts: ListOpts = {}): Promise<V1Pod[]> {
    return this.call("list pods", () =>
      this.acrossNamespaces(
        () => this.core.listPodForAllNamespaces({ labelSelector: opts.labelSelector, fieldSelector: opts.fieldSelector }),
        (ns) => this.core.listNamespacedPod(this.listArgs(ns, opts)),
      ),
    );
  }

  async getPod(namespace: string, name: string): Promise<V1Pod> {
    return this.call(`get pod ${namespace}/${name}`, () =>
      this.core.readNamespacedPod({ namespace: this.ns(namespace), name: assertName(name, "pod name") }),
    );
  }

  async listDeployments(namespace: string, opts: ListOpts = {}): Promise<V1Deployment[]> {
    return this.call(`list deployments in ${namespace}`, async () => (await this.apps.listNamespacedDeployment(this.listArgs(namespace, opts))).items);
  }

  async listDeploymentsAll(): Promise<V1Deployment[]> {
    return this.call("list deployments", () =>
      this.acrossNamespaces(
        () => this.apps.listDeploymentForAllNamespaces(),
        (ns) => this.apps.listNamespacedDeployment({ namespace: this.ns(ns) }),
      ),
    );
  }

  async listReplicaSets(namespace: string, opts: ListOpts = {}): Promise<V1ReplicaSet[]> {
    return this.call(`list replicasets in ${namespace}`, async () => (await this.apps.listNamespacedReplicaSet(this.listArgs(namespace, opts))).items);
  }

  async listStatefulSets(namespace: string, opts: ListOpts = {}): Promise<V1StatefulSet[]> {
    return this.call(`list statefulsets in ${namespace}`, async () => (await this.apps.listNamespacedStatefulSet(this.listArgs(namespace, opts))).items);
  }

  async listDaemonSets(namespace: string, opts: ListOpts = {}): Promise<V1DaemonSet[]> {
    return this.call(`list daemonsets in ${namespace}`, async () => (await this.apps.listNamespacedDaemonSet(this.listArgs(namespace, opts))).items);
  }

  async listJobs(namespace: string, opts: ListOpts = {}): Promise<V1Job[]> {
    return this.call(`list jobs in ${namespace}`, async () => (await this.batch.listNamespacedJob(this.listArgs(namespace, opts))).items);
  }

  async listCronJobs(namespace: string, opts: ListOpts = {}): Promise<V1CronJob[]> {
    return this.call(`list cronjobs in ${namespace}`, async () => (await this.batch.listNamespacedCronJob(this.listArgs(namespace, opts))).items);
  }

  async listHpas(namespace: string): Promise<V2HorizontalPodAutoscaler[]> {
    return this.call(`list hpas in ${namespace}`, async () => (await this.autoscaling.listNamespacedHorizontalPodAutoscaler({ namespace: this.ns(namespace) })).items);
  }

  async listPdbs(namespace: string): Promise<V1PodDisruptionBudget[]> {
    return this.call(`list pdbs in ${namespace}`, async () => (await this.policy.listNamespacedPodDisruptionBudget({ namespace: this.ns(namespace) })).items);
  }

  // ---- networking ------------------------------------------------------

  async listServices(namespace: string, opts: ListOpts = {}): Promise<V1Service[]> {
    return this.call(`list services in ${namespace}`, async () => (await this.core.listNamespacedService(this.listArgs(namespace, opts))).items);
  }

  async listEndpointSlices(namespace: string, opts: ListOpts = {}): Promise<V1EndpointSlice[]> {
    return this.call(`list endpointslices in ${namespace}`, async () => (await this.discovery.listNamespacedEndpointSlice(this.listArgs(namespace, opts))).items);
  }

  async listNetworkPolicies(namespace: string): Promise<V1NetworkPolicy[]> {
    return this.call(`list networkpolicies in ${namespace}`, async () => (await this.networking.listNamespacedNetworkPolicy({ namespace: this.ns(namespace) })).items);
  }

  async listIngresses(namespace: string): Promise<V1Ingress[]> {
    return this.call(`list ingresses in ${namespace}`, async () => (await this.networking.listNamespacedIngress({ namespace: this.ns(namespace) })).items);
  }

  // ---- config (never Secrets) ------------------------------------------

  async listConfigMaps(namespace: string): Promise<V1ConfigMap[]> {
    return this.call(`list configmaps in ${namespace}`, async () => (await this.core.listNamespacedConfigMap({ namespace: this.ns(namespace) })).items);
  }

  async getConfigMap(namespace: string, name: string): Promise<V1ConfigMap> {
    return this.call(`get configmap ${namespace}/${name}`, () =>
      this.core.readNamespacedConfigMap({ namespace: this.ns(namespace), name: assertName(name, "configmap name") }),
    );
  }

  async listResourceQuotas(namespace: string): Promise<V1ResourceQuota[]> {
    return this.call(`list resourcequotas in ${namespace}`, async () => (await this.core.listNamespacedResourceQuota({ namespace: this.ns(namespace) })).items);
  }

  // ---- rbac ------------------------------------------------------------

  async listServiceAccounts(namespace: string): Promise<V1ServiceAccount[]> {
    return this.call(`list serviceaccounts in ${namespace}`, async () => (await this.core.listNamespacedServiceAccount({ namespace: this.ns(namespace) })).items);
  }

  async listRoles(namespace: string): Promise<V1Role[]> {
    return this.call(`list roles in ${namespace}`, async () => (await this.rbac.listNamespacedRole({ namespace: this.ns(namespace) })).items);
  }

  async listRoleBindings(namespace: string): Promise<V1RoleBinding[]> {
    return this.call(`list rolebindings in ${namespace}`, async () => (await this.rbac.listNamespacedRoleBinding({ namespace: this.ns(namespace) })).items);
  }

  async listClusterRoles(): Promise<V1ClusterRole[]> {
    return this.call("list clusterroles", async () => (await this.rbac.listClusterRole()).items);
  }

  async listClusterRoleBindings(): Promise<V1ClusterRoleBinding[]> {
    return this.call("list clusterrolebindings", async () => (await this.rbac.listClusterRoleBinding()).items);
  }

  // ---- events & logs ---------------------------------------------------

  async listEvents(namespace: string, opts: ListOpts = {}): Promise<CoreV1Event[]> {
    return this.call(`list events in ${namespace}`, async () => (await this.core.listNamespacedEvent(this.listArgs(namespace, opts))).items);
  }

  async readPodLog(namespace: string, pod: string, opts: LogOpts = {}): Promise<string> {
    return this.call(`read logs of ${namespace}/${pod}`, () =>
      this.core.readNamespacedPodLog({
        namespace: this.ns(namespace),
        name: assertName(pod, "pod name"),
        container: opts.container ? assertContainerName(opts.container) : undefined,
        tailLines: opts.tailLines,
        sinceSeconds: opts.sinceSeconds,
        previous: opts.previous,
        limitBytes: opts.limitBytes,
        timestamps: opts.timestamps,
      }),
    );
  }

  // ---- metrics.k8s.io (optional; metrics-server) -----------------------

  async podMetrics(namespace: string): Promise<PodMetricsList | undefined> {
    try {
      return await this.call(`pod metrics in ${namespace}`, () => this.metrics.getPodMetrics(this.ns(namespace)));
    } catch (err) {
      if (err instanceof KubeError && (err.status === 404 || err.status === 503)) return undefined;
      throw err;
    }
  }

  async nodeMetrics(): Promise<NodeMetricsList | undefined> {
    try {
      return await this.call("node metrics", () => this.metrics.getNodeMetrics());
    } catch (err) {
      if (err instanceof KubeError && (err.status === 404 || err.status === 503)) return undefined;
      throw err;
    }
  }
}

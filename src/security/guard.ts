/**
 * Input validation for tool arguments. Everything that ends up in a
 * Kubernetes API path, a label selector, or a probe URL goes through here,
 * so a crafted argument can't turn into path traversal or selector injection.
 * Fails closed.
 */

export class GuardError extends Error {}

// RFC 1123 label: lowercase alphanumerics and '-', 1-63 chars, start/end alphanumeric.
const DNS_LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
// Pod names may be longer subdomain-ish (statefulset pods etc.); still no slashes or whitespace.
const K8S_NAME = /^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/;
const CONTAINER_NAME = DNS_LABEL;
const LABEL_SELECTOR = /^[A-Za-z0-9_./=,!()\- ]{1,512}$/;
const HOSTNAME = /^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/;
const TRACE_ID = /^[A-Za-z0-9-]{8,64}$/;

export function assertNamespace(value: string): string {
  if (!DNS_LABEL.test(value)) throw new GuardError(`Invalid namespace name: "${value}"`);
  return value;
}

export function assertName(value: string, what = "name"): string {
  if (!K8S_NAME.test(value)) throw new GuardError(`Invalid ${what}: "${value}"`);
  return value;
}

export function assertContainerName(value: string): string {
  if (!CONTAINER_NAME.test(value)) throw new GuardError(`Invalid container name: "${value}"`);
  return value;
}

export function assertLabelSelector(value: string): string {
  if (!LABEL_SELECTOR.test(value)) throw new GuardError(`Invalid label selector: "${value}"`);
  return value;
}

export function assertHostname(value: string): string {
  if (!HOSTNAME.test(value)) throw new GuardError(`Invalid hostname: "${value}"`);
  return value;
}

export function assertPort(value: number): number {
  if (!Number.isInteger(value) || value < 1 || value > 65535) throw new GuardError(`Invalid port: ${value}`);
  return value;
}

export function assertTraceId(value: string): string {
  if (!TRACE_ID.test(value)) throw new GuardError(`Invalid trace id: "${value}"`);
  return value;
}

/** Clamp a user-supplied limit into [1, max]. */
export function clampLimit(value: number | undefined, fallback: number, max: number): number {
  if (value === undefined) return Math.min(fallback, max);
  if (!Number.isFinite(value) || value < 1) return 1;
  return Math.min(Math.floor(value), max);
}

/**
 * Parses a human window like "15m", "2h", "1d", "90s" into seconds. Used for
 * `since`/`window` arguments. Capped to keep queries bounded.
 */
export function parseWindowSeconds(value: string | undefined, fallbackSeconds: number, maxSeconds = 7 * 24 * 3600): number {
  if (!value?.trim()) return Math.min(fallbackSeconds, maxSeconds);
  const m = /^(\d+)\s*(s|m|h|d)?$/i.exec(value.trim());
  if (!m) throw new GuardError(`Invalid time window "${value}" (use e.g. 90s, 15m, 2h, 1d)`);
  const n = Number(m[1]);
  const unit = (m[2] ?? "s").toLowerCase();
  const mult = unit === "d" ? 86400 : unit === "h" ? 3600 : unit === "m" ? 60 : 1;
  return Math.max(1, Math.min(n * mult, maxSeconds));
}

/** Enforce the DIAG_NAMESPACES allow-list (empty list = no restriction beyond RBAC). */
export function assertNamespaceAllowed(namespace: string, allowed: string[]): string {
  assertNamespace(namespace);
  if (allowed.length && !allowed.includes(namespace)) {
    throw new GuardError(`Namespace "${namespace}" is not in the configured allow-list (${allowed.join(", ")}).`);
  }
  return namespace;
}

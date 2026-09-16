/**
 * Defense-in-depth output scrubbing.
 *
 * This is NOT a security boundary. The real boundaries are: (1) the hub's
 * Kubernetes client has no write methods and its ServiceAccount has no RBAC
 * on Secrets, (2) env values that come from secretKeyRef are never resolved,
 * (3) the probe has no cluster credentials at all. This layer exists to catch
 * credential-shaped text that might otherwise be echoed back inside a log
 * line, a ConfigMap value, an error message, or a URL before it reaches the
 * LLM. Ported from postgres-readonly-mcp and extended with more shapes.
 */

export const REDACTED = "[REDACTED]";

interface RedactionRule {
  pattern: RegExp;
  replace: (match: string, ...groups: string[]) => string;
}

const RULES: RedactionRule[] = [
  // Connection strings with embedded credentials (any scheme: postgres, jdbc, mongodb, redis, amqp, mysql, http...)
  {
    pattern: /\b([a-z][a-z0-9+.-]{1,30}):\/\/[^\s"'<>@/]*:[^\s"'<>@/]+@[^\s"'<>]+/gi,
    replace: (_m, scheme: string) => `${scheme}://${REDACTED}@[host]`,
  },
  // postgres:// / postgresql:// / jdbc: strings even without a visible user:pass (may carry ?password=)
  {
    pattern: /\b(postgres(?:ql)?|jdbc:[a-z]+):\/\/[^\s"'<>]+/gi,
    replace: (_m, scheme: string) => `${scheme}://${REDACTED}`,
  },
  // Authorization: Bearer <token> / Basic <token>
  {
    pattern: /\b(Authorization\s*[:=]\s*)(Bearer|Basic)\s+[\w\-.~+/]+=*/gi,
    replace: (_m, prefix: string, scheme: string) => `${prefix}${scheme} ${REDACTED}`,
  },
  // Bare "Bearer <token>" / "Basic <token>"
  {
    pattern: /\b(Bearer|Basic)\s+[\w\-.~+/]{8,}=*/g,
    replace: (_m, scheme: string) => `${scheme} ${REDACTED}`,
  },
  // JWTs
  {
    pattern: /\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}\b/g,
    replace: () => `[REDACTED_JWT]`,
  },
  // key = value / key: "value" assignments for common credential field names
  {
    pattern:
      /\b([A-Za-z0-9_.-]*?(?:(?:api|access|auth|client|private|secret|app|application)[_-]?(?:key|token|secret)|secret|password|passwd|pwd|token|credentials?|database[_-]?url|connection[_-]?string|jdbc[_-]?url))\s*[:=]\s*["']?[^\s"'&,;]{4,}["']?/gi,
    replace: (_m, key: string) => `${key}=${REDACTED}`,
  },
  // PEM private key blocks
  {
    pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    replace: () => REDACTED,
  },
  // AWS access key IDs, GitHub tokens, Slack tokens, Google API keys, Stripe keys
  { pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, replace: () => REDACTED },
  { pattern: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, replace: () => REDACTED },
  { pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, replace: () => REDACTED },
  { pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g, replace: () => REDACTED },
  { pattern: /\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b/g, replace: () => REDACTED },
];

/** Redacts likely credential material from a single string. */
export function redactText(input: string): string {
  let out = input;
  for (const rule of RULES) {
    out = out.replace(rule.pattern, rule.replace as (...args: string[]) => string);
  }
  return out;
}

/**
 * Keys whose *values* are replaced outright, regardless of content. This is
 * also what decides whether an env var value is shown by get_config: a key
 * that looks like a credential is redacted even when it's a literal value.
 */
export const SENSITIVE_KEY_PATTERN =
  /(^|[_\-.])(api[_-]?key|access[_-]?token|auth[_-]?token|secret|password|passwd|pwd|client[_-]?secret|token|authorization|credentials?|connection[_-]?string|database[_-]?url|jdbc[_-]?url|private[_-]?key|cert(ificate)?[_-]?key)($|[_\-.])/i;

/** Keys that *reference* a secret rather than hold one (a file path, a Secret name, a flag). */
const REFERENCE_KEY_SUFFIX = /(_|-)?(file|path|dir|mount|name|ref|enabled|header|prefix|length|ttl|expiry|expires|rotation)$/i;

export function isSensitiveKey(key: string): boolean {
  return SENSITIVE_KEY_PATTERN.test(key) && !REFERENCE_KEY_SUFFIX.test(key);
}

/**
 * Recursively applies redaction to every string value in a JSON-like value.
 * Values stored under credential-looking keys are replaced outright.
 */
export function sanitizeDeep<T>(value: T, keyHint?: string): T {
  if (typeof value === "string") {
    if (keyHint && isSensitiveKey(keyHint)) return REDACTED as unknown as T;
    return redactText(value) as unknown as T;
  }
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeDeep(item, keyHint)) as unknown as T;
  }
  if (value !== null && typeof value === "object") {
    if (value instanceof Date) return value;
    const out: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
      out[key] = sanitizeDeep(val, key);
    }
    return out as unknown as T;
  }
  return value;
}

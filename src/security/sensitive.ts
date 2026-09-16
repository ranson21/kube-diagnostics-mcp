/**
 * Sensitive-data *detection* (as opposed to redaction in sanitize.ts).
 *
 * Used by scan_logs_for_sensitive_data and the access-log/RUM scanners. The
 * contract: return counts and *redacted* samples, never the matched value.
 * Pattern matching is noisy by nature, so every finding carries a confidence
 * and the sample is masked (first/last 2 chars only).
 */

export type SensitiveKind =
  | "email"
  | "credit_card"
  | "us_ssn"
  | "phone"
  | "ipv4_private"
  | "jwt"
  | "aws_access_key"
  | "gcp_api_key"
  | "github_token"
  | "slack_token"
  | "stripe_key"
  | "bearer_token"
  | "basic_auth"
  | "connection_string"
  | "private_key"
  | "credential_assignment";

export interface SensitiveFinding {
  kind: SensitiveKind;
  confidence: "high" | "medium" | "low";
  count: number;
  /** Masked example, e.g. "ja***@***.com" or "41** **** **** **11". Never the raw value. */
  sample: string;
  /** Line numbers (or record indexes) where it was seen, capped. */
  locations: number[];
}

interface Detector {
  kind: SensitiveKind;
  pattern: RegExp;
  confidence: SensitiveFinding["confidence"];
  /** Optional validator to cut false positives (e.g. Luhn for cards). */
  validate?: (match: string) => boolean;
  mask: (match: string) => string;
}

export function luhnValid(digits: string): boolean {
  const s = digits.replace(/[\s-]/g, "");
  if (!/^\d{13,19}$/.test(s)) return false;
  let sum = 0;
  let alt = false;
  for (let i = s.length - 1; i >= 0; i--) {
    let n = Number(s[i]);
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function maskMiddle(value: string, keep = 2): string {
  if (value.length <= keep * 2 + 1) return "*".repeat(value.length);
  return `${value.slice(0, keep)}${"*".repeat(Math.min(value.length - keep * 2, 12))}${value.slice(-keep)}`;
}

function maskEmail(value: string): string {
  const [local, domain] = value.split("@");
  const tld = domain?.includes(".") ? domain.slice(domain.lastIndexOf(".")) : "";
  return `${(local ?? "").slice(0, 2)}***@***${tld}`;
}

const DETECTORS: Detector[] = [
  {
    kind: "private_key",
    pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g,
    confidence: "high",
    mask: () => "-----BEGIN ***PRIVATE KEY-----",
  },
  { kind: "aws_access_key", pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, confidence: "high", mask: (m) => maskMiddle(m, 4) },
  { kind: "gcp_api_key", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g, confidence: "high", mask: (m) => maskMiddle(m, 4) },
  { kind: "github_token", pattern: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, confidence: "high", mask: (m) => maskMiddle(m, 4) },
  { kind: "slack_token", pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, confidence: "high", mask: (m) => maskMiddle(m, 4) },
  { kind: "stripe_key", pattern: /\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b/g, confidence: "high", mask: (m) => maskMiddle(m, 7) },
  { kind: "jwt", pattern: /\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}\b/g, confidence: "high", mask: (m) => maskMiddle(m, 6) },
  {
    kind: "connection_string",
    pattern: /\b(?:[a-z][a-z0-9+.-]{1,30}):\/\/[^\s"'<>@/]*:[^\s"'<>@/]+@[^\s"'<>]+/gi,
    confidence: "high",
    mask: (m) => `${m.slice(0, m.indexOf("://") + 3)}***:***@***`,
  },
  {
    kind: "bearer_token",
    pattern: /\bBearer\s+[\w\-.~+/]{16,}=*/g,
    confidence: "medium",
    mask: (m) => `Bearer ${maskMiddle(m.slice(7), 3)}`,
  },
  {
    kind: "basic_auth",
    pattern: /\bBasic\s+[A-Za-z0-9+/]{12,}=*/g,
    confidence: "medium",
    mask: (m) => `Basic ${maskMiddle(m.slice(6), 3)}`,
  },
  {
    kind: "credential_assignment",
    pattern:
      /\b(?:(?:api|access|auth|client|private|secret|app)[_-]?(?:key|token|secret)|password|passwd|pwd|secret|token)\s*[:=]\s*["']?[^\s"'&,;]{6,}["']?/gi,
    confidence: "medium",
    mask: (m) => {
      const idx = m.search(/[:=]/);
      return `${m.slice(0, idx + 1)}***`;
    },
  },
  {
    kind: "credit_card",
    pattern: /\b(?:\d[ -]?){13,19}\b/g,
    confidence: "high",
    validate: luhnValid,
    mask: (m) => {
      const digits = m.replace(/[\s-]/g, "");
      return `${digits.slice(0, 2)}** **** **** ${digits.slice(-2)}`;
    },
  },
  {
    kind: "us_ssn",
    pattern: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
    confidence: "medium",
    mask: () => "***-**-****",
  },
  {
    kind: "email",
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    confidence: "high",
    mask: maskEmail,
  },
  {
    kind: "phone",
    // North-American shapes with separators; deliberately narrow to avoid matching ids/timestamps.
    pattern: /(?:\+1[ -.])?\(?\b[2-9]\d{2}\)?[ -.]\d{3}[ -.]\d{4}\b/g,
    confidence: "low",
    mask: (m) => `${m.slice(0, 3)}***${m.slice(-2)}`,
  },
];

export interface ScanOptions {
  /** Max locations to record per finding. */
  maxLocations?: number;
  /** Kinds to skip (e.g. ["ipv4_private"]). */
  exclude?: SensitiveKind[];
}

/**
 * Scans an array of text records (log lines, JSON strings, access-log rows)
 * and returns aggregated, masked findings. The input is never returned.
 */
export function scanForSensitiveData(records: string[], opts: ScanOptions = {}): SensitiveFinding[] {
  const maxLocations = opts.maxLocations ?? 10;
  const exclude = new Set(opts.exclude ?? []);
  const byKind = new Map<SensitiveKind, SensitiveFinding>();

  records.forEach((record, index) => {
    for (const det of DETECTORS) {
      if (exclude.has(det.kind)) continue;
      det.pattern.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = det.pattern.exec(record)) !== null) {
        const value = m[0];
        if (det.validate && !det.validate(value)) continue;
        let f = byKind.get(det.kind);
        if (!f) {
          f = { kind: det.kind, confidence: det.confidence, count: 0, sample: det.mask(value), locations: [] };
          byKind.set(det.kind, f);
        }
        f.count += 1;
        if (f.locations.length < maxLocations && f.locations[f.locations.length - 1] !== index + 1) {
          f.locations.push(index + 1);
        }
        if (m.index === det.pattern.lastIndex) det.pattern.lastIndex++;
      }
    }
  });

  const order: Record<SensitiveFinding["confidence"], number> = { high: 0, medium: 1, low: 2 };
  return [...byKind.values()].sort((a, b) => order[a.confidence] - order[b.confidence] || b.count - a.count);
}

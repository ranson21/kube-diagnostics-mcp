import { sanitizeDeep } from "./security/sanitize.js";

/**
 * Diagnostic logging.
 *
 * IMPORTANT: in stdio mode stdout is reserved for MCP JSON-RPC traffic, so
 * every log line goes to stderr (console.error), never console.log. The
 * probe and the HTTP hub follow the same rule for consistency.
 */

export type LogLevel = "debug" | "info" | "warn" | "error";

const LEVEL_WEIGHT: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };
const VALID_LEVELS = new Set<LogLevel>(["debug", "info", "warn", "error"]);

export interface LoggerLike {
  debug(message: string, fields?: Record<string, unknown>): void;
  info(message: string, fields?: Record<string, unknown>): void;
  warn(message: string, fields?: Record<string, unknown>): void;
  error(message: string, fields?: Record<string, unknown>): void;
}

export function parseLogLevel(raw: string | undefined): LogLevel {
  const normalized = raw?.trim().toLowerCase();
  if (normalized && VALID_LEVELS.has(normalized as LogLevel)) return normalized as LogLevel;
  return "info";
}

export class Logger implements LoggerLike {
  constructor(
    private readonly level: LogLevel,
    private readonly component: string = "kube-diagnostics-mcp",
  ) {}

  private write(level: LogLevel, message: string, fields?: Record<string, unknown>): void {
    if (LEVEL_WEIGHT[level] < LEVEL_WEIGHT[this.level]) return;
    // Fields are sanitized on top of callers already being careful - defense-in-depth.
    const safeFields = fields ? sanitizeDeep(fields) : undefined;
    const suffix = safeFields && Object.keys(safeFields).length ? ` ${JSON.stringify(safeFields)}` : "";
    console.error(`[${new Date().toISOString()}] [${level.toUpperCase()}] [${this.component}] ${message}${suffix}`);
  }

  debug(message: string, fields?: Record<string, unknown>): void { this.write("debug", message, fields); }
  info(message: string, fields?: Record<string, unknown>): void { this.write("info", message, fields); }
  warn(message: string, fields?: Record<string, unknown>): void { this.write("warn", message, fields); }
  error(message: string, fields?: Record<string, unknown>): void { this.write("error", message, fields); }

  /** Returns a logger that merges `boundFields` into every call. */
  child(boundFields: Record<string, unknown>): LoggerLike {
    return {
      debug: (m, f) => this.debug(m, { ...boundFields, ...f }),
      info: (m, f) => this.info(m, { ...boundFields, ...f }),
      warn: (m, f) => this.warn(m, { ...boundFields, ...f }),
      error: (m, f) => this.error(m, { ...boundFields, ...f }),
    };
  }
}

export function createLogger(env: NodeJS.ProcessEnv = process.env, component?: string): Logger {
  return new Logger(parseLogLevel(env.DIAG_LOG_LEVEL), component);
}

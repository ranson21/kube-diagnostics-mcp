import { describe, expect, it } from "vitest";
import { redactText, sanitizeDeep, isSensitiveKey } from "../src/security/sanitize.js";

describe("redactText", () => {
  it("redacts connection strings with credentials for any scheme", () => {
    for (const s of ["postgres://u:FAKEPW@db:5432/x", "mongodb://u:FAKEPW@m:27017/x", "amqp://u:FAKEPW@r:5672/", "redis://:FAKEPW@r:6379"]) {
      const out = redactText(`conn=${s}`);
      expect(out).not.toContain("FAKEPW");
    }
  });
  it("redacts jdbc urls", () => {
    expect(redactText("jdbc:postgresql://db:5432/app?password=FAKEPW")).not.toContain("FAKEPW");
  });
  it("redacts bearer, basic and JWT", () => {
    expect(redactText("Authorization: Bearer abcdefghijklmnop.qrstuvwxyz")).toContain("Bearer [REDACTED]");
    expect(redactText("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")).toContain("[REDACTED_JWT]");
  });
  it("redacts key=value credentials", () => {
    expect(redactText("SPRING_DATASOURCE_PASSWORD=hunter2fake")).toContain("[REDACTED]");
    expect(redactText('api_key: "sk_fake_1234567890"')).not.toContain("1234567890");
  });
  it("redacts cloud keys", () => {
    expect(redactText("AKIAIOSFODNN7EXAMPLE")).toBe("[REDACTED]");
    expect(redactText("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")).toBe("[REDACTED]");
    expect(redactText("AIzaSyA-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAK")).toBe("[REDACTED]");
  });
  it("leaves ordinary text alone", () => {
    expect(redactText("GET /api/products 200 12ms")).toBe("GET /api/products 200 12ms");
  });
});

describe("sanitizeDeep / isSensitiveKey", () => {
  it("replaces values under credential-looking keys", () => {
    const out = sanitizeDeep({ DB_PASSWORD: "x", nested: { apiKey: "y", ok: "fine" }, list: [{ token: "z" }] });
    expect(out.DB_PASSWORD).toBe("[REDACTED]");
    expect(out.nested.apiKey).toBe("[REDACTED]");
    expect(out.nested.ok).toBe("fine");
    expect(out.list[0].token).toBe("[REDACTED]");
  });
  it("matches env-style keys", () => {
    expect(isSensitiveKey("SPRING_DATASOURCE_PASSWORD")).toBe(true);
    expect(isSensitiveKey("DB_URL")).toBe(false);
    expect(isSensitiveKey("DATABASE_URL")).toBe(true);
    expect(isSensitiveKey("JWT_SECRET")).toBe(true);
    expect(isSensitiveKey("LOG_LEVEL")).toBe(false);
    // references to secrets are not secrets
    expect(isSensitiveKey("DIAG_PROBE_TOKEN_FILE")).toBe(false);
    expect(isSensitiveKey("TLS_SECRET_NAME")).toBe(false);
    expect(isSensitiveKey("JWT_TOKEN_TTL")).toBe(false);
    expect(isSensitiveKey("PASSWORD_ROTATION")).toBe(false);
  });
});

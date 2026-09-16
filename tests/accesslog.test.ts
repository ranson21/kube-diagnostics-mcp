import { describe, expect, it } from "vitest";
import { parseAccessLine, summarizeAccessRecords, normalizePath } from "../src/probe/accesslog.js";

describe("access log", () => {
  it("parses nginx json lines", () => {
    const r = parseAccessLine(JSON.stringify({ time: "2026-09-16T10:00:00+00:00", request_method: "GET", uri: "/api/catalog/products/42", status: "200", request_time: "0.250", upstream_response_time: "0.200", upstream_addr: "10.0.0.5:8080", http_user_agent: "x" }));
    expect(r?.status).toBe(200);
    expect(r?.requestMs).toBe(250);
    expect(r?.upstreamMs).toBe(200);
    expect(r?.upstream).toBe("10.0.0.5:8080");
  });
  it("parses combined format with rt/urt suffix", () => {
    const r = parseAccessLine('10.0.0.1 - - [16/Sep/2026:10:00:00 +0000] "GET /products?id=1 HTTP/1.1" 504 12 "-" "curl" 2.001 2.000');
    expect(r?.status).toBe(504);
    expect(r?.path).toBe("/products");
    expect(r?.requestMs).toBe(2001);
  });
  it("normalizes ids", () => {
    expect(normalizePath("/api/products/42/reviews")).toBe("/api/products/:id/reviews");
    expect(normalizePath("/u/3f2504e0-4f89-11d3-9a0c-0305e82c3301")).toBe("/u/:uuid");
  });
  it("summarizes and flags 504/499 and scanners and pii", () => {
    const recs = [
      ...Array.from({ length: 50 }, () => ({ method: "GET", path: "/api/x", status: 200, requestMs: 50, upstreamMs: 40, upstream: "u1" })),
      ...Array.from({ length: 5 }, () => ({ method: "GET", path: "/api/slow", status: 504, requestMs: 2000, upstreamMs: 2000, upstream: "u1" })),
      { method: "GET", path: "/api/y", status: 499, requestMs: 3000 },
      { method: "GET", path: "/wp-login.php", status: 404 },
    ];
    const s = summarizeAccessRecords(recs, ['{"uri":"/api/x","email":"jane.doe@example.com"}']);
    expect(s.byStatusClass["5xx"]).toBe(5);
    expect(s.clientAbandoned499).toBe(1);
    expect(s.byUpstream[0].timeouts504).toBe(5);
    expect(s.suspiciousPaths[0].reason).toContain("WordPress");
    expect(s.sensitive?.[0].kind).toBe("email");
    expect(JSON.stringify(s)).not.toContain("jane.doe");
  });
});

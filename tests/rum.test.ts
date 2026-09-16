import { describe, expect, it } from "vitest";
import { RumAggregator, normalizeRoute, normalizeResourceUrl } from "../src/probe/rum.js";
import { mergeSummaries } from "../src/hub/tools/rum.js";

describe("rum aggregator", () => {
  it("normalizes routes and resource urls (privacy)", () => {
    expect(normalizeRoute("/products/42?utm=abc#x")).toBe("/products/:id");
    expect(normalizeResourceUrl("http://x/api/products/42?token=abc")).toBe("http://x/api/products/:id");
    expect(normalizeResourceUrl("/main.3f9a8b7c6d5e.js")).toBe("/main.[hash].js");
  });
  it("ingests only allow-listed events and summarizes", () => {
    const a = new RumAggregator(60_000);
    const n = a.ingest({
      session: "abc123", device: "desktop", route: "/products/:id",
      events: [
        { type: "vital", name: "LCP", value: 3200 }, { type: "vital", name: "LCP", value: 4100 }, { type: "vital", name: "BOGUS", value: 1 },
        { type: "view", route: "/products/:id", entry: true }, { type: "view", route: "/checkout" },
        { type: "resource", url: "/api/cart", durationMs: 1200, status: 200 }, { type: "resource", url: "/api/cart", durationMs: 800, status: 500 },
        { type: "error", message: "Cannot read properties of undefined (reading 'id') token=secretvalue123", stack: "TypeError: x\n    at ProductComponent.ngOnInit (main.js:1:2)" },
        { type: "nav", ttfb: 300, load: 2500 },
        { type: "exfil", data: "nope" },
      ],
    });
    expect(n).toBe(8);
    const s = a.summary();
    expect(s.vitals["/products/:id"].LCP.count).toBe(2);
    expect(s.views.find((v) => v.route === "/products/:id")?.entries).toBe(1);
    expect(s.resources[0].url).toBe("/api/cart");
    expect(s.resources[0].errors).toBe(1);
    expect(s.errors[0].signature).toContain("ProductComponent.ngOnInit");
    expect(JSON.stringify(s)).not.toContain("secretvalue123");
    expect(s.nav["/products/:id"].ttfb.p50).toBe(300);
    expect(s.sessions).toBe(1);
    expect(a.prometheusText()).toContain('rum_page_views_total{route="/checkout"} 1');
  });
  it("rejects garbage", () => {
    const a = new RumAggregator(60_000);
    expect(a.ingest("x")).toBe(0);
    expect(a.ingest({ events: "no" })).toBe(0);
    expect(a.ingest({ events: [{ type: "vital", name: "LCP", value: -1 }] })).toBe(0);
  });
  it("merges summaries weighted by count", () => {
    const base = { available: true, nav: {}, views: [], resources: [], errors: [], devices: {}, sessions: 1 };
    const m = mergeSummaries([
      { ...base, vitals: { "/": { LCP: { count: 10, p50: 1000, p75: 1000, p95: 1000, max: 1000 } } }, views: [{ route: "/", views: 10, entries: 1 }] },
      { ...base, vitals: { "/": { LCP: { count: 30, p50: 3000, p75: 3000, p95: 3000, max: 3500 } } }, views: [{ route: "/", views: 30, entries: 3 }] },
    ]);
    expect(m.vitals["/"].LCP.count).toBe(40);
    expect(m.vitals["/"].LCP.p75).toBe(2500);
    expect(m.vitals["/"].LCP.max).toBe(3500);
    expect(m.views[0].views).toBe(40);
    expect(m.sessions).toBe(2);
  });
});

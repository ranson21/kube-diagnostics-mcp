import { describe, expect, it } from "vitest";
import { assertNamespace, assertName, assertLabelSelector, parseWindowSeconds, clampLimit, assertNamespaceAllowed, GuardError, assertHostname } from "../src/security/guard.js";

describe("guard", () => {
  it("accepts valid names and rejects path-ish input", () => {
    expect(assertNamespace("faultlab")).toBe("faultlab");
    expect(() => assertNamespace("../kube-system")).toThrow(GuardError);
    expect(() => assertNamespace("Fault Lab")).toThrow(GuardError);
    expect(assertName("catalog-service-7d9f8b6c5-x2k9q", "pod")).toBeTruthy();
    expect(() => assertName("a/b", "pod")).toThrow(GuardError);
    expect(assertLabelSelector("app=catalog,tier in (web)")).toBeTruthy();
    expect(() => assertLabelSelector("app=x;rm -rf")).toThrow(GuardError);
    expect(assertHostname("catalog-service.faultlab.svc")).toBeTruthy();
    expect(() => assertHostname("http://x")).toThrow(GuardError);
  });
  it("parses windows", () => {
    expect(parseWindowSeconds("15m", 60)).toBe(900);
    expect(parseWindowSeconds("2h", 60)).toBe(7200);
    expect(parseWindowSeconds("1d", 60)).toBe(86400);
    expect(parseWindowSeconds(undefined, 60)).toBe(60);
    expect(parseWindowSeconds("30d", 60)).toBe(7 * 86400);
    expect(() => parseWindowSeconds("soon", 60)).toThrow(GuardError);
  });
  it("clamps limits", () => {
    expect(clampLimit(undefined, 200, 500)).toBe(200);
    expect(clampLimit(9999, 200, 500)).toBe(500);
    expect(clampLimit(-3, 200, 500)).toBe(1);
  });
  it("enforces allow-list", () => {
    expect(assertNamespaceAllowed("a", [])).toBe("a");
    expect(assertNamespaceAllowed("a", ["a", "b"])).toBe("a");
    expect(() => assertNamespaceAllowed("c", ["a", "b"])).toThrow(/allow-list/);
  });
});

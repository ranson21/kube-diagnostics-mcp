import { describe, expect, it } from "vitest";
import { loadConfig, ConfigError, summarize } from "../src/config.js";

describe("loadConfig", () => {
  it("defaults to hub/stdio", () => {
    const c = loadConfig({});
    expect(c.mode).toBe("hub");
    if (c.mode === "hub") {
      expect(c.transport).toBe("stdio");
      expect(c.allowActiveChecks).toBe(false);
      expect(c.namespaces).toEqual([]);
    }
  });
  it("requires a token for http unless explicitly disabled", () => {
    expect(() => loadConfig({ DIAG_TRANSPORT: "http" })).toThrow(ConfigError);
    expect(loadConfig({ DIAG_TRANSPORT: "http", DIAG_HTTP_TOKEN: "t" }).mode).toBe("hub");
    expect(loadConfig({ DIAG_TRANSPORT: "http", DIAG_HTTP_ALLOW_UNAUTHENTICATED: "true" }).mode).toBe("hub");
  });
  it("requires a probe token", () => {
    expect(() => loadConfig({ DIAG_MODE: "probe" })).toThrow(ConfigError);
    const c = loadConfig({ DIAG_MODE: "probe", DIAG_PROBE_TOKEN: "x", DIAG_PROBE_ACTUATOR_URL: "http://127.0.0.1:8080/actuator/" });
    expect(c.mode).toBe("probe");
    if (c.mode === "probe") expect(c.actuatorUrl).toBe("http://127.0.0.1:8080/actuator");
  });
  it("derives default namespace from a single allow-listed namespace", () => {
    const c = loadConfig({ DIAG_NAMESPACES: "faultlab" });
    if (c.mode === "hub") expect(c.defaultNamespace).toBe("faultlab");
    expect(() => loadConfig({ DIAG_NAMESPACES: "a,b", DIAG_DEFAULT_NAMESPACE: "c" })).toThrow(ConfigError);
  });
  it("recognizes datadog/splunk config without exposing secrets in summary", () => {
    const c = loadConfig({ DIAG_DATADOG_API_KEY: "a", DIAG_DATADOG_APP_KEY: "b", DIAG_SPLUNK_URL: "https://s", DIAG_SPLUNK_TOKEN: "t" });
    const s = JSON.stringify(summarize(c));
    expect(s).toContain('"datadog":true');
    expect(s).toContain('"splunk":true');
    expect(s).not.toContain('"a"');
    expect(() => loadConfig({ DIAG_DATADOG_API_KEY: "a" })).toThrow(ConfigError);
  });
});

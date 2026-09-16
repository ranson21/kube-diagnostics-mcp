import { describe, expect, it } from "vitest";
import { logSignature, javaSignature } from "../src/hub/tools/logs.js";
import { summarizeThreadDump } from "../src/hub/tools/java.js";
import { summarizeNginxConf } from "../src/hub/tools/proxy.js";
import { parseQuantity, cpuMillicores, memoryBytes, summarizePod } from "../src/hub/model.js";
import { jvmFindings } from "../src/hub/tools/config.js";

describe("log signatures", () => {
  it("normalizes numbers/ids/timestamps", () => {
    const a = logSignature("2026-09-16T10:00:00.123Z ERROR [http-nio-8080-exec-3] order 8842 failed for user 3f2504e0-4f89-11d3-9a0c-0305e82c3301 after 1200ms");
    const b = logSignature("2026-09-16T10:05:00.999Z ERROR [http-nio-8080-exec-9] order 17 failed for user 9f2504e0-4f89-11d3-9a0c-0305e82c3302 after 3ms");
    expect(a).toBe(b);
  });
  it("java signature uses exception + first app frame", () => {
    const lines = [
      "2026-09-16 ERROR o.s.web.servlet.DispatcherServlet - Request failed",
      "java.lang.NullPointerException: Cannot invoke \"String.length()\"",
      "\tat java.base/java.lang.String.length(String.java:1)",
      "\tat org.springframework.web.Foo.bar(Foo.java:2)",
      "\tat com.faultlab.catalog.ReviewService.load(ReviewService.java:42)",
    ];
    expect(javaSignature(lines, 1)).toBe("java.lang.NullPointerException @ com.faultlab.catalog.ReviewService.load");
    expect(javaSignature(lines, 0)).toBeUndefined();
  });
});

describe("thread dump summary", () => {
  it("detects deadlocks and pool saturation", () => {
    const threads = [
      { threadName: "worker-1", threadState: "BLOCKED", lockName: "java.lang.Object@1", lockOwnerName: "worker-2", lockedMonitors: [{ className: "java.lang.Object@2" }], stackTrace: [{ className: "com.faultlab.Dead", methodName: "a" }] },
      { threadName: "worker-2", threadState: "BLOCKED", lockName: "java.lang.Object@2", lockOwnerName: "worker-1", lockedMonitors: [{ className: "java.lang.Object@1" }], stackTrace: [{ className: "com.faultlab.Dead", methodName: "b" }] },
      ...Array.from({ length: 10 }, (_, i) => ({ threadName: `http-nio-8080-exec-${i}`, threadState: "RUNNABLE", stackTrace: [{ className: "java.net.SocketInputStream", methodName: "read" }, { className: "com.faultlab.Slow", methodName: "query" }] })),
      { threadName: "Reference Handler", threadState: "WAITING", stackTrace: [] },
    ];
    const s = summarizeThreadDump(threads);
    expect(s.deadlocks).toHaveLength(1);
    expect(s.findings.some((f) => f.startsWith("DEADLOCK"))).toBe(true);
    expect(s.findings.some((f) => /pool "http-nio-8080-exec" saturated/.test(f))).toBe(true);
    expect(s.topStacks[0].signature).toBe("com.faultlab.Slow.query");
    expect(s.byState.BLOCKED).toBe(2);
  });
});

describe("nginx conf summary", () => {
  it("extracts upstreams, locations, timeouts, and flags faults", () => {
    const conf = `
      upstream catalog { server catalog-service:8080; }
      server {
        listen 80;
        proxy_read_timeout 2s;
        location / { root /usr/share/nginx/html; try_files $uri /index.html; }
        location /api/catalog/ { proxy_pass http://catalog/; }
        location = /stub_status { stub_status; }
      }`;
    const s = summarizeNginxConf(conf);
    expect(s.upstreams[0]).toEqual({ name: "catalog", servers: ["catalog-service:8080"] });
    expect(s.locations.find((l) => l.path === "/api/catalog/")?.proxyPass).toBe("http://catalog/");
    expect(s.timeouts.proxy_read_timeout).toBe("2s");
    expect(s.findings.some((f) => /proxy_read_timeout/.test(f))).toBe(true);
    expect(s.findings.some((f) => /gzip/.test(f))).toBe(true);
    expect(s.findings.some((f) => /Strict-Transport-Security/.test(f))).toBe(true);
    expect(s.findings.some((f) => /index.html is cacheable/.test(f))).toBe(true);
    expect(s.stubStatus).toBe(true);
  });
});

describe("model", () => {
  it("parses quantities", () => {
    expect(parseQuantity("100m")).toBeCloseTo(0.1);
    expect(cpuMillicores("1.5")).toBe(1500);
    expect(memoryBytes("512Mi")).toBe(512 * 1024 * 1024);
    expect(memoryBytes("1G")).toBe(1e9);
    expect(parseQuantity("abc")).toBeUndefined();
  });
  it("summarizes pod problems", () => {
    const s = summarizePod({
      metadata: { name: "p", namespace: "n", creationTimestamp: new Date(Date.now() - 3600_000) },
      spec: { containers: [{ name: "app", image: "x:1" }], initContainers: [{ name: "diag-probe", image: "probe", restartPolicy: "Always" }] },
      status: {
        phase: "Running",
        containerStatuses: [{ name: "app", ready: false, restartCount: 7, image: "x:1", imageID: "", state: { waiting: { reason: "CrashLoopBackOff", message: "back-off 5m" } }, lastState: { terminated: { reason: "OOMKilled", exitCode: 137 } } }],
        initContainerStatuses: [{ name: "diag-probe", ready: true, restartCount: 0, image: "probe", imageID: "", state: { running: { startedAt: new Date() } } }],
      },
    } as never);
    expect(s.ready).toBe("1/2");
    expect(s.restarts).toBe(7);
    expect(s.hasProbe).toBe(true);
    expect(s.problems.some((p) => /CrashLoopBackOff/.test(p))).toBe(true);
    expect(s.problems.some((p) => /OOMKilled/.test(p))).toBe(true);
  });
  it("flags JVM heap vs limit", () => {
    const f = jvmFindings({ name: "app", image: "eclipse-temurin:21", resources: { limits: { memory: "512Mi", cpu: "100m" } } } as never, [{ name: "JAVA_TOOL_OPTIONS", value: "-Xmx900m" }]);
    expect(f.some((x) => /-Xmx/.test(x))).toBe(true);
    expect(f.some((x) => /CPU limit/.test(x))).toBe(true);
  });
});

describe("structured log parsing", () => {
  it("extracts level/message/exception from ECS json and builds a clean signature", async () => {
    const { parseJsonLog, firstAppFrame } = await import("../src/hub/tools/logs.js");
    const line = JSON.stringify({ "@timestamp": "2026-09-16T10:09:27Z", log: { level: "ERROR", logger: "o.h.SqlExceptionHelper" }, message: "Connection is not available, request timed out after 3001ms (total=2, active=2)", error: { type: "java.sql.SQLTransientConnectionException", stack_trace: "java.sql.SQLTransientConnectionException: x\n\tat com.zaxxer.hikari.pool.HikariPool.createTimeoutException(HikariPool.java:1)\n\tat dev.faultlab.order.OrderController.checkout(OrderController.java:42)\n" }, traceId: "abc" });
    const j = parseJsonLog(`2026-09-16T10:09:27.0Z ${line}`.replace(/^\S+\s+/, ""));
    expect(j?.level).toBe("ERROR");
    expect(j?.exceptionType).toBe("java.sql.SQLTransientConnectionException");
    expect(firstAppFrame(j?.stack)).toBe("dev.faultlab.order.OrderController.checkout");
    expect(parseJsonLog("plain text line")).toBeUndefined();
  });
});

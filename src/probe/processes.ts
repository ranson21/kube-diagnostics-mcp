/**
 * Process stats from /proc. Only meaningful when the pod sets
 * shareProcessNamespace: true; otherwise the probe sees only itself and says so.
 */
import { readdir, readFile, readlink } from "node:fs/promises";
import type { ProcessSummary } from "./protocol.js";

async function readOptional(path: string): Promise<string | undefined> {
  try {
    return await readFile(path, "utf8");
  } catch {
    return undefined;
  }
}

export async function summarizeProcesses(procRoot = "/proc", selfPid = process.pid): Promise<ProcessSummary> {
  let entries: string[];
  try {
    entries = await readdir(procRoot);
  } catch {
    return { available: false, note: "/proc not readable", processes: [] };
  }
  const pids = entries.filter((e) => /^\d+$/.test(e)).map(Number);
  const pageSize = 4096;
  const uptimeRaw = await readOptional(`${procRoot}/uptime`);
  const sysUptime = uptimeRaw ? Number(uptimeRaw.split(" ")[0]) : undefined;
  const clockTicks = 100;

  const processes: ProcessSummary["processes"] = [];
  for (const pid of pids) {
    const stat = await readOptional(`${procRoot}/${pid}/stat`);
    if (!stat) continue;
    // comm may contain spaces; it is delimited by parentheses.
    const open = stat.indexOf("(");
    const close = stat.lastIndexOf(")");
    const comm = stat.slice(open + 1, close);
    const rest = stat.slice(close + 2).split(" ");
    const state = rest[0];
    const startTicks = Number(rest[19]);
    const threads = Number(rest[17]);
    const rssPages = Number(rest[21]);
    let fdCount: number | undefined;
    try {
      fdCount = (await readdir(`${procRoot}/${pid}/fd`)).length;
    } catch {
      fdCount = undefined;
    }
    let fdLimit: number | undefined;
    const limits = await readOptional(`${procRoot}/${pid}/limits`);
    const lim = limits?.split("\n").find((l) => l.startsWith("Max open files"));
    if (lim) {
      const parts = lim.split(/\s{2,}/);
      fdLimit = Number(parts[1]) || undefined;
    }
    let cmdline = (await readOptional(`${procRoot}/${pid}/cmdline`))?.replace(/\0/g, " ").trim();
    if (cmdline && cmdline.length > 200) cmdline = `${cmdline.slice(0, 200)}...`;
    // Never echo a full JVM command line's -D flags verbatim: they can carry passwords.
    if (cmdline) cmdline = cmdline.replace(/(-D[\w.]*(?:pass|secret|token|key)[\w.]*=)\S+/gi, "$1[REDACTED]");
    processes.push({
      pid,
      comm,
      state,
      rssBytes: rssPages * pageSize,
      threads,
      fdCount,
      fdLimit,
      uptimeSeconds: sysUptime !== undefined ? Math.max(0, Math.round(sysUptime - startTicks / clockTicks)) : undefined,
      cmdline,
    });
  }
  const others = processes.filter((p) => p.pid !== selfPid);
  const note = others.length === 0 ? "Only the probe's own process is visible: set shareProcessNamespace: true on the pod to see the application." : undefined;
  void readlink;
  return { available: true, note, processes: processes.sort((a, b) => b.rssBytes - a.rssBytes).slice(0, 50) };
}

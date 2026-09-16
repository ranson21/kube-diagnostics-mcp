/**
 * /proc/net readers. The probe shares the pod's network namespace, so
 * /proc/net/tcp{,6} and /proc/net/udp{,6} inside the probe describe the
 * application's sockets too. Passive: nothing is opened or sent.
 */
import { readFile } from "node:fs/promises";
import type { ConnectionSummary } from "./protocol.js";

const TCP_STATES: Record<string, string> = {
  "01": "ESTABLISHED",
  "02": "SYN_SENT",
  "03": "SYN_RECV",
  "04": "FIN_WAIT1",
  "05": "FIN_WAIT2",
  "06": "TIME_WAIT",
  "07": "CLOSE",
  "08": "CLOSE_WAIT",
  "09": "LAST_ACK",
  "0A": "LISTEN",
  "0B": "CLOSING",
};

export function parseHexAddr4(hex: string): { address: string; port: number } {
  const [addrHex, portHex] = hex.split(":");
  const n = Number.parseInt(addrHex, 16);
  const address = [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff].join(".");
  return { address, port: Number.parseInt(portHex, 16) };
}

export function parseHexAddr6(hex: string): { address: string; port: number } {
  const [addrHex, portHex] = hex.split(":");
  // /proc/net/tcp6 stores the address as four little-endian 32-bit words.
  const words: string[] = [];
  for (let i = 0; i < 4; i++) {
    const w = addrHex.slice(i * 8, i * 8 + 8);
    const bytes = [w.slice(6, 8), w.slice(4, 6), w.slice(2, 4), w.slice(0, 2)];
    words.push(bytes[0] + bytes[1], bytes[2] + bytes[3]);
  }
  let address = words.map((g) => g.replace(/^0+(?=.)/, "").toLowerCase()).join(":");
  // v4-mapped ::ffff:a.b.c.d
  const m = /^0:0:0:0:0:ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(address);
  if (m) {
    const hi = Number.parseInt(m[1].padStart(4, "0"), 16);
    const lo = Number.parseInt(m[2].padStart(4, "0"), 16);
    address = `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
  }
  return { address, port: Number.parseInt(portHex, 16) };
}

interface SockRow {
  local: { address: string; port: number };
  remote: { address: string; port: number };
  state: string;
}

export function parseProcNetTable(content: string, v6: boolean): SockRow[] {
  const rows: SockRow[] = [];
  const lines = content.split("\n").slice(1);
  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 4) continue;
    const parse = v6 ? parseHexAddr6 : parseHexAddr4;
    rows.push({ local: parse(parts[1]), remote: parse(parts[2]), state: TCP_STATES[parts[3]] ?? parts[3] });
  }
  return rows;
}

async function readOptional(path: string): Promise<string | undefined> {
  try {
    return await readFile(path, "utf8");
  } catch {
    return undefined;
  }
}

export async function summarizeConnections(procRoot = "/proc"): Promise<ConnectionSummary> {
  const tcp4 = await readOptional(`${procRoot}/net/tcp`);
  const tcp6 = await readOptional(`${procRoot}/net/tcp6`);
  const udp4 = await readOptional(`${procRoot}/net/udp`);
  const udp6 = await readOptional(`${procRoot}/net/udp6`);
  if (tcp4 === undefined && tcp6 === undefined) {
    return { established: [], states: {}, listening: [], totals: { tcp: 0, udp: 0 }, available: false, note: "/proc/net/tcp not readable" };
  }
  const tcpRows = [...(tcp4 ? parseProcNetTable(tcp4, false) : []), ...(tcp6 ? parseProcNetTable(tcp6, true) : [])];
  const udpRows = [...(udp4 ? parseProcNetTable(udp4, false) : []), ...(udp6 ? parseProcNetTable(udp6, true) : [])];

  const states: Record<string, number> = {};
  const estab = new Map<string, { remote: string; port: number; count: number }>();
  const listening: ConnectionSummary["listening"] = [];
  for (const r of tcpRows) {
    states[r.state] = (states[r.state] ?? 0) + 1;
    if (r.state === "LISTEN") {
      listening.push({ address: r.local.address, port: r.local.port, proto: r.local.address.includes(":") ? "tcp6" : "tcp" });
    } else if (r.state === "ESTABLISHED") {
      const key = `${r.remote.address}:${r.remote.port}`;
      const e = estab.get(key) ?? { remote: r.remote.address, port: r.remote.port, count: 0 };
      e.count++;
      estab.set(key, e);
    }
  }
  for (const r of udpRows) {
    // UDP "LISTEN" is state 07 (CLOSE) with a bound local port and no remote.
    if (r.remote.port === 0 && r.local.port !== 0) {
      listening.push({ address: r.local.address, port: r.local.port, proto: r.local.address.includes(":") ? "udp6" : "udp" });
    }
  }
  return {
    established: [...estab.values()].sort((a, b) => b.count - a.count).slice(0, 100),
    states,
    listening: listening.sort((a, b) => a.port - b.port),
    totals: { tcp: tcpRows.length, udp: udpRows.length },
    available: true,
  };
}

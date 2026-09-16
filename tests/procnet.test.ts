import { describe, expect, it } from "vitest";
import { parseHexAddr4, parseHexAddr6, parseProcNetTable } from "../src/probe/procnet.js";

describe("procnet", () => {
  it("parses ipv4 little-endian addresses", () => {
    expect(parseHexAddr4("0100007F:1F90")).toEqual({ address: "127.0.0.1", port: 8080 });
    expect(parseHexAddr4("00000000:0050")).toEqual({ address: "0.0.0.0", port: 80 });
  });
  it("parses v4-mapped ipv6", () => {
    expect(parseHexAddr6("0000000000000000FFFF00000100000A:1F90")).toEqual({ address: "10.0.0.1", port: 8080 });
  });
  it("parses a tcp table", () => {
    const table = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0A00000A:C350 0B00000A:1538 01 00000000:00000000 00:00000000 00000000  1000        0 12346 1 0000000000000000 100 0 0 10 0
   2: 0A00000A:C351 0B00000A:1538 06 00000000:00000000 00:00000000 00000000  1000        0 0 1 0000000000000000 100 0 0 10 0`;
    const rows = parseProcNetTable(table, false);
    expect(rows).toHaveLength(3);
    expect(rows[0].state).toBe("LISTEN");
    expect(rows[0].local.port).toBe(8080);
    expect(rows[1].state).toBe("ESTABLISHED");
    expect(rows[1].remote).toEqual({ address: "10.0.0.11", port: 5432 });
    expect(rows[2].state).toBe("TIME_WAIT");
  });
});

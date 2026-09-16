/**
 * Streamable HTTP transport for the hub, with bearer-token auth and
 * per-session transports. One MCP session = one StreamableHTTPServerTransport.
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { randomUUID, timingSafeEqual } from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { HubConfig } from "../../config.js";
import type { LoggerLike } from "../../logger.js";

function authorized(req: IncomingMessage, config: HubConfig): boolean {
  if (config.allowUnauthenticated) return true;
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ") || !config.httpToken) return false;
  const given = Buffer.from(header.slice(7));
  const want = Buffer.from(config.httpToken);
  return given.length === want.length && timingSafeEqual(given, want);
}

async function readJson(req: IncomingMessage, maxBytes = 4 * 1024 * 1024): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > maxBytes) {
        reject(new Error("request body too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      const text = Buffer.concat(chunks).toString("utf8");
      if (!text) return resolve(undefined);
      try {
        resolve(JSON.parse(text));
      } catch (e) {
        reject(e);
      }
    });
    req.on("error", reject);
  });
}

export function startHttp(config: HubConfig, logger: LoggerLike, makeServer: () => McpServer): Promise<void> {
  const sessions = new Map<string, { transport: StreamableHTTPServerTransport; server: McpServer }>();

  async function handle(req: IncomingMessage, res: ServerResponse) {
    const url = new URL(req.url ?? "/", "http://hub");
    if (url.pathname === "/healthz") {
      res.writeHead(200, { "content-type": "text/plain" }).end("ok");
      return;
    }
    if (url.pathname !== "/mcp") {
      res.writeHead(404).end();
      return;
    }
    if (!authorized(req, config)) {
      res.writeHead(401, { "content-type": "application/json", "www-authenticate": "Bearer" }).end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    const sessionId = req.headers["mcp-session-id"];
    const sid = Array.isArray(sessionId) ? sessionId[0] : sessionId;

    if (req.method === "POST") {
      const body = await readJson(req);
      if (sid && sessions.has(sid)) {
        await sessions.get(sid)!.transport.handleRequest(req, res, body);
        return;
      }
      const isInit = body && typeof body === "object" && (body as { method?: string }).method === "initialize";
      if (!sid && isInit) {
        const server = makeServer();
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          enableDnsRebindingProtection: false,
          onsessioninitialized: (id) => {
            sessions.set(id, { transport, server });
            logger.info("mcp session started", { session: id, sessions: sessions.size });
          },
        });
        transport.onclose = () => {
          const id = transport.sessionId;
          if (id && sessions.delete(id)) logger.info("mcp session closed", { session: id, sessions: sessions.size });
        };
        await server.connect(transport);
        await transport.handleRequest(req, res, body);
        return;
      }
      res.writeHead(400, { "content-type": "application/json" }).end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32000, message: "Bad Request: no valid session (send initialize first)" }, id: null }));
      return;
    }
    if (req.method === "GET" || req.method === "DELETE") {
      if (!sid || !sessions.has(sid)) {
        res.writeHead(400).end("missing or unknown mcp-session-id");
        return;
      }
      await sessions.get(sid)!.transport.handleRequest(req, res);
      return;
    }
    res.writeHead(405).end();
  }

  const httpServer = createServer((req, res) => {
    handle(req, res).catch((err) => {
      logger.error("http handler failed", { error: err instanceof Error ? err.message : String(err) });
      if (!res.headersSent) res.writeHead(500).end();
    });
  });
  return new Promise((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(config.httpPort, config.httpHost, () => {
      logger.info("hub listening", { host: config.httpHost, port: config.httpPort, path: "/mcp", auth: config.httpToken ? "bearer" : "NONE" });
      resolve();
    });
  });
}

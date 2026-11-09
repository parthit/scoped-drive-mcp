import { cors } from "hono/cors";
import { Hono } from "hono";
import { Bridge } from "./bridge.js";
import { createMcpServer } from "./mcp.js";
import {
  approvalPage,
  approvalResultPage,
  homePage,
  manageDonePage,
  managePage,
  messagePage,
  playbookPage,
  registerPage,
  registeredPage,
} from "./pages.js";
import { PLAYBOOK } from "./playbook.js";
import { safeEqual, sha256 } from "./ids.js";
import { limitsFromEnv, type Limits } from "./limits.js";
import { createDefaultStore, type Store } from "./store/index.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";

const VERSION = "1.0.0";

export type AppDeps = {
  store: Store;
  now?: () => Date;
  limits?: Limits;
  baseUrl?: string;
  auditToken?: string | null;
  sweepToken?: string | null;
  registerPerHour?: number;
};

export function createApp(deps: AppDeps): Hono {
  const bridge = new Bridge(deps.store, { now: deps.now, limits: deps.limits });
  const auditToken = deps.auditToken !== undefined ? deps.auditToken : process.env.AUDIT_TOKEN?.trim() || null;
  const sweepToken = deps.sweepToken !== undefined ? deps.sweepToken : process.env.SWEEP_TOKEN?.trim() || null;
  const registerPerHour = deps.registerPerHour ?? 30;
  const app = new Hono();

  app.use("*", async (c, next) => {
    await next();
    c.header("X-Content-Type-Options", "nosniff");
    c.header("Referrer-Policy", "no-referrer");
    c.header("X-Frame-Options", "DENY");
  });

  const corsMw = cors({
    origin: "*",
    allowMethods: ["POST", "GET", "DELETE", "OPTIONS"],
    allowHeaders: ["Content-Type", "Accept", "Authorization", "Mcp-Protocol-Version", "Mcp-Session-Id", "Last-Event-ID", "X-Bot-Token"],
    exposeHeaders: ["Mcp-Session-Id", "WWW-Authenticate"],
    maxAge: 86400,
  });
  app.use("/mcp", corsMw);
  app.use("/mcp/*", corsMw);

  app.get("/", (c) => html(c, homePage()));
  app.get("/playbook", (c) => {
    if (wantsJson(c)) return c.text(PLAYBOOK);
    return html(c, playbookPage());
  });

  app.get("/health", async (c) => {
    try {
      await deps.store.ping();
      return c.json({ ok: true, service: "bot-bridge", version: VERSION, store: deps.store.kind });
    } catch {
      return c.json({ ok: false, service: "bot-bridge", version: VERSION, store: deps.store.kind }, 503);
    }
  });

  app.get("/register", (c) => html(c, registerPage()));
  app.post("/register", async (c) => {
    if (!(await allowRegister(deps.store, clientIp(c), registerPerHour, new Date()))) {
      const message = "Too many registrations from this network. Try again later.";
      if (wantsJson(c)) return c.json({ error: "rate_limited", message }, 429);
      return html(c, registerPage(message), 429);
    }
    const body = await readObject(c);
    if (!body.ok) {
      if (wantsJson(c)) return c.json({ error: "invalid_input", message: body.message }, 400);
      return html(c, registerPage(body.message), 400);
    }
    const result = await bridge.register(
      { displayName: stringField(body.value, "display_name") ?? stringField(body.value, "displayName") ?? "", email: stringField(body.value, "email") },
      base(c, deps.baseUrl),
    );
    if (!result.ok) {
      if (wantsJson(c)) return c.json({ error: result.error, message: result.message }, 400);
      return html(c, registerPage(result.message), 400);
    }
    if (wantsJson(c)) return c.json(result.data, 201);
    return html(
      c,
      registeredPage({ displayName: result.data.display_name, mcpUrl: result.data.mcp_url, token: result.data.token, baseUrl: base(c, deps.baseUrl) }),
      201,
    );
  });

  app.get("/approve/:token", async (c) => {
    const view = await bridge.approvalView(c.req.param("token"), base(c, deps.baseUrl));
    return html(c, approvalPage(view));
  });

  app.post("/approve/:token", async (c) => {
    const token = c.req.param("token");
    const body = await readObject(c);
    const decision = body.ok ? stringField(body.value, "decision") : null;
    if (decision !== "approve" && decision !== "deny") {
      const message = "Choose approve or deny.";
      if (wantsJson(c)) return c.json({ error: "invalid_input", message }, 400);
      return html(c, messagePage("Missing decision", message), 400);
    }
    const result = await bridge.decideApproval(token, decision, base(c, deps.baseUrl));
    if (!result.ok) {
      if (wantsJson(c)) return c.json({ error: result.error, message: result.message, ...result.details }, statusFor(result.error));
      if (result.error === "waiting_for_peer") return html(c, approvalPage(await bridge.approvalView(token, base(c, deps.baseUrl))), 409);
      return html(c, messagePage("Approval not recorded", result.message), statusFor(result.error));
    }
    const view = await bridge.approvalView(token, base(c, deps.baseUrl));
    const peerName = view.state === "invalid" ? null : view.peer_name;
    if (wantsJson(c)) return c.json({ ...result.data, peer_name: peerName });
    return html(c, approvalResultPage({ status: result.data.status, peerName, manageUrl: result.data.manage_url, denied: decision === "deny" }));
  });

  app.get("/manage/:token", async (c) => html(c, managePage(await bridge.manageView(c.req.param("token")))));

  app.post("/manage/:token", async (c) => {
    const body = await readObject(c);
    const purge = body.ok && (body.value.purge_messages === true || body.value.purge_messages === "true" || body.value.purge_messages === "on");
    const result = await bridge.revokeFromManage(c.req.param("token"), purge);
    if (!result.ok) {
      if (wantsJson(c)) return c.json({ error: result.error, message: result.message }, statusFor(result.error));
      return html(c, managePage(await bridge.manageView(c.req.param("token")), result.message), statusFor(result.error));
    }
    if (wantsJson(c)) return c.json(result.data);
    return html(c, manageDonePage(result.data.purged_messages));
  });

  app.get("/audit", async (c) => {
    if (!auditToken) return c.json({ error: "not_found", message: "Audit read is disabled." }, 404);
    if (!bearerMatches(c.req.header("authorization"), auditToken)) {
      return c.json({ error: "unauthenticated", message: "Audit token required." }, 401);
    }
    const events = await deps.store.listAudits();
    return c.json({
      events: events.map((event) => ({
        event_id: event.event_id,
        actor: event.actor,
        action: event.action,
        link_id: event.link_id,
        meta: event.meta_json,
        created_at: event.created_at.toISOString(),
      })),
    });
  });

  app.post("/internal/sweep", async (c) => {
    if (!sweepToken) return c.json({ error: "not_found", message: "Sweep is disabled." }, 404);
    if (!bearerMatches(c.req.header("authorization"), sweepToken)) {
      return c.json({ error: "unauthenticated", message: "Sweep token required." }, 401);
    }
    return c.json(await bridge.sweep());
  });

  app.on(["GET", "DELETE"], "/mcp", (c) => methodNotAllowed(c));
  app.on(["GET", "DELETE"], "/mcp/:token", (c) => methodNotAllowed(c));
  app.post("/mcp", (c) => handleMcp(c, bridge, base(c, deps.baseUrl)));
  app.post("/mcp/:token", (c) => handleMcp(c, bridge, base(c, deps.baseUrl)));

  app.notFound((c) => {
    if (wantsJson(c)) return c.json({ error: "not_found", message: "No such page." }, 404);
    return html(c, messagePage("Not found", "That page is not part of Bot Bridge."), 404);
  });

  app.onError((error, c) => {
    console.error("request_failed", error instanceof Error ? error.message : "error");
    return c.json({ error: "internal_error", message: "Something went wrong." }, 500);
  });

  return app;
}

async function handleMcp(
  c: {
    req: {
      param: (name: string) => string | undefined;
      raw: Request;
      header: (name: string) => string | undefined;
    };
  },
  bridge: Bridge,
  baseUrl: string,
): Promise<Response> {
  const pathToken = c.req.param("token");
  const headerToken = tokenFromHeader(c.req.header("authorization"), c.req.header("x-bot-token"));
  if (pathToken && headerToken && pathToken !== headerToken) return unauthenticated();
  const token = pathToken || headerToken;
  const bot = token ? await bridge.authenticate(token) : null;
  if (!bot) return unauthenticated();
  const server = createMcpServer(bridge, bot, baseUrl);
  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
    maxRequestBodySize: 64 * 1024,
  });
  try {
    await server.connect(transport);
    return await transport.handleRequest(c.req.raw);
  } catch (error) {
    console.error("mcp_failed", error instanceof Error ? error.name : "error");
    return Response.json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal server error" }, id: null }, { status: 500 });
  } finally {
    await transport.close().catch(() => undefined);
    await server.close().catch(() => undefined);
  }
}

function unauthenticated(): Response {
  return Response.json(
    {
      jsonrpc: "2.0",
      error: {
        code: -32001,
        message: "unauthenticated",
        data: { error: "unauthenticated", message: "Provide the bot token in the connector URL or as Authorization: Bearer." },
      },
      id: null,
    },
    { status: 401, headers: { "WWW-Authenticate": 'Bearer realm="bot-bridge"' } },
  );
}

function methodNotAllowed(c: { json: (body: unknown, status?: number) => Response }): Response {
  return c.json(
    { jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed. This server is stateless. POST JSON-RPC to /mcp." }, id: null },
    405,
  );
}

function html(c: { body: (body: string, status?: number, headers?: Record<string, string>) => Response }, body: string, status = 200): Response {
  return c.body(body, status, {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  });
}

function wantsJson(c: { req: { header: (name: string) => string | undefined } }): boolean {
  const accept = c.req.header("accept") ?? "";
  const type = c.req.header("content-type") ?? "";
  return accept.includes("application/json") || type.includes("application/json");
}

function base(c: { req: { url: string } }, forced?: string): string {
  return resolveBaseUrl(c.req.url, forced);
}

export function resolveBaseUrl(requestUrl: string, forced?: string): string {
  if (forced) return forced.replace(/\/$/, "");
  const configured = process.env.PUBLIC_BASE_URL?.trim();
  if (configured) return configured.replace(/\/$/, "");
  const url = new URL(requestUrl);
  return `${url.protocol}//${url.host}`;
}

function clientIp(c: { req: { header: (name: string) => string | undefined } }): string {
  const real = c.req.header("x-real-ip")?.trim();
  if (real) return real;
  const vercel = c.req.header("x-vercel-forwarded-for")?.split(",")[0]?.trim();
  if (vercel) return vercel;
  const forwarded = c.req.header("x-forwarded-for");
  if (forwarded) {
    const parts = forwarded.split(",").map((part) => part.trim()).filter((part) => part.length > 0);
    const platform = parts[parts.length - 1];
    if (platform) return platform;
  }
  return "local";
}

const REGISTER_WINDOW_MS = 60 * 60 * 1000;

async function allowRegister(store: Store, ip: string, limit: number, now: Date): Promise<boolean> {
  return store.tryConsumeRate(`register:${sha256(ip)}`, now, REGISTER_WINDOW_MS, limit);
}

async function readObject(c: { req: { header: (name: string) => string | undefined; json: () => Promise<unknown>; parseBody: () => Promise<Record<string, unknown>> } }): Promise<{ ok: true; value: Record<string, unknown> } | { ok: false; message: string }> {
  const type = c.req.header("content-type") ?? "";
  try {
    if (type.includes("application/json")) {
      const value = await c.req.json();
      if (!value || typeof value !== "object" || Array.isArray(value)) return { ok: false, message: "JSON body must be an object." };
      return { ok: true, value: value as Record<string, unknown> };
    }
    const form = await c.req.parseBody();
    return { ok: true, value: form };
  } catch {
    return { ok: false, message: "Could not read the form." };
  }
}

function stringField(body: Record<string, unknown>, key: string): string | undefined {
  const value = body[key];
  return typeof value === "string" ? value : undefined;
}

function tokenFromHeader(authorization: string | undefined, alt: string | undefined): string | null {
  if (authorization?.toLowerCase().startsWith("bearer ")) {
    const token = authorization.slice(7).trim();
    if (token) return token;
  }
  if (alt?.trim()) return alt.trim();
  return null;
}

function bearerMatches(authorization: string | undefined, expected: string): boolean {
  const token = tokenFromHeader(authorization, undefined);
  if (!token) return false;
  return safeEqual(token, expected);
}

function statusFor(error: string): 400 | 401 | 404 | 409 | 429 {
  if (error === "unauthenticated") return 401;
  if (error === "not_found" || error === "invite_not_found") return 404;
  if (error === "rate_limited") return 429;
  if (error === "waiting_for_peer" || error === "already_used" || error === "invite_taken" || error === "idempotency_conflict") return 409;
  return 400;
}

let pending: Promise<Hono> | null = null;

export function getApp(): Promise<Hono> {
  if (!pending) {
    pending = createDefaultApp().catch((error: unknown) => {
      pending = null;
      throw error;
    });
  }
  return pending;
}

async function createDefaultApp(): Promise<Hono> {
  const store = await createDefaultStore();
  return createApp({ store, limits: limitsFromEnv() });
}

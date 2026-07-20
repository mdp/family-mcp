import { Hono } from "hono";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import type { Env } from "./env.js";
import { CloudflareKVStorage } from "./storage.js";
import { getTokens, getUserInfoFromStorage } from "./storage.js";
import { resolveAuth, signJWT, makeSessionCookie, clearSessionCookie } from "./auth.js";
import { registerOAuthRoutes } from "./oauth.js";
import { createMcpServer } from "./mcp-server.js";

// ─── HTML helpers ─────────────────────────────────────────────────────────────

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function page(title: string, body: string): string {
  return `<!DOCTYPE html>
<html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title} — family-mcp</title>
<style>
  *{box-sizing:border-box}
  body{font-family:system-ui,sans-serif;max-width:520px;margin:60px auto;padding:0 24px;color:#1a1a1a;line-height:1.5}
  h1{font-size:1.4em;margin-bottom:0.25em}
  h2{font-size:1em;font-weight:600;margin:1.8em 0 0.5em;color:#444}
  p{margin:0.4em 0}
  a{color:#2563eb}
  .card{background:#f8f8f8;border:1px solid #e5e5e5;border-radius:8px;padding:16px 20px;margin:1em 0}
  .avatar{width:40px;height:40px;border-radius:50%;vertical-align:middle;margin-right:10px}
  .key{font-family:monospace;font-size:0.85em;background:#f1f5f9;padding:10px 14px;border-radius:6px;word-break:break-all;display:block;margin:0.5em 0}
  .btn{display:inline-block;padding:8px 16px;border-radius:6px;font-size:0.9em;font-weight:500;cursor:pointer;text-decoration:none;border:none}
  .btn-primary{background:#2563eb;color:#fff}
  .btn-danger{background:#fff;color:#dc2626;border:1px solid #dc2626}
  .btn-sm{padding:4px 12px;font-size:0.82em}
  .meta{color:#888;font-size:0.82em}
  .actions{margin-top:1.2em;display:flex;gap:8px;flex-wrap:wrap}
</style>
</head><body>${body}</body></html>`;
}

// ─── App ──────────────────────────────────────────────────────────────────────

const app = new Hono<{ Bindings: Env }>();

let oauthRoutesRegistered = false;

function ensureOAuthRoutes(env: Env): void {
  if (oauthRoutesRegistered) return;
  oauthRoutesRegistered = true;
  const tokensStorage = new CloudflareKVStorage(env.TOKENS_KV);
  const stateStorage = new CloudflareKVStorage(env.STATE_KV);
  registerOAuthRoutes(app, tokensStorage, stateStorage);
}

// ─── /auth/status ─────────────────────────────────────────────────────────────

app.get("/auth/status", async (c) => {
  const storage = new CloudflareKVStorage(c.env.TOKENS_KV);
  const auth = await resolveAuth(c.req.raw, c.env.JWT_SECRET, storage, c.executionCtx);
  const wantsJson = c.req.header("accept")?.includes("application/json");

  if (!auth) {
    if (wantsJson) return c.json({ authenticated: false }, 200);
    return c.html(page("Not Signed In", `
      <h1>family-mcp</h1>
      <p>You are not signed in.</p>
      <div class="actions">
        <a class="btn btn-primary" href="/oauth/authorize">Sign in with Google</a>
      </div>
    `));
  }

  const userInfo = await getUserInfoFromStorage(storage, auth.email);

  if (wantsJson) {
    return c.json({
      authenticated: true,
      email: auth.email,
      name: userInfo?.name ?? null,
      picture: userInfo?.picture ?? null,
    });
  }

  const mcpUrl = new URL("/mcp", c.req.url).href;
  const avatarHtml = userInfo?.picture
    ? `<img class="avatar" src="${escapeHtml(userInfo.picture)}" alt="">`
    : "";

  return c.html(page("Status", `
    <h1>family-mcp</h1>

    <div class="card">
      <p>
        ${avatarHtml}
        <strong>${escapeHtml(userInfo?.name ?? auth.email)}</strong>
      </p>
      <p class="meta">${escapeHtml(auth.email)}</p>
    </div>

    <h2>MCP Server URL</h2>
    <code class="key">${escapeHtml(mcpUrl)}</code>

    <div class="actions" style="margin-top:2.5em;padding-top:1.2em;border-top:1px solid #e5e5e5">
      <a class="btn btn-danger btn-sm" href="/oauth/authorize">Re-authorize Google</a>
      <a class="btn btn-sm" href="/auth/logout" style="border:1px solid #ccc">Sign out</a>
    </div>
  `));
});

// ─── GET /auth/logout ─────────────────────────────────────────────────────────

app.get("/auth/logout", (c) => {
  const isSecure = new URL(c.req.url).protocol === "https:";
  c.header("Set-Cookie", clearSessionCookie(isSecure));
  return c.redirect("/auth/status", 303);
});

// ─── DELETE /auth/session ─────────────────────────────────────────────────────

app.delete("/auth/session", (c) => {
  const isSecure = new URL(c.req.url).protocol === "https:";
  c.header("Set-Cookie", clearSessionCookie(isSecure));
  return c.json({ ok: true });
});

// ─── /mcp ─────────────────────────────────────────────────────────────────────

app.all("/mcp", async (c) => {
  if (c.req.method === "GET") {
    return c.json(
      {
        jsonrpc: "2.0",
        error: { code: -32000, message: "Method not allowed (stateless mode)" },
        id: null,
      },
      405,
      { Allow: "POST, DELETE" },
    );
  }

  const storage = new CloudflareKVStorage(c.env.TOKENS_KV);
  const auth = await resolveAuth(c.req.raw, c.env.JWT_SECRET, storage, c.executionCtx);

  if (!auth) {
    const resourceMetadata = `${new URL(c.req.url).origin}/.well-known/oauth-protected-resource`;
    return c.json(
      {
        jsonrpc: "2.0",
        error: { code: -32001, message: "Unauthorized. Please sign in at /oauth/authorize." },
        id: null,
      },
      401,
      {
        "WWW-Authenticate": `Bearer resource_metadata="${resourceMetadata}"`,
      },
    );
  }

  const { success } = await c.env.MCP_RATE_LIMITER.limit({ key: auth.email });
  if (!success) {
    return c.json(
      {
        jsonrpc: "2.0",
        error: { code: -32002, message: "Rate limit exceeded. Try again shortly." },
        id: null,
      },
      429,
      { "Retry-After": "10" },
    );
  }

  const mcpServer = createMcpServer(storage, c.env, auth.email);
  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
  });

  await mcpServer.connect(transport);

  return transport.handleRequest(c.req.raw, {
    authInfo: {
      token: "session",
      clientId: auth.email,
      scopes: [],
      extra: { email: auth.email },
    },
  });
});

// ─── / ────────────────────────────────────────────────────────────────────────

app.get("/", (c) => {
  return c.json({
    name: "family-mcp",
    version: "1.0.0",
    description: "MCP server for shared family Gmail, Calendar, and Drive workflows",
    endpoints: {
      oauth: {
        authorize: "GET /oauth/authorize",
        callback:  "GET /oauth/callback",
      },
      auth: {
        status:  "GET /auth/status",
        logout:  "GET /auth/logout",
        session: "DELETE /auth/session",
      },
      mcp: "POST /mcp",
    },
  });
});

// ─── Cloudflare Workers export ────────────────────────────────────────────────

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    ensureOAuthRoutes(env);
    return app.fetch(request, env, ctx);
  },
};

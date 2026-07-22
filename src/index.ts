import { Hono } from "hono";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import type { Env } from "./env.js";
import { CloudflareKVStorage } from "./storage.js";
import { getTokens, getUserInfoFromStorage, saveApiKey, listApiKeysForEmail, revokeApiKey, listOAuthGrantsForEmail } from "./storage.js";
import { resolveAuth, signJWT, makeSessionCookie, clearSessionCookie, API_KEY_PREFIX } from "./auth.js";
import { registerOAuthRoutes } from "./oauth.js";
import { createMcpServer } from "./mcp-server.js";
import type { ApiKey } from "./types.js";

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
  const authMethod = auth.authMethod ?? "oauth";

  // Fetch API keys and OAuth clients
  const apiKeys = await listApiKeysForEmail(storage, auth.email);
  const clients = await listOAuthGrantsForEmail(storage, auth.email);

  function apiKeyRows(): string {
    if (apiKeys.length === 0) return "<p class=\"meta\">No API keys created.</p>";
    return apiKeys
      .map((k) => {
        const status = k.revokedAt
          ? `<span style="color:#dc2626">Revoked</span>`
          : `<span style="color:#16a34a">Active</span>`;
        return `<div class="card" style="padding:10px 14px;margin:6px 0">
          <p><strong>${escapeHtml(k.name)}</strong> <span class="meta">…${escapeHtml(k.tokenSuffix)}</span></p>
          <p class="meta">${status} · Created ${new Date(k.createdAt).toLocaleDateString()}</p>
        </div>`;
      })
      .join("");
  }

  function clientRows(): string {
    if (clients.length === 0) return "<p class=\"meta\">No OAuth clients connected.</p>";
    return clients
      .map((g) => `<div class="card" style="padding:10px 14px;margin:6px 0">
        <p><strong>${escapeHtml(g.clientName || g.clientId)}</strong></p>
        <p class="meta">${escapeHtml(g.clientUri || "")} · Scope: ${escapeHtml(g.scope)} · ${new Date(g.createdAt).toLocaleDateString()}</p>
      </div>`)
      .join("");
  }

  return c.html(page("Status", `
    <h1>family-mcp</h1>

    <div class="card">
      <p>
        ${avatarHtml}
        <strong>${escapeHtml(userInfo?.name ?? auth.email)}</strong>
      </p>
      <p class="meta">${escapeHtml(auth.email)} · Auth: ${escapeHtml(authMethod)}</p>
    </div>

    <h2>MCP Server URL</h2>
    <code class="key">${escapeHtml(mcpUrl)}</code>

    <h2>API Keys</h2>
    ${apiKeyRows()}
    <div class="actions" style="margin-top:6px">
      <button class="btn btn-primary btn-sm" onclick="location.href='/auth/api-keys-page'">+ Create API Key</button>
    </div>

    <h2>OAuth Clients</h2>
    ${clientRows()}

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

// ─── GET /auth/api-keys ───────────────────────────────────────────────────────

app.get("/auth/api-keys", async (c) => {
  const storage = new CloudflareKVStorage(c.env.TOKENS_KV);
  const auth = await resolveAuth(c.req.raw, c.env.JWT_SECRET, storage, c.executionCtx);
  if (!auth) return c.json({ error: "Unauthorized" }, 401);

  const keys = await listApiKeysForEmail(storage, auth.email);
  return c.json(
    keys.map((k) => ({
      id: k.id,
      name: k.name,
      tokenSuffix: k.tokenSuffix,
      createdAt: k.createdAt,
      lastUsedAt: k.lastUsedAt ?? null,
      revokedAt: k.revokedAt ?? null,
    })),
  );
});

// ─── POST /auth/api-keys ──────────────────────────────────────────────────────

app.post("/auth/api-keys", async (c) => {
  const storage = new CloudflareKVStorage(c.env.TOKENS_KV);
  const auth = await resolveAuth(c.req.raw, c.env.JWT_SECRET, storage, c.executionCtx);
  if (!auth) return c.json({ error: "Unauthorized" }, 401);

  let body: { name?: string };
  try {
    body = await c.req.json();
  } catch {
    body = {};
  }
  const name = (body.name || "API Key").trim().slice(0, 100) || "API Key";

  // Generate a cryptographically random API key
  const randomBytes = new Uint8Array(32);
  crypto.getRandomValues(randomBytes);
  const randomHex = Array.from(randomBytes, (b) => b.toString(16).padStart(2, "0")).join("");
  const token = API_KEY_PREFIX + randomHex;
  const tokenSuffix = token.slice(-8);

  // Hash the token for storage
  const encoder = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(token));
  const tokenHash = Array.from(new Uint8Array(hashBuffer), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");

  const apiKey: ApiKey = {
    id: crypto.randomUUID(),
    email: auth.email,
    name,
    tokenHash,
    tokenSuffix,
    createdAt: Date.now(),
  };

  await saveApiKey(storage, apiKey);

  // Return the full token — this is the ONLY time it is shown
  return c.json({
    id: apiKey.id,
    name: apiKey.name,
    token,
    tokenSuffix: apiKey.tokenSuffix,
    createdAt: apiKey.createdAt,
  }, 201);
});

// ─── DELETE /auth/api-keys/:id ───────────────────────────────────────────────

app.delete("/auth/api-keys/:id", async (c) => {
  const storage = new CloudflareKVStorage(c.env.TOKENS_KV);
  const auth = await resolveAuth(c.req.raw, c.env.JWT_SECRET, storage, c.executionCtx);
  if (!auth) return c.json({ error: "Unauthorized" }, 401);

  const id = c.req.param("id");
  if (!id) return c.json({ error: "Missing key ID" }, 400);

  // Find the API key by ID to get its tokenHash
  const keys = await listApiKeysForEmail(storage, auth.email);
  const key = keys.find((k) => k.id === id);
  if (!key) return c.json({ error: "API key not found" }, 404);

  const revoked = await revokeApiKey(storage, key.tokenHash, auth.email);
  if (!revoked) return c.json({ error: "Key already revoked or not found" }, 404);

  return c.json({ ok: true });
});

// ─── GET /auth/api-keys-page (API key creation page) ────────────────────────

app.get("/auth/api-keys-page", async (c) => {
  const storage = new CloudflareKVStorage(c.env.TOKENS_KV);
  const auth = await resolveAuth(c.req.raw, c.env.JWT_SECRET, storage, c.executionCtx);
  if (!auth) return c.redirect("/auth/status", 303);

  return c.html(
    page("Create API Key", `
    <h1>Create API Key</h1>
    <p>API keys allow MCP clients to authenticate without going through the full OAuth flow.</p>

    <form id="create-form" style="margin:1em 0">
      <label for="name" style="display:block;margin-bottom:0.5em;font-weight:600">Key name:</label>
      <input type="text" id="name" name="name" placeholder="e.g. Claude Desktop" required
        style="width:100%;padding:10px 12px;border:1px solid #ccc;border-radius:6px;font-size:0.95em;box-sizing:border-box">
      <div style="margin-top:1em">
        <button type="submit" class="btn btn-primary">Generate API Key</button>
        <a href="/auth/status" class="btn btn-sm" style="border:1px solid #ccc;margin-left:8px">Cancel</a>
      </div>
    </form>

    <div id="result" style="display:none;margin-top:1em">
      <div class="card" style="background:#f0fdf4;border-color:#16a34a">
        <p style="font-weight:600;color:#16a34a">API Key Created</p>
        <p class="meta">Copy this key now — it will not be shown again.</p>
        <code class="key" id="token-display" style="user-select:all"></code>
        <p class="meta">Use with: <code>Authorization: Bearer &lt;key&gt;</code></p>
      </div>
      <div class="actions">
        <a class="btn btn-primary btn-sm" href="/auth/status">Back to Status</a>
      </div>
    </div>

    <script>
      document.getElementById("create-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        const name = document.getElementById("name").value.trim() || "API Key";
        const res = await fetch("/auth/api-keys", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name }),
        });
        if (!res.ok) {
          alert("Failed to create API key: " + (await res.text()));
          return;
        }
        const data = await res.json();
        document.getElementById("create-form").style.display = "none";
        document.getElementById("token-display").textContent = data.token;
        document.getElementById("result").style.display = "block";
      });
    </script>
  `),
  );
});


// ─── GET /auth/clients ────────────────────────────────────────────────────────

app.get("/auth/clients", async (c) => {
  const storage = new CloudflareKVStorage(c.env.TOKENS_KV);
  const auth = await resolveAuth(c.req.raw, c.env.JWT_SECRET, storage, c.executionCtx);
  if (!auth) return c.json({ error: "Unauthorized" }, 401);

  const wantsJson = c.req.header("accept")?.includes("application/json") || false;
  const clients = await listOAuthGrantsForEmail(storage, auth.email);

  if (wantsJson) {
    return c.json(
      clients.map((g) => ({
        grantId: g.grantId,
        clientId: g.clientId,
        clientName: g.clientName ?? null,
        clientUri: g.clientUri ?? null,
        scope: g.scope,
        createdAt: g.createdAt,
        lastUsedAt: g.lastUsedAt ?? null,
      })),
    );
  }

  // HTML page
  function clientRows(): string {
    if (clients.length === 0) return '<p class="meta">No OAuth clients connected.</p>';
    return clients
      .map(
        (g) => `<div class="card" style="padding:10px 14px;margin:6px 0">
          <p><strong>${escapeHtml(g.clientName || g.clientId)}</strong></p>
          <p class="meta">${escapeHtml(g.clientUri || "")} · Scope: ${escapeHtml(g.scope)} · Created ${new Date(g.createdAt).toLocaleDateString()}</p>
          ${g.lastUsedAt ? `<p class="meta">Last used: ${new Date(g.lastUsedAt).toLocaleString()}</p>` : ""}
        </div>`,
      )
      .join("");
  }

  return c.html(
    page("OAuth Clients", `
    <h1>OAuth Clients</h1>
    ${clientRows()}
    <p class="meta"><a href="/auth/status">Back to status</a></p>
  `),
  );
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
        status:    "GET /auth/status",
        logout:    "GET /auth/logout",
        session:   "DELETE /auth/session",
        apiKeys:   "GET /auth/api-keys · POST /auth/api-keys · DELETE /auth/api-keys/:id",
        clients:   "GET /auth/clients",
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

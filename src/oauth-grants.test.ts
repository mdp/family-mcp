import { describe, expect, it } from "vitest";
import { Hono } from "hono";
import { registerOAuthRoutes } from "./oauth.js";
import {
  MemoryStorage,
  saveOAuthClient,
  saveOAuthGrant,
  saveRefreshToken,
  getRefreshTokenRecord,
} from "./storage.js";
import type { Env } from "./env.js";
import type { OAuthClientGrant, RegisteredClient } from "./types.js";
import { resolveAuth, signJWT } from "./auth.js";
import worker from "./index.js";

const secret = "test-secret-that-is-long-enough";

function envWithStorage(storage: MemoryStorage): Env {
  return {
    TOKENS_KV: storage as unknown as KVNamespace,
    STATE_KV: new MemoryStorage() as unknown as KVNamespace,
    GOOGLE_CLIENT_ID: "google-client-id",
    GOOGLE_CLIENT_SECRET: "google-client-secret",
    JWT_SECRET: secret,
    ALLOWED_EMAILS: "adult@example.com",
    FAMILY_MEMBERS: "[]",
    MCP_RATE_LIMITER: {
      limit: async () => ({ success: true }),
    },
  } as Env;
}

function grant(overrides: Partial<OAuthClientGrant> = {}): OAuthClientGrant {
  const now = Date.now();
  return {
    grantId: "grant-1",
    email: "adult@example.com",
    clientId: "client-1",
    clientName: "Claude Code",
    clientUri: "https://claude.ai",
    scope: "mcp:tools",
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
}

function client(overrides: Partial<RegisteredClient> = {}): RegisteredClient {
  return {
    client_id: "client-1",
    client_id_issued_at: Math.floor(Date.now() / 1000),
    redirect_uris: ["http://localhost:1234/callback"],
    client_name: "Claude Code",
    client_uri: "https://claude.ai",
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    ...overrides,
  };
}

async function sha256Hex(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hash), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function refreshTokenRequest(
  app: Hono<{ Bindings: Env }>,
  storage: MemoryStorage,
  refreshToken: string,
  clientId = "client-1",
): Promise<Response> {
  return app.request(
    "https://family-mcp.example/token",
    {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: clientId,
      }),
    },
    envWithStorage(storage),
  );
}

describe("OAuth refresh token rotation", () => {
  it("advertises refresh-token support", async () => {
    const app = new Hono<{ Bindings: Env }>();
    registerOAuthRoutes(app, new MemoryStorage(), new MemoryStorage());

    const response = await app.request("https://family-mcp.example/.well-known/oauth-authorization-server");

    await expect(response.json()).resolves.toMatchObject({
      grant_types_supported: ["authorization_code", "refresh_token"],
      token_endpoint_auth_methods_supported: ["none"],
    });
  });

  it("refreshes legacy plain refresh-token records", async () => {
    const app = new Hono<{ Bindings: Env }>();
    const storage = new MemoryStorage();
    const refreshToken = "legacy-refresh-token";
    registerOAuthRoutes(app, storage, new MemoryStorage());
    await Promise.all([
      saveOAuthClient(storage, client()),
      saveOAuthGrant(storage, grant()),
      storage.put(`mcp:refresh:${await sha256Hex(refreshToken)}`, "grant-1"),
    ]);

    const response = await refreshTokenRequest(app, storage, refreshToken);

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      refresh_token: expect.stringMatching(/^mcp_rt_/),
      token_type: "bearer",
      expires_in: 3600,
      scope: "mcp:tools",
    });
  });

  it("replays duplicate refresh-token submissions with the same token response", async () => {
    const app = new Hono<{ Bindings: Env }>();
    const storage = new MemoryStorage();
    const refreshToken = "overlapping-refresh-token";
    registerOAuthRoutes(app, storage, new MemoryStorage());
    await Promise.all([
      saveOAuthClient(storage, client()),
      saveOAuthGrant(storage, grant()),
      saveRefreshToken(storage, await sha256Hex(refreshToken), "grant-1"),
    ]);

    const firstResponse = await refreshTokenRequest(app, storage, refreshToken);
    const firstBody = await firstResponse.json();
    const secondResponse = await refreshTokenRequest(app, storage, refreshToken);
    const secondBody = await secondResponse.json();

    expect(firstResponse.status).toBe(200);
    expect(secondResponse.status).toBe(200);
    expect(secondBody).toEqual(firstBody);
  });

  it("handles concurrent refresh of the same token with a single rotation", async () => {
    const app = new Hono<{ Bindings: Env }>();
    const storage = new MemoryStorage();
    const refreshToken = "concurrent-refresh-token";
    registerOAuthRoutes(app, storage, new MemoryStorage());
    await Promise.all([
      saveOAuthClient(storage, client()),
      saveOAuthGrant(storage, grant()),
      saveRefreshToken(storage, await sha256Hex(refreshToken), "grant-1"),
    ]);

    const responses = await Promise.all([
      refreshTokenRequest(app, storage, refreshToken),
      refreshTokenRequest(app, storage, refreshToken),
      refreshTokenRequest(app, storage, refreshToken),
    ]);

    const bodies = await Promise.all(responses.map((r) => r.json()));
    expect(responses.every((r) => r.status === 200)).toBe(true);
    expect(bodies[1]).toEqual(bodies[0]);
    expect(bodies[2]).toEqual(bodies[0]);

    const newRt = (bodies[0] as { refresh_token: string }).refresh_token;
    const chain = await refreshTokenRequest(app, storage, newRt);
    expect(chain.status).toBe(200);
    const chainBody = (await chain.json()) as { refresh_token: string };
    expect(chainBody.refresh_token).not.toBe(newRt);
  });

  it("rejects replayed refresh-token submissions for the wrong client", async () => {
    const app = new Hono<{ Bindings: Env }>();
    const storage = new MemoryStorage();
    const refreshToken = "wrong-client-refresh-token";
    registerOAuthRoutes(app, storage, new MemoryStorage());
    await Promise.all([
      saveOAuthClient(storage, client()),
      saveOAuthClient(storage, client({ client_id: "client-2" })),
      saveOAuthGrant(storage, grant()),
      saveRefreshToken(storage, await sha256Hex(refreshToken), "grant-1"),
    ]);

    const firstResponse = await refreshTokenRequest(app, storage, refreshToken);
    const secondResponse = await refreshTokenRequest(app, storage, refreshToken, "client-2");

    expect(firstResponse.status).toBe(200);
    expect(secondResponse.status).toBe(400);
    await expect(secondResponse.json()).resolves.toMatchObject({
      error: "invalid_grant",
    });
  });

  it("allows newly issued refresh tokens to refresh later", async () => {
    const app = new Hono<{ Bindings: Env }>();
    const storage = new MemoryStorage();
    const refreshToken = "chainable-refresh-token";
    registerOAuthRoutes(app, storage, new MemoryStorage());
    await Promise.all([
      saveOAuthClient(storage, client()),
      saveOAuthGrant(storage, grant()),
      saveRefreshToken(storage, await sha256Hex(refreshToken), "grant-1"),
    ]);

    const firstResponse = await refreshTokenRequest(app, storage, refreshToken);
    const firstBody = (await firstResponse.json()) as { refresh_token: string };
    const secondResponse = await refreshTokenRequest(app, storage, firstBody.refresh_token);
    const secondBody = (await secondResponse.json()) as { refresh_token: string };

    expect(firstResponse.status).toBe(200);
    expect(secondResponse.status).toBe(200);
    expect(secondBody.refresh_token).toMatch(/^mcp_rt_/);
    expect(secondBody.refresh_token).not.toBe(firstBody.refresh_token);
  });

  it("marks the previous refresh token as rotated after success", async () => {
    const app = new Hono<{ Bindings: Env }>();
    const storage = new MemoryStorage();
    const refreshToken = "mark-rotated-token";
    registerOAuthRoutes(app, storage, new MemoryStorage());
    const hash = await sha256Hex(refreshToken);
    await Promise.all([
      saveOAuthClient(storage, client()),
      saveOAuthGrant(storage, grant()),
      saveRefreshToken(storage, hash, "grant-1"),
    ]);

    const response = await refreshTokenRequest(app, storage, refreshToken);
    expect(response.status).toBe(200);
    const body = (await response.json()) as { refresh_token: string; access_token: string };

    const record = await getRefreshTokenRecord(storage, hash);
    expect(record?.status).toBe("rotated");
    if (record?.status === "rotated") {
      expect(record.response.refresh_token).toBe(body.refresh_token);
      expect(record.response.access_token).toBe(body.access_token);
    }
  });

  it("accepts legacy JWTs without a grantId", async () => {
    const storage = new MemoryStorage();
    const jwt = await signJWT({ email: "adult@example.com", authMethod: "oauth" }, secret);
    const request = new Request("https://family-mcp.example/mcp", {
      headers: { Authorization: `Bearer ${jwt}` },
    });
    const auth = await resolveAuth(request, secret, storage);
    expect(auth?.email).toBe("adult@example.com");
    expect(auth?.grantId).toBeUndefined();
  });

  it("rejects JWTs when grant is missing or mismatched", async () => {
    const storage = new MemoryStorage();
    const jwt = await signJWT(
      {
        email: "adult@example.com",
        authMethod: "oauth",
        clientId: "client-1",
        grantId: "missing-grant",
      },
      secret,
    );
    const request = new Request("https://family-mcp.example/mcp", {
      headers: { Authorization: `Bearer ${jwt}` },
    });
    expect(await resolveAuth(request, secret, storage)).toBeNull();
  });
});

describe("MCP unauthorized responses", () => {
  it("includes WWW-Authenticate resource_metadata on unauthenticated /mcp", async () => {
    const storage = new MemoryStorage();
    const env = envWithStorage(storage);
    const response = await worker.fetch(
      new Request("https://family-mcp.example/mcp", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", method: "ping", id: 1 }),
      }),
      env,
      { waitUntil() {}, passThroughOnException() {}, props: {} } as unknown as ExecutionContext,
    );

    expect(response.status).toBe(401);
    const www = response.headers.get("WWW-Authenticate") ?? "";
    expect(www.toLowerCase()).toContain("bearer");
    expect(www).toContain("resource_metadata=");
    expect(www).toContain("https://family-mcp.example/.well-known/oauth-protected-resource");
  });
});

import type { Hono } from "hono";
import type { Env } from "./env.js";
import type { Storage } from "./storage.js";
import {
  getOAuthClient,
  getOAuthGrant,
  getOAuthGrantForClient,
  getRefreshTokenRecord,
  saveOAuthClient,
  saveOAuthGrant,
  saveRefreshToken,
  saveRotatedRefreshToken,
  saveTokens,
  saveUserInfo,
  tryClaimRefreshTokenRotation,
  waitForRotatedRefreshToken,
} from "./storage.js";
import { signJWT, makeSessionCookie } from "./auth.js";
import { isAllowedEmail } from "./access-policy.js";
import type { OAuthTokenResponse } from "./storage.js";
import type { GoogleTokens, GoogleUserInfo, OAuthClientGrant, RegisteredClient } from "./types.js";

// ─── Constants ────────────────────────────────────────────────────────────────

const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo";
const OAUTH_STATE_TTL_SECONDS = 10 * 60;
const MCP_AUTH_CODE_TTL_SECONDS = 5 * 60;
/** How long a rotated RT may still be replayed (delayed retries / multi-instance clients). */
const REFRESH_TOKEN_GRACE_TTL_SECONDS = 24 * 60 * 60;
/** Keep an active RT usable for up to 90 days of offline / no refresh. */
const REFRESH_TOKEN_TTL_SECONDS = 90 * 24 * 60 * 60;

const GOOGLE_SCOPES = [
  "openid",
  "email",
  "profile",
  "https://www.googleapis.com/auth/gmail.modify",
  "https://www.googleapis.com/auth/gmail.send",
  "https://www.googleapis.com/auth/calendar",
  "https://www.googleapis.com/auth/drive",
].join(" ");

// ─── Internal types ───────────────────────────────────────────────────────────

type OAuthState =
  | { type: "direct" }
  | {
      type: "mcp";
      clientId: string;
      redirectUri: string;
      codeChallenge: string;
      codeChallengeMethod: string;
      clientState?: string;
      scope?: string;
    };

type AuthCodeData = {
  email: string;
  clientId: string;
  scope: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: string;
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function htmlPage(title: string, body: string): string {
  return `<!DOCTYPE html>
<html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title} — family-mcp</title>
<style>
  body{font-family:system-ui,sans-serif;max-width:480px;margin:80px auto;padding:0 20px;color:#333}
  h1{font-size:1.4em}a{color:#2563eb}
  pre{background:#f5f5f5;padding:12px;border-radius:6px;overflow-x:auto;font-size:0.85em}
  .btn{display:inline-block;padding:9px 18px;background:#2563eb;color:#fff;border-radius:6px;text-decoration:none;font-size:0.9em}
</style>
</head><body><h1>${title}</h1>${body}</body></html>`;
}

function baseUrl(reqUrl: string): string {
  const u = new URL(reqUrl);
  return `${u.protocol}//${u.host}`;
}

function callbackUrl(reqUrl: string): string {
  const u = new URL(reqUrl);
  u.pathname = "/oauth/callback";
  u.search = "";
  return u.toString();
}

function parseOAuthState(raw: string): OAuthState {
  if (raw === "pending") return { type: "direct" };
  try {
    return JSON.parse(raw) as OAuthState;
  } catch {
    return { type: "direct" };
  }
}

async function pkceChallenge(verifier: string): Promise<string> {
  const data = new TextEncoder().encode(verifier);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function randomToken(prefix: string): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return `${prefix}_${Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")}`;
}

async function sha256Hex(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hash), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function issueOAuthTokens(
  storage: Storage,
  env: Env,
  grant: OAuthClientGrant,
): Promise<OAuthTokenResponse> {
  const refreshToken = randomToken("mcp_rt");
  const now = Date.now();
  const updatedGrant = {
    ...grant,
    updatedAt: now,
    lastUsedAt: now,
  };
  await Promise.all([
    saveOAuthGrant(storage, updatedGrant),
    saveRefreshToken(storage, await sha256Hex(refreshToken), grant.grantId, {
      expirationTtl: REFRESH_TOKEN_TTL_SECONDS,
    }),
  ]);

  const accessToken = await signJWT(
    {
      email: grant.email,
      authMethod: "oauth",
      clientId: grant.clientId,
      grantId: grant.grantId,
    },
    env.JWT_SECRET,
    "1h",
  );

  return {
    access_token: accessToken,
    refresh_token: refreshToken,
    token_type: "bearer",
    expires_in: 60 * 60,
    scope: grant.scope,
  };
}

/**
 * Rotate a refresh token with single-flight + grace-period replay.
 * Concurrent / delayed retries of the same RT return the same token set.
 */
async function rotateRefreshToken(
  storage: Storage,
  env: Env,
  refreshTokenHash: string,
  grant: OAuthClientGrant,
): Promise<OAuthTokenResponse | { error: "invalid_grant" | "temporarily_unavailable"; description: string }> {
  // Fast path: already rotated (grace play).
  const existing = await getRefreshTokenRecord(storage, refreshTokenHash);
  if (!existing) {
    return { error: "invalid_grant", description: "Invalid or expired refresh token" };
  }
  if (existing.status === "rotated") {
    return existing.response;
  }

  const ownerId = crypto.randomUUID();
  const claim = await tryClaimRefreshTokenRotation(
    storage,
    refreshTokenHash,
    grant.grantId,
    ownerId,
    { expirationTtl: REFRESH_TOKEN_GRACE_TTL_SECONDS },
  );

  if (claim === "missing") {
    return { error: "invalid_grant", description: "Invalid or expired refresh token" };
  }

  if (claim === "lost") {
    // Another worker is rotating (or already finished). Wait for the result.
    const waited = await waitForRotatedRefreshToken(storage, refreshTokenHash, {
      timeoutMs: 5_000,
      pollMs: 25,
    });
    if (waited) return waited;

    // Still rotating or became active again — one more read.
    const latest = await getRefreshTokenRecord(storage, refreshTokenHash);
    if (latest?.status === "rotated") return latest.response;
    if (latest?.status === "active") {
      // Stale claim abandoned without finishing; try once more as winner.
      const retryOwner = crypto.randomUUID();
      const retryClaim = await tryClaimRefreshTokenRotation(
        storage,
        refreshTokenHash,
        grant.grantId,
        retryOwner,
        { expirationTtl: REFRESH_TOKEN_GRACE_TTL_SECONDS },
      );
      if (retryClaim === "won") {
        const response = await issueOAuthTokens(storage, env, grant);
        await saveRotatedRefreshToken(storage, refreshTokenHash, grant.grantId, response, {
          expirationTtl: REFRESH_TOKEN_GRACE_TTL_SECONDS,
        });
        return response;
      }
      const waitedAgain = await waitForRotatedRefreshToken(storage, refreshTokenHash, {
        timeoutMs: 3_000,
        pollMs: 25,
      });
      if (waitedAgain) return waitedAgain;
    }
    return {
      error: "temporarily_unavailable",
      description: "Refresh token rotation in progress; retry shortly",
    };
  }

  // We own the claim.
  try {
    // Re-check after claim in case a peer finished first and overwrote us.
    const afterClaim = await getRefreshTokenRecord(storage, refreshTokenHash);
    if (afterClaim?.status === "rotated") {
      return afterClaim.response;
    }
    if (afterClaim?.status === "rotating" && afterClaim.ownerId !== ownerId) {
      const waited = await waitForRotatedRefreshToken(storage, refreshTokenHash, {
        timeoutMs: 5_000,
        pollMs: 25,
      });
      if (waited) return waited;
      return {
        error: "temporarily_unavailable",
        description: "Refresh token rotation in progress; retry shortly",
      };
    }

    const response = await issueOAuthTokens(storage, env, grant);
    await saveRotatedRefreshToken(storage, refreshTokenHash, grant.grantId, response, {
      expirationTtl: REFRESH_TOKEN_GRACE_TTL_SECONDS,
    });
    return response;
  } catch (error) {
    // Release claim so another request can retry (best-effort restore to active).
    console.error(`Refresh rotation failed for grant=${grant.grantId}: ${error}`);
    const stillOurs = await getRefreshTokenRecord(storage, refreshTokenHash);
    if (stillOurs?.status === "rotating" && stillOurs.ownerId === ownerId) {
      await saveRefreshToken(storage, refreshTokenHash, grant.grantId, {
        expirationTtl: REFRESH_TOKEN_TTL_SECONDS,
      });
    }
    return {
      error: "temporarily_unavailable",
      description: "Token refresh failed; retry shortly",
    };
  }
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

function corsAllowOrigin(origin: string | null): string | null {
  if (!origin) return null;
  let u: URL;
  try {
    u = new URL(origin);
  } catch {
    return null;
  }
  if (u.protocol === "https:") return origin;
  if (u.protocol === "http:" && LOOPBACK_HOSTS.has(u.hostname)) return origin;
  return null;
}

function setCors(c: { req: { header: (k: string) => string | undefined }; header: (k: string, v: string) => void }): void {
  const allow = corsAllowOrigin(c.req.header("origin") ?? null);
  if (allow) {
    c.header("Access-Control-Allow-Origin", allow);
    c.header("Vary", "Origin");
  }
}

export function validateRedirectUri(uri: string): { ok: true } | { ok: false; reason: string } {
  if (typeof uri !== "string" || uri.length === 0) {
    return { ok: false, reason: "redirect_uri must be a non-empty string" };
  }
  if (uri.length > 2048) {
    return { ok: false, reason: "redirect_uri exceeds 2048 characters" };
  }
  let u: URL;
  try {
    u = new URL(uri);
  } catch {
    return { ok: false, reason: "redirect_uri is not a valid URL" };
  }
  if (u.hash !== "") {
    return { ok: false, reason: "redirect_uri must not contain a fragment" };
  }
  if (u.protocol === "https:") return { ok: true };
  if (u.protocol === "http:" && LOOPBACK_HOSTS.has(u.hostname)) return { ok: true };
  return { ok: false, reason: "redirect_uri must use https:// or http:// loopback (localhost/127.0.0.1/[::1])" };
}

// ─── OAuth route registration ──────────────────────────────────────────────────

export function registerOAuthRoutes(
  app: Hono<{ Bindings: Env }>,
  tokensStorage: Storage,
  stateStorage: Storage,
): void {

  // ── RFC 8414 / RFC 9728 discovery ──────────────────────────────────────────

  app.get("/.well-known/oauth-authorization-server", (c) => {
    const base = baseUrl(c.req.url);
    c.header("Access-Control-Allow-Origin", "*");
    return c.json({
      issuer: base,
      authorization_endpoint: `${base}/authorize`,
      token_endpoint: `${base}/token`,
      registration_endpoint: `${base}/register`,
      response_types_supported: ["code"],
      code_challenge_methods_supported: ["S256"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      token_endpoint_auth_methods_supported: ["none"],
      scopes_supported: ["mcp:tools"],
    });
  });

  app.get("/.well-known/oauth-protected-resource", (c) => {
    const base = baseUrl(c.req.url);
    c.header("Access-Control-Allow-Origin", "*");
    return c.json({
      resource: base,
      authorization_servers: [base],
      scopes_supported: ["mcp:tools"],
    });
  });

  // ── Dynamic client registration (RFC 7591) ─────────────────────────────────

  app.options("/register", (c) => {
    setCors(c);
    c.header("Access-Control-Allow-Methods", "POST, OPTIONS");
    c.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
    return c.body(null, 204);
  });

  app.post("/register", async (c) => {
    setCors(c);
    c.header("Cache-Control", "no-store");

    let body: Record<string, unknown>;
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "invalid_client_metadata", error_description: "Invalid JSON body" }, 400);
    }

    const redirectUris = body["redirect_uris"];
    if (
      !Array.isArray(redirectUris) ||
      redirectUris.length === 0 ||
      !redirectUris.every((u) => typeof u === "string")
    ) {
      return c.json({ error: "invalid_client_metadata", error_description: "redirect_uris is required" }, 400);
    }
    for (const uri of redirectUris as string[]) {
      const check = validateRedirectUri(uri);
      if (!check.ok) {
        return c.json({ error: "invalid_redirect_uri", error_description: check.reason }, 400);
      }
    }

    const clientId = crypto.randomUUID();
    const issuedAt = Math.floor(Date.now() / 1000);
    const authMethod = body["token_endpoint_auth_method"];
    if (authMethod && authMethod !== "none") {
      return c.json({
        error: "invalid_client_metadata",
        error_description: "Only public PKCE clients with token_endpoint_auth_method=none are supported",
      }, 400);
    }

    const client: RegisteredClient = {
      client_id: clientId,
      client_id_issued_at: issuedAt,
      redirect_uris: redirectUris as string[],
      ...(typeof body["client_name"] === "string" ? { client_name: body["client_name"] } : {}),
      ...(typeof body["client_uri"] === "string" ? { client_uri: body["client_uri"] } : {}),
      token_endpoint_auth_method: "none",
      grant_types: Array.isArray(body["grant_types"])
        ? (body["grant_types"] as string[])
        : ["authorization_code", "refresh_token"],
      response_types: Array.isArray(body["response_types"])
        ? (body["response_types"] as string[])
        : ["code"],
    };

    await saveOAuthClient(tokensStorage, client);

    return c.json(client, 201);
  });

  // ── /authorize — MCP OAuth AS authorization endpoint ──────────────────────

  app.get("/authorize", async (c) => {
    const responseType = c.req.query("response_type");
    const clientId = c.req.query("client_id");
    const redirectUri = c.req.query("redirect_uri");
    const codeChallenge = c.req.query("code_challenge");
    const codeChallengeMethod = c.req.query("code_challenge_method") ?? "S256";
    const clientState = c.req.query("state");
    const scope = c.req.query("scope");

    if (responseType !== "code") {
      return c.html(htmlPage("Error", "<p>Only <code>response_type=code</code> is supported.</p>"), 400);
    }
    if (!clientId) {
      return c.html(htmlPage("Error", "<p>Missing <code>client_id</code>.</p>"), 400);
    }
    if (!redirectUri) {
      return c.html(htmlPage("Error", "<p>Missing <code>redirect_uri</code>.</p>"), 400);
    }
    if (!codeChallenge) {
      return c.html(htmlPage("Error", "<p>Missing <code>code_challenge</code> (PKCE required).</p>"), 400);
    }

    const registeredClient = await getOAuthClient(tokensStorage, clientId);
    if (!registeredClient) {
      return c.html(htmlPage("Error", "<p>Unknown <code>client_id</code>.</p>"), 400);
    }
    if (!registeredClient.redirect_uris.includes(redirectUri)) {
      return c.html(htmlPage("Error", "<p><code>redirect_uri</code> is not registered for this client.</p>"), 400);
    }
    if (codeChallengeMethod !== "S256") {
      return c.html(htmlPage("Error", "<p>Only <code>code_challenge_method=S256</code> is supported.</p>"), 400);
    }

    const googleState = crypto.randomUUID();
    const mcpStatePayload: OAuthState = {
      type: "mcp",
      clientId,
      redirectUri,
      codeChallenge,
      codeChallengeMethod,
      ...(clientState ? { clientState } : {}),
      scope: scope || "mcp:tools",
    };
    await stateStorage.put(`oauth:state:${googleState}`, JSON.stringify(mcpStatePayload), {
      expirationTtl: OAUTH_STATE_TTL_SECONDS,
    });

    const googleUrl = new URL(GOOGLE_AUTH_URL);
    googleUrl.searchParams.set("client_id", c.env.GOOGLE_CLIENT_ID);
    googleUrl.searchParams.set("redirect_uri", callbackUrl(c.req.url));
    googleUrl.searchParams.set("response_type", "code");
    googleUrl.searchParams.set("scope", GOOGLE_SCOPES);
    googleUrl.searchParams.set("state", googleState);
    googleUrl.searchParams.set("access_type", "offline");
    googleUrl.searchParams.set("prompt", "consent");
    return c.redirect(googleUrl.toString(), 302);
  });

  // ── /token — MCP OAuth AS token endpoint ──────────────────────────────────

  app.options("/token", (c) => {
    setCors(c);
    c.header("Access-Control-Allow-Methods", "POST, OPTIONS");
    c.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
    return c.body(null, 204);
  });

  app.post("/token", async (c) => {
    setCors(c);
    c.header("Cache-Control", "no-store");

    const rawBody = await c.req.parseBody().catch(() => ({}) as Record<string, string | File>);
    const str = (k: string) => (typeof rawBody[k] === "string" ? (rawBody[k] as string) : undefined);
    const grantType = str("grant_type");

    if (grantType === "refresh_token") {
      const refreshToken = str("refresh_token");
      const clientId = str("client_id");
      if (!refreshToken || !clientId) {
        return c.json({ error: "invalid_request", error_description: "Missing refresh_token or client_id" }, 400);
      }

      const refreshTokenHash = await sha256Hex(refreshToken);
      const refreshRecord = await getRefreshTokenRecord(tokensStorage, refreshTokenHash);
      if (!refreshRecord) {
        return c.json({ error: "invalid_grant", error_description: "Invalid or expired refresh token" }, 400);
      }
      const grant = await getOAuthGrant(tokensStorage, refreshRecord.grantId);
      if (!grant || grant.clientId !== clientId) {
        return c.json({ error: "invalid_grant", error_description: "Client grant not found" }, 400);
      }

      // Grace-period replay for an already-rotated RT (delayed retries).
      if (refreshRecord.status === "rotated") {
        return c.json(refreshRecord.response);
      }

      const result = await rotateRefreshToken(tokensStorage, c.env, refreshTokenHash, grant);
      if ("error" in result) {
        const status = result.error === "temporarily_unavailable" ? 503 : 400;
        return c.json(
          { error: result.error, error_description: result.description },
          status,
          result.error === "temporarily_unavailable" ? { "Retry-After": "1" } : undefined,
        );
      }
      return c.json(result);
    }

    if (grantType !== "authorization_code") {
      return c.json({ error: "unsupported_grant_type" }, 400);
    }

    const code = str("code");
    const redirectUri = str("redirect_uri");
    const codeVerifier = str("code_verifier");
    const clientId = str("client_id");

    if (!code || !redirectUri || !codeVerifier || !clientId) {
      return c.json(
        { error: "invalid_request", error_description: "Missing required parameters" },
        400,
      );
    }

    const codeJson = await stateStorage.get(`mcp:code:${code}`);
    if (!codeJson) {
      return c.json(
        { error: "invalid_grant", error_description: "Invalid or expired authorization code" },
        400,
      );
    }
    await stateStorage.delete(`mcp:code:${code}`);

    const codeData = JSON.parse(codeJson) as AuthCodeData;

    if (codeData.clientId !== clientId) {
      return c.json({ error: "invalid_grant", error_description: "client_id mismatch" }, 400);
    }
    if (codeData.redirectUri !== redirectUri) {
      return c.json({ error: "invalid_grant", error_description: "redirect_uri mismatch" }, 400);
    }

    const computed = await pkceChallenge(codeVerifier);
    if (computed !== codeData.codeChallenge) {
      return c.json(
        { error: "invalid_grant", error_description: "code_verifier does not match code_challenge" },
        400,
      );
    }

    const client = await getOAuthClient(tokensStorage, clientId);
    if (!client) {
      return c.json({ error: "invalid_client", error_description: "Unknown client_id" }, 400);
    }

    const existingGrant = await getOAuthGrantForClient(tokensStorage, codeData.email, clientId);
    const grant: OAuthClientGrant = existingGrant ?? {
      grantId: crypto.randomUUID(),
      email: codeData.email,
      clientId,
      clientName: client.client_name,
      clientUri: client.client_uri,
      scope: codeData.scope || "mcp:tools",
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };

    return c.json(await issueOAuthTokens(tokensStorage, c.env, grant));
  });

  // ── /oauth/authorize — direct browser login via Google ────────────────────

  app.get("/oauth/authorize", async (c) => {
    const state = crypto.randomUUID();
    await stateStorage.put(
      `oauth:state:${state}`,
      JSON.stringify({ type: "direct" }),
      { expirationTtl: OAUTH_STATE_TTL_SECONDS },
    );

    const url = new URL(GOOGLE_AUTH_URL);
    url.searchParams.set("client_id", c.env.GOOGLE_CLIENT_ID);
    url.searchParams.set("redirect_uri", callbackUrl(c.req.url));
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", GOOGLE_SCOPES);
    url.searchParams.set("state", state);
    url.searchParams.set("access_type", "offline");
    url.searchParams.set("prompt", "consent");
    return c.redirect(url.toString(), 302);
  });

  // ── /oauth/callback — Google OAuth callback (shared by both flows) ─────────

  app.get("/oauth/callback", async (c) => {
    const code = c.req.query("code");
    const state = c.req.query("state");
    const error = c.req.query("error");

    if (error) {
      return c.html(
        htmlPage(
          "Authorization Failed",
          `<p>Google returned an error: <strong>${escapeHtml(error)}</strong></p><p><a href="/oauth/authorize">Try again</a></p>`,
        ),
        400,
      );
    }

    if (!code || !state) {
      return c.html(
        htmlPage("Error", "<p>Missing code or state parameter.</p><p><a href='/oauth/authorize'>Try again</a></p>"),
        400,
      );
    }

    const storedRaw = await stateStorage.get(`oauth:state:${state}`);
    if (!storedRaw) {
      return c.html(
        htmlPage("Error", "<p>Invalid or expired state. Please try again.</p><p><a href='/oauth/authorize'>Try again</a></p>"),
        400,
      );
    }
    await stateStorage.delete(`oauth:state:${state}`);

    const oauthState = parseOAuthState(storedRaw);

    // Exchange Google code for tokens
    const tokenRes = await fetch(GOOGLE_TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        client_id: c.env.GOOGLE_CLIENT_ID,
        client_secret: c.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: callbackUrl(c.req.url),
        grant_type: "authorization_code",
      }),
    });

    if (!tokenRes.ok) {
      const text = await tokenRes.text();
      return c.html(
        htmlPage(
          "Token Exchange Failed",
          `<p>Could not exchange authorization code.</p><pre>${escapeHtml(text)}</pre><p><a href='/oauth/authorize'>Try again</a></p>`,
        ),
        500,
      );
    }

    const rawTokens = (await tokenRes.json()) as {
      access_token: string;
      refresh_token?: string;
      expires_in: number;
      token_type: string;
    };

    if (oauthState.type === "direct" && !rawTokens.refresh_token) {
      return c.html(
        htmlPage(
          "No Refresh Token",
          `<p>Google did not return a refresh token.</p>
           <p>Please <a href="https://myaccount.google.com/permissions" target="_blank">revoke access</a> for this app, then <a href="/oauth/authorize">try again</a>.</p>`,
        ),
        500,
      );
    }

    // Fetch user info
    const userRes = await fetch(GOOGLE_USERINFO_URL, {
      headers: { Authorization: `Bearer ${rawTokens.access_token}` },
    });
    if (!userRes.ok) {
      return c.html(
        htmlPage("Error", "<p>Failed to fetch your Google profile.</p><p><a href='/oauth/authorize'>Try again</a></p>"),
        500,
      );
    }
    const user = (await userRes.json()) as GoogleUserInfo;
    console.log(
      `Google OAuth callback flow=${oauthState.type} email=${user.email} refresh_token=${rawTokens.refresh_token ? "present" : "missing"} expires_in=${rawTokens.expires_in}`,
    );

    // Email whitelist check
    if (!isAllowedEmail(user.email, c.env.ALLOWED_EMAILS)) {
      if (oauthState.type === "mcp") {
        const errUrl = new URL(oauthState.redirectUri);
        errUrl.searchParams.set("error", "access_denied");
        errUrl.searchParams.set("error_description", "Your account is not authorized.");
        if (oauthState.clientState) errUrl.searchParams.set("state", oauthState.clientState);
        return c.redirect(errUrl.toString(), 302);
      }
      return c.html(
        htmlPage(
          "Access Denied",
          `<p>Your account (<strong>${escapeHtml(user.email)}</strong>) is not authorized to use this server.</p>`,
        ),
        403,
      );
    }

    if (oauthState.type === "mcp") {
      await saveUserInfo(tokensStorage, user.email, user);
      if (rawTokens.refresh_token) {
        await saveTokens(tokensStorage, user.email, {
          access_token: rawTokens.access_token,
          refresh_token: rawTokens.refresh_token,
          expires_in: rawTokens.expires_in,
          expiry_date: Date.now() + rawTokens.expires_in * 1000,
          token_type: rawTokens.token_type,
          obtained_at: Date.now(),
        });
      }

      const authCode = crypto.randomUUID();
      const codeData: AuthCodeData = {
        email: user.email,
        clientId: oauthState.clientId,
        scope: oauthState.scope || "mcp:tools",
        redirectUri: oauthState.redirectUri,
        codeChallenge: oauthState.codeChallenge,
        codeChallengeMethod: oauthState.codeChallengeMethod,
      };
      await stateStorage.put(`mcp:code:${authCode}`, JSON.stringify(codeData), {
        expirationTtl: MCP_AUTH_CODE_TTL_SECONDS,
      });

      const redirectUrl = new URL(oauthState.redirectUri);
      redirectUrl.searchParams.set("code", authCode);
      if (oauthState.clientState) {
        redirectUrl.searchParams.set("state", oauthState.clientState);
      }
      return c.redirect(redirectUrl.toString(), 302);
    }

    // Direct browser flow: save tokens + set session cookie.
    await Promise.all([
      saveTokens(tokensStorage, user.email, {
        access_token: rawTokens.access_token,
        refresh_token: rawTokens.refresh_token!,
        expires_in: rawTokens.expires_in,
        expiry_date: Date.now() + rawTokens.expires_in * 1000,
        token_type: rawTokens.token_type,
        obtained_at: Date.now(),
      }),
      saveUserInfo(tokensStorage, user.email, user),
    ]);

    const jwt = await signJWT({ email: user.email, authMethod: "oauth" }, c.env.JWT_SECRET);
    const isSecure = new URL(c.req.url).protocol === "https:";
    c.header("Set-Cookie", makeSessionCookie(jwt, isSecure));

    return c.html(
      htmlPage(
        "Signed In",
        `<p>Welcome, <strong>${escapeHtml(user.name)}</strong>!</p>
         <p>Signed in as <strong>${escapeHtml(user.email)}</strong>.</p>
         <p><a class="btn" href="/auth/status">View Status</a></p>`,
      ),
    );
  });
}

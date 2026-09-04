import { SignJWT, jwtVerify } from "jose";
import type { JWTPayload } from "./types.js";
import type { Storage } from "./storage.js";
import { getOAuthGrant, getApiKeyByHash, touchApiKeyLastUsed, touchOAuthGrantLastUsed } from "./storage.js";
import type { ApiKey, OAuthClientGrant } from "./types.js";

// ─── JWT ──────────────────────────────────────────────────────────────────────

const JWT_ALGORITHM = "HS256";
const JWT_EXPIRY = "90d";

function jwtSecretKey(secret: string): Uint8Array {
  return new TextEncoder().encode(secret);
}

export async function signJWT(payload: JWTPayload, secret: string, expiresIn = JWT_EXPIRY): Promise<string> {
  return new SignJWT({
    email: payload.email,
    authMethod: payload.authMethod ?? "oauth",
    ...(payload.clientId ? { clientId: payload.clientId } : {}),
    ...(payload.grantId ? { grantId: payload.grantId } : {}),
  })
    .setProtectedHeader({ alg: JWT_ALGORITHM })
    .setIssuedAt()
    .setExpirationTime(expiresIn)
    .sign(jwtSecretKey(secret));
}

export async function verifyJWT(token: string, secret: string): Promise<JWTPayload | null> {
  try {
    const { payload } = await jwtVerify(token, jwtSecretKey(secret));
    if (typeof payload.email !== "string") return null;
    return {
      email: payload.email,
      authMethod: typeof payload.authMethod === "string" ? (payload.authMethod as JWTPayload["authMethod"]) : "oauth",
      clientId: typeof payload.clientId === "string" ? payload.clientId : undefined,
      grantId: typeof payload.grantId === "string" ? payload.grantId : undefined,
      iat: payload.iat,
      exp: payload.exp,
    };
  } catch {
    return null;
  }
}

// ─── Cookie helpers ───────────────────────────────────────────────────────────

export const JWT_COOKIE_NAME = "mcp_session";

export function makeSessionCookie(token: string, secure: boolean): string {
  const parts = [
    `${JWT_COOKIE_NAME}=${token}`,
    "HttpOnly",
    "SameSite=Lax",
    "Path=/",
    "Max-Age=7776000",
  ];
  if (secure) parts.push("Secure");
  return parts.join("; ");
}

export function clearSessionCookie(secure: boolean): string {
  const parts = [
    `${JWT_COOKIE_NAME}=`,
    "HttpOnly",
    "SameSite=Lax",
    "Path=/",
    "Max-Age=0",
  ];
  if (secure) parts.push("Secure");
  return parts.join("; ");
}

export function getJWTFromRequest(request: Request): string | null {
  const cookieHeader = request.headers.get("cookie") ?? "";
  for (const part of cookieHeader.split(";")) {
    const [name, ...rest] = part.trim().split("=");
    if (name === JWT_COOKIE_NAME) return rest.join("=");
  }
  const auth = request.headers.get("authorization");
  if (auth?.startsWith("Bearer ")) return auth.slice(7);
  return null;
}

// ─── API Key support ──────────────────────────────────────────────────────────

/** API keys created by this server are prefixed with `mcp_sk_`. */
export const API_KEY_PREFIX = "mcp_sk_";

export function isApiKeyToken(token: string): boolean {
  return token.startsWith(API_KEY_PREFIX);
}

async function sha256Hex(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hash), (b) => b.toString(16).padStart(2, "0")).join("");
}

// ─── Auth resolution ──────────────────────────────────────────────────────────

// ── KV usage throttling ──────────────────────────────────────────────────────
// Auth resolution runs on every request. To keep KV operations (especially
// writes) to a minimum, repeated lookups are served from isolate memory and
// last-used timestamps are persisted at most once per interval (see
// storage.ts). Revocations therefore take up to LOOKUP_CACHE_TTL_MS to be
// observed within a warm isolate, which is acceptable here.
const LOOKUP_CACHE_TTL_MS = 60_000;
const apiKeyCache = new Map<string, { value: ApiKey | null; at: number }>();
const grantCache = new Map<string, { value: OAuthClientGrant | null; at: number }>();

function cachedLookup<T>(map: Map<string, { value: T; at: number }>, key: string): T | undefined {
  const entry = map.get(key);
  if (!entry) return undefined;
  if (Date.now() - entry.at > LOOKUP_CACHE_TTL_MS) {
    map.delete(key);
    return undefined;
  }
  return entry.value;
}

export async function resolveAuth(
  request: Request,
  jwtSecret: string,
  storage?: Storage,
  ctx?: { waitUntil(promise: Promise<unknown>): void },
): Promise<{ email: string; authMethod?: "oauth" | "api_key"; clientId?: string; grantId?: string } | null> {
  const token = getJWTFromRequest(request);
  if (!token) return null;

  // ── API Key path ─────────────────────────────────────────────────────────
  if (isApiKeyToken(token) && storage) {
    const tokenHash = await sha256Hex(token);
    let apiKey = cachedLookup(apiKeyCache, tokenHash);
    if (apiKey === undefined) {
      apiKey = await getApiKeyByHash(storage, tokenHash);
      apiKeyCache.set(tokenHash, { value: apiKey, at: Date.now() });
    }
    if (!apiKey || apiKey.revokedAt) return null;
    const update = touchApiKeyLastUsed(storage, apiKey);
    if (ctx) ctx.waitUntil(update);
    return {
      email: apiKey.email,
      authMethod: "api_key",
    };
  }

  // ── JWT path ─────────────────────────────────────────────────────────────
  const payload = await verifyJWT(token, jwtSecret);
  if (!payload) return null;
  if (payload.grantId && storage) {
    let grant = cachedLookup(grantCache, payload.grantId);
    if (grant === undefined) {
      grant = await getOAuthGrant(storage, payload.grantId);
      grantCache.set(payload.grantId, { value: grant, at: Date.now() });
    }
    if (!grant || grant.email !== payload.email || grant.clientId !== payload.clientId) return null;
    const update = touchOAuthGrantLastUsed(storage, grant);
    if (ctx) ctx.waitUntil(update);
  }
  return {
    email: payload.email,
    authMethod: payload.authMethod,
    clientId: payload.clientId,
    grantId: payload.grantId,
  };
}

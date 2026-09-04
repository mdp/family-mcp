import type { GoogleTokens, GoogleUserInfo, OAuthClientGrant, RegisteredClient, ApiKey } from "./types.js";

// ─── Storage Interface ────────────────────────────────────────────────────────

export interface Storage {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
  list(options: { prefix: string }): Promise<{ keys: { name: string }[] }>;
}

export type OAuthTokenResponse = {
  access_token: string;
  refresh_token: string;
  token_type: "bearer";
  expires_in: number;
  scope: string;
};

export type OAuthRefreshTokenRecord =
  | { status: "active"; grantId: string }
  | { status: "rotating"; grantId: string; ownerId: string; startedAt: number }
  | { status: "rotated"; grantId: string; response: OAuthTokenResponse; rotatedAt: number };

/** How long a stuck "rotating" claim may be stolen by another request. */
export const REFRESH_ROTATION_STALE_MS = 10_000;

// ─── Cloudflare KV Storage ────────────────────────────────────────────────────

export class CloudflareKVStorage implements Storage {
  constructor(private kv: KVNamespace) {}

  get(key: string): Promise<string | null> {
    return this.kv.get(key);
  }

  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void> {
    return this.kv.put(key, value, options);
  }

  delete(key: string): Promise<void> {
    return this.kv.delete(key);
  }

  async list(options: { prefix: string }): Promise<{ keys: { name: string }[] }> {
    return this.kv.list(options);
  }
}

// ─── In-Memory Storage (dev / testing) ───────────────────────────────────────

export class MemoryStorage implements Storage {
  private store = new Map<string, { value: string; expiresAt?: number }>();

  async get(key: string): Promise<string | null> {
    const entry = this.store.get(key);
    if (!entry) return null;
    if (entry.expiresAt && Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return null;
    }
    return entry.value;
  }

  async put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void> {
    this.store.set(key, {
      value,
      expiresAt: options?.expirationTtl ? Date.now() + options.expirationTtl * 1000 : undefined,
    });
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  async list(options: { prefix: string }): Promise<{ keys: { name: string }[] }> {
    const keys = [...this.store.keys()]
      .filter((k) => k.startsWith(options.prefix))
      .map((name) => ({ name }));
    return { keys };
  }
}

// ─── Token helpers ────────────────────────────────────────────────────────────

const TOKEN_PREFIX = "google:tokens:";
const USER_INFO_PREFIX = "user-info:";
const OAUTH_CLIENT_PREFIX = "mcp:client:";
const OAUTH_GRANT_PREFIX = "mcp:grant:";
const OAUTH_REFRESH_PREFIX = "mcp:refresh:";
const USER_CLIENT_PREFIX = "mcp:user-client:";
const API_KEY_PREFIX = "mcp:apikey:";
const EMAIL_API_KEYS_PREFIX = "mcp:email-apikeys:";

export async function getTokens(storage: Storage, email: string): Promise<GoogleTokens | null> {
  const data = await storage.get(`${TOKEN_PREFIX}${email}`);
  if (!data) return null;
  return JSON.parse(data) as GoogleTokens;
}

export async function saveTokens(
  storage: Storage,
  email: string,
  tokens: GoogleTokens
): Promise<void> {
  await storage.put(`${TOKEN_PREFIX}${email}`, JSON.stringify(tokens));
}

export async function getUserInfoFromStorage(
  storage: Storage,
  email: string
): Promise<GoogleUserInfo | null> {
  const data = await storage.get(`${USER_INFO_PREFIX}${email}`);
  if (!data) return null;
  return JSON.parse(data) as GoogleUserInfo;
}

export async function saveUserInfo(
  storage: Storage,
  email: string,
  userInfo: GoogleUserInfo
): Promise<void> {
  await storage.put(`${USER_INFO_PREFIX}${email}`, JSON.stringify(userInfo));
}

// ─── MCP OAuth client + grant helpers ────────────────────────────────────────

export async function saveOAuthClient(storage: Storage, client: RegisteredClient): Promise<void> {
  await storage.put(`${OAUTH_CLIENT_PREFIX}${client.client_id}`, JSON.stringify(client));
}

export async function getOAuthClient(storage: Storage, clientId: string): Promise<RegisteredClient | null> {
  const data = await storage.get(`${OAUTH_CLIENT_PREFIX}${clientId}`);
  if (!data) return null;
  return JSON.parse(data) as RegisteredClient;
}

export async function saveOAuthGrant(storage: Storage, grant: OAuthClientGrant): Promise<void> {
  await Promise.all([
    storage.put(`${OAUTH_GRANT_PREFIX}${grant.grantId}`, JSON.stringify(grant)),
    storage.put(`${USER_CLIENT_PREFIX}${grant.email}:${grant.clientId}`, grant.grantId),
  ]);
}

export async function getOAuthGrant(storage: Storage, grantId: string): Promise<OAuthClientGrant | null> {
  const data = await storage.get(`${OAUTH_GRANT_PREFIX}${grantId}`);
  if (!data) return null;
  return JSON.parse(data) as OAuthClientGrant;
}

export async function getOAuthGrantForClient(
  storage: Storage,
  email: string,
  clientId: string,
): Promise<OAuthClientGrant | null> {
  const grantId = await storage.get(`${USER_CLIENT_PREFIX}${email}:${clientId}`);
  if (!grantId) return null;
  return getOAuthGrant(storage, grantId);
}

export async function saveRefreshToken(
  storage: Storage,
  refreshTokenHash: string,
  grantId: string,
  options?: { expirationTtl?: number },
): Promise<void> {
  const record: OAuthRefreshTokenRecord = { status: "active", grantId };
  await storage.put(`${OAUTH_REFRESH_PREFIX}${refreshTokenHash}`, JSON.stringify(record), options);
}

function isTokenResponse(value: unknown): value is OAuthTokenResponse {
  if (!value || typeof value !== "object") return false;
  const response = value as Partial<OAuthTokenResponse>;
  return (
    typeof response.access_token === "string" &&
    typeof response.refresh_token === "string" &&
    response.token_type === "bearer" &&
    typeof response.expires_in === "number" &&
    typeof response.scope === "string"
  );
}

function parseRefreshTokenRecord(data: string): OAuthRefreshTokenRecord | null {
  try {
    const parsed = JSON.parse(data) as Partial<OAuthRefreshTokenRecord> & {
      ownerId?: string;
      startedAt?: number;
    };
    if (parsed.status === "active" && typeof parsed.grantId === "string") {
      return { status: "active", grantId: parsed.grantId };
    }
    if (
      parsed.status === "rotating" &&
      typeof parsed.grantId === "string" &&
      typeof parsed.ownerId === "string" &&
      typeof parsed.startedAt === "number"
    ) {
      return {
        status: "rotating",
        grantId: parsed.grantId,
        ownerId: parsed.ownerId,
        startedAt: parsed.startedAt,
      };
    }
    if (
      parsed.status === "rotated" &&
      typeof parsed.grantId === "string" &&
      typeof parsed.rotatedAt === "number" &&
      isTokenResponse(parsed.response)
    ) {
      return {
        status: "rotated",
        grantId: parsed.grantId,
        response: parsed.response,
        rotatedAt: parsed.rotatedAt,
      };
    }
    return null;
  } catch {
    // Legacy: plain grantId string (pre-rotation metadata).
    return { status: "active", grantId: data };
  }
}

export async function getRefreshTokenRecord(
  storage: Storage,
  refreshTokenHash: string,
): Promise<OAuthRefreshTokenRecord | null> {
  const data = await storage.get(`${OAUTH_REFRESH_PREFIX}${refreshTokenHash}`);
  if (!data) return null;
  return parseRefreshTokenRecord(data);
}

export async function saveRotatedRefreshToken(
  storage: Storage,
  refreshTokenHash: string,
  grantId: string,
  response: OAuthTokenResponse,
  options: { expirationTtl: number },
): Promise<void> {
  const record: OAuthRefreshTokenRecord = {
    status: "rotated",
    grantId,
    response,
    rotatedAt: Date.now(),
  };
  await storage.put(`${OAUTH_REFRESH_PREFIX}${refreshTokenHash}`, JSON.stringify(record), options);
}

/**
 * Best-effort single-flight claim for a refresh token.
 * Without true KV CAS, write a temporary "rotating" record and re-read to see if we own it.
 */
export async function tryClaimRefreshTokenRotation(
  storage: Storage,
  refreshTokenHash: string,
  grantId: string,
  ownerId: string,
  options?: { expirationTtl?: number },
): Promise<"won" | "lost" | "missing"> {
  const key = `${OAUTH_REFRESH_PREFIX}${refreshTokenHash}`;
  const current = await getRefreshTokenRecord(storage, refreshTokenHash);
  if (!current) return "missing";
  if (current.grantId !== grantId) return "lost";

  if (current.status === "rotated") return "lost";
  if (current.status === "rotating") {
    if (
      current.ownerId !== ownerId &&
      Date.now() - current.startedAt < REFRESH_ROTATION_STALE_MS
    ) {
      return "lost";
    }
  }

  const claim: OAuthRefreshTokenRecord = {
    status: "rotating",
    grantId,
    ownerId,
    startedAt: Date.now(),
  };
  await storage.put(key, JSON.stringify(claim), options);

  const after = await getRefreshTokenRecord(storage, refreshTokenHash);
  if (!after) return "missing";
  if (after.status === "rotated") return "lost";
  if (after.status === "rotating" && after.ownerId === ownerId) return "won";
  return "lost";
}

export async function waitForRotatedRefreshToken(
  storage: Storage,
  refreshTokenHash: string,
  options?: { timeoutMs?: number; pollMs?: number },
): Promise<OAuthTokenResponse | null> {
  const timeoutMs = options?.timeoutMs ?? 5_000;
  const pollMs = options?.pollMs ?? 50;
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    const record = await getRefreshTokenRecord(storage, refreshTokenHash);
    if (!record) return null;
    if (record.status === "rotated") return record.response;
    if (record.status === "active") return null;
    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }
  return null;
}


// ─── API Key helpers ──────────────────────────────────────────────────────────

export async function saveApiKey(storage: Storage, apiKey: ApiKey): Promise<void> {
  const emailLower = apiKey.email.toLowerCase();
  await storage.put(`${API_KEY_PREFIX}${apiKey.tokenHash}`, JSON.stringify(apiKey));
  // Maintain a set of key IDs per email for listing.
  const setKey = `${EMAIL_API_KEYS_PREFIX}${emailLower}`;
  const existing = await storage.get(setKey);
  const ids: string[] = existing ? JSON.parse(existing) : [];
  if (!ids.includes(apiKey.id)) ids.push(apiKey.id);
  await storage.put(setKey, JSON.stringify(ids));
}

export async function getApiKeyByHash(storage: Storage, tokenHash: string): Promise<ApiKey | null> {
  const data = await storage.get(`${API_KEY_PREFIX}${tokenHash}`);
  if (!data) return null;
  return JSON.parse(data) as ApiKey;
}

export async function listApiKeysForEmail(storage: Storage, email: string): Promise<ApiKey[]> {
  const emailLower = email.toLowerCase();
  const setKey = `${EMAIL_API_KEYS_PREFIX}${emailLower}`;
  const raw = await storage.get(setKey);
  if (!raw) return [];
  let ids: string[];
  try { ids = JSON.parse(raw); } catch { return []; }
  if (!Array.isArray(ids)) return [];

  const idSet = new Set(ids);
  const keys: ApiKey[] = [];
  const allKeys = await storage.list({ prefix: API_KEY_PREFIX });
  for (const k of allKeys.keys) {
    const data = await storage.get(k.name);
    if (!data) continue;
    try {
      const key = JSON.parse(data) as ApiKey;
      if (idSet.has(key.id) && key.email.toLowerCase() === emailLower) {
        keys.push(key);
      }
    } catch { /* skip malformed */ }
  }
  return keys.sort((a, b) => a.createdAt - b.createdAt);
}

export async function revokeApiKey(storage: Storage, tokenHash: string, email: string): Promise<boolean> {
  const existing = await getApiKeyByHash(storage, tokenHash);
  if (!existing || existing.email.toLowerCase() !== email.toLowerCase()) return false;
  if (existing.revokedAt) return false; // already revoked
  existing.revokedAt = Date.now();
  await storage.put(`${API_KEY_PREFIX}${tokenHash}`, JSON.stringify(existing));
  return true;
}

// ─── Last-used bookkeeping ────────────────────────────────────────────────────
// KV writes are the scarce resource (1k/day on the free tier), so last-used
// timestamps are persisted at most once per interval instead of per request.
export const LAST_USED_WRITE_INTERVAL_MS = 60 * 60 * 1000;

export function shouldPersistLastUsed(lastUsedAt: number | undefined | null): boolean {
  return !lastUsedAt || Date.now() - lastUsedAt > LAST_USED_WRITE_INTERVAL_MS;
}

export async function touchApiKeyLastUsed(storage: Storage, apiKey: ApiKey): Promise<void> {
  if (apiKey.revokedAt) return;
  if (!shouldPersistLastUsed(apiKey.lastUsedAt)) return;
  apiKey.lastUsedAt = Date.now();
  await storage.put(`${API_KEY_PREFIX}${apiKey.tokenHash}`, JSON.stringify(apiKey));
}

export async function touchOAuthGrantLastUsed(storage: Storage, grant: OAuthClientGrant): Promise<void> {
  if (!shouldPersistLastUsed(grant.lastUsedAt)) return;
  grant.lastUsedAt = Date.now();
  await storage.put(`${OAUTH_GRANT_PREFIX}${grant.grantId}`, JSON.stringify(grant));
}

// ─── OAuth Grant listing ─────────────────────────────────────────────────────

export async function listOAuthGrantsForEmail(storage: Storage, email: string): Promise<OAuthClientGrant[]> {
  const emailLower = email.toLowerCase();
  const grants: OAuthClientGrant[] = [];
  const result = await storage.list({ prefix: OAUTH_GRANT_PREFIX });
  for (const key of result.keys) {
    const data = await storage.get(key.name);
    if (!data) continue;
    try {
      const grant = JSON.parse(data) as OAuthClientGrant;
      if (grant.email?.toLowerCase() === emailLower) {
        grants.push(grant);
      }
    } catch { /* skip malformed */ }
  }
  return grants.sort((a, b) => a.createdAt - b.createdAt);
}


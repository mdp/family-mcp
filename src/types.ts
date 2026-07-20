// ─── Google OAuth Tokens ──────────────────────────────────────────────────────

export interface GoogleTokens {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  expiry_date: number; // epoch ms
  token_type: string;
  obtained_at?: number; // epoch ms
}

// ─── Google User Info ─────────────────────────────────────────────────────────

export interface GoogleUserInfo {
  id: string;
  email: string;
  name: string;
  picture?: string;
  verified_email: boolean;
}

// ─── JWT Payload ──────────────────────────────────────────────────────────────

export interface JWTPayload {
  email: string;
  authMethod?: "oauth";
  clientId?: string;
  grantId?: string;
  iat?: number;
  exp?: number;
}

// ─── Auth context passed into MCP tool handlers ───────────────────────────────

export interface AuthExtra {
  email: string;
  authMethod?: "oauth";
  clientId?: string;
  grantId?: string;
}

export interface RegisteredClient {
  client_id: string;
  client_id_issued_at: number;
  redirect_uris: string[];
  client_name?: string;
  client_uri?: string;
  token_endpoint_auth_method: "none";
  grant_types: string[];
  response_types: string[];
}

export interface OAuthClientGrant {
  grantId: string;
  email: string;
  clientId: string;
  clientName?: string;
  clientUri?: string;
  scope: string;
  createdAt: number;
  updatedAt: number;
  lastUsedAt?: number;
}

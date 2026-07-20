import type { GoogleTokens, GoogleUserInfo } from "./types.js";
import type { Storage } from "./storage.js";

const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo";

// Refresh access token 5 minutes before expiry
const EXPIRY_BUFFER_MS = 5 * 60 * 1000;

/** In-isolate single-flight for Google token refreshes (keyed by email). */
const googleRefreshInflight = new Map<string, Promise<string>>();

type GoogleTokenError = {
  error?: string;
  error_description?: string;
};

function googleTokenErrorMessage(status: number, body: string): string {
  let googleError = "";
  try {
    const parsed = JSON.parse(body) as GoogleTokenError;
    if (parsed.error) {
      googleError = parsed.error;
      if (parsed.error_description) {
        googleError += `: ${parsed.error_description}`;
      }
    }
  } catch {
    googleError = body.trim().slice(0, 240);
  }

  const suffix = googleError ? ` (${googleError})` : "";
  return `Google token refresh failed (${status})${suffix}. The user may need to re-authorize at /oauth/authorize.`;
}

export class GoogleClient {
  private tokens: GoogleTokens;

  constructor(
    tokens: GoogleTokens,
    private clientId: string,
    private clientSecret: string,
    private storage: Storage,
    private email: string
  ) {
    this.tokens = { ...tokens };
  }

  static async fromStorage(
    storage: Storage,
    email: string,
    clientId: string,
    clientSecret: string
  ): Promise<GoogleClient | null> {
    const stored = await storage.get(`google:tokens:${email}`);
    if (!stored) return null;
    const tokens = JSON.parse(stored) as GoogleTokens;
    return new GoogleClient(tokens, clientId, clientSecret, storage, email);
  }

  async ensureValidToken(): Promise<string> {
    if (Date.now() < this.tokens.expiry_date - EXPIRY_BUFFER_MS) {
      return this.tokens.access_token;
    }

    if (!this.tokens.refresh_token) {
      throw new Error("No refresh token available. User may need to re-authorize.");
    }

    const existing = googleRefreshInflight.get(this.email);
    if (existing) {
      const accessToken = await existing;
      const stored = await this.storage.get(`google:tokens:${this.email}`);
      if (stored) {
        this.tokens = JSON.parse(stored) as GoogleTokens;
      }
      return this.tokens.access_token || accessToken;
    }

    const promise = this.refreshAccessToken().finally(() => {
      googleRefreshInflight.delete(this.email);
    });
    googleRefreshInflight.set(this.email, promise);
    return promise;
  }

  private async refreshAccessToken(): Promise<string> {
    // Re-check expiry under single-flight: another waiter may have finished.
    const stored = await this.storage.get(`google:tokens:${this.email}`);
    if (stored) {
      const latest = JSON.parse(stored) as GoogleTokens;
      if (Date.now() < latest.expiry_date - EXPIRY_BUFFER_MS) {
        this.tokens = latest;
        return this.tokens.access_token;
      }
      if (latest.refresh_token) {
        this.tokens.refresh_token = latest.refresh_token;
      }
    }

    if (!this.tokens.refresh_token) {
      throw new Error("No refresh token available. User may need to re-authorize.");
    }

    const response = await fetch(GOOGLE_TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: this.tokens.refresh_token,
        client_id: this.clientId,
        client_secret: this.clientSecret,
      }),
    });

    if (!response.ok) {
      const body = await response.text();
      const message = googleTokenErrorMessage(response.status, body);
      console.error(`Token refresh failed for ${this.email}: ${message}`);
      throw new Error(message);
    }

    const data = (await response.json()) as {
      access_token: string;
      expires_in: number;
      refresh_token?: string;
    };

    this.tokens.access_token = data.access_token;
    this.tokens.expiry_date = Date.now() + data.expires_in * 1000;
    this.tokens.expires_in = data.expires_in;
    this.tokens.obtained_at = Date.now();
    // Google often omits refresh_token on refresh; never clobber the stored one.
    if (data.refresh_token) {
      this.tokens.refresh_token = data.refresh_token;
    }

    await this.storage.put(`google:tokens:${this.email}`, JSON.stringify(this.tokens));

    return this.tokens.access_token;
  }

  async request<T>(method: string, url: string, body?: unknown, timeoutMs = 25000): Promise<T> {
    const token = await this.ensureValidToken();
    const headers: Record<string, string> = {
      Authorization: `Bearer ${token}`,
    };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    let response: Response;
    try {
      response = await fetch(url, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }

    if (!response.ok) {
      let path = url;
      try {
        path = new URL(url).pathname;
      } catch {
        // leave as-is if not a valid URL
      }
      console.error(`Google API error (${response.status}): ${path}`);
      throw new Error(`Google API request failed (${response.status}).`);
    }

    if (response.status === 204) {
      return undefined as T;
    }

    return response.json() as Promise<T>;
  }

  async getUserInfo(): Promise<GoogleUserInfo> {
    const token = await this.ensureValidToken();
    const response = await fetch(GOOGLE_USERINFO_URL, {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!response.ok) {
      throw new Error(`Failed to get user info: ${response.status}`);
    }

    return response.json() as Promise<GoogleUserInfo>;
  }
}

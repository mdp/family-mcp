# ALLOWED_EMAILS (login allowlist)

Google accounts that can complete OAuth are gated here:

```ts
// src/oauth.ts
if (!isAllowedEmail(user.email, c.env.ALLOWED_EMAILS)) {
  // → redirect uri?error=access_denied&error_description=Your account (email) is not authorized.
}
```

Matching is **exact, case-insensitive email** against a comma-separated list.
There is no domain wildcard for login (domains only apply to `ALLOWED_EXTERNAL_RECIPIENTS` for outbound mail/invites).

## Production source of truth

Repo `wrangler.jsonc` ships **placeholder** emails. Real family data is **not** committed.

CI (`scripts/write-wrangler-ci.mjs`) also does **not** set `ALLOWED_EMAILS` / `FAMILY_MEMBERS`.
Those Worker **vars** are set on the Cloudflare Worker (Dashboard or `wrangler`) and persist across deploys.

## Fix `access_denied` / “not authorized”

1. Complete OAuth again and read `error_description` — it now includes the Google email that was denied.
2. Sign in as that family Gmail (e.g. `percival@gmail.com`), not a work account.
3. Or add the desired email to the Worker var:

```bash
cd ~/Sync/src/mdp/family-mcp
wrangler login   # interactive

# Inspect current vars in dashboard:
# Workers & Pages → family-mcp → Settings → Variables → ALLOWED_EMAILS

# Or set via CLI (plain text var, not secret):
wrangler versions secret bulk   # not this — use:
# Dashboard is simplest for vars; CLI:
echo -n 'person1@gmail.com,person2@gmail.com' | wrangler secret put ALLOWED_EMAILS
# Note: if ALLOWED_EMAILS is a plain var (not secret), use dashboard "Edit variables"
# or: wrangler deploy --var ALLOWED_EMAILS:person1@gmail.com,person2@gmail.com
```

Keep `FAMILY_MEMBERS` JSON in sync with the same emails (names/relationships/timezones).

4. Re-run MCPJungle OAuth:

```bash
cd ~/Sync/agents/mdp/docker/mcpjungle
./scripts/register-servers.sh oauth percival_family
```

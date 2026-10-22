import { writeFileSync } from "node:fs";

function required(name) {
  const value = process.env[name];
  if (!value?.trim()) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value.trim();
}

function optional(name, fallback = "") {
  return process.env[name]?.trim() || fallback;
}

required("CLOUDFLARE_API_TOKEN");
required("CLOUDFLARE_ACCOUNT_ID");

const config = {
  $schema: "./node_modules/wrangler/config-schema.json",
  name: optional("FAMILY_MCP_WORKER_NAME", "family-mcp"),
  main: "src/index.ts",
  compatibility_date: "2025-01-13",
  compatibility_flags: ["nodejs_compat"],
  // Runtime vars are managed on Cloudflare, not in this generated config.
  // Without this, deploying deletes dashboard-managed vars such as ALLOWED_EMAILS.
  keep_vars: true,
  kv_namespaces: [
    {
      binding: "STATE_KV",
      id: required("FAMILY_MCP_STATE_KV_NAMESPACE_ID"),
    },
    {
      binding: "TOKENS_KV",
      id: required("FAMILY_MCP_TOKENS_KV_NAMESPACE_ID"),
    },
  ],
  ratelimits: [
    {
      name: "MCP_RATE_LIMITER",
      namespace_id: required("FAMILY_MCP_RATE_LIMIT_NAMESPACE_ID"),
      simple: { limit: 60, period: 10 },
    },
  ],
  observability: {
    enabled: true,
  },
};

if (optional("FAMILY_MCP_WORKERS_DEV", "true") === "false") {
  config.workers_dev = false;
}

const customDomain = optional("FAMILY_MCP_CUSTOM_DOMAIN");
if (customDomain) {
  config.routes = [{ pattern: customDomain, custom_domain: true }];
}

writeFileSync("wrangler.ci.jsonc", `${JSON.stringify(config, null, 2)}\n`);

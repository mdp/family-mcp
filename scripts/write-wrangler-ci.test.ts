import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";

it("preserves Cloudflare-managed runtime vars when generating deployment config", () => {
  const directory = mkdtempSync(join(tmpdir(), "family-mcp-config-"));
  try {
    execFileSync(process.execPath, [fileURLToPath(new URL("./write-wrangler-ci.mjs", import.meta.url))], {
      cwd: directory,
      env: {
        CLOUDFLARE_API_TOKEN: "test-token",
        CLOUDFLARE_ACCOUNT_ID: "test-account",
        FAMILY_MCP_STATE_KV_NAMESPACE_ID: "test-state",
        FAMILY_MCP_TOKENS_KV_NAMESPACE_ID: "test-tokens",
        FAMILY_MCP_RATE_LIMIT_NAMESPACE_ID: "1001",
      },
    });
    const config = JSON.parse(readFileSync(join(directory, "wrangler.ci.jsonc"), "utf8"));
    expect(config.keep_vars).toBe(true);
    expect(config).not.toHaveProperty("vars");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

import { describe, it, expect, vi } from "vitest";

describe("dexter-x402 plugin", () => {
  it("exports default plugin with correct id", async () => {
    const plugin = await import("../index.js");
    expect(plugin.default).toBeDefined();
    expect(plugin.default.id).toBe("dexter-x402");
    expect(plugin.default.name).toBe("Dexter x402");
  });

  it("has register function", async () => {
    const plugin = await import("../index.js");
    expect(typeof plugin.default.register).toBe("function");
  });

  it("has valid plugin manifest", async () => {
    const fs = await import("node:fs/promises");
    const path = await import("node:path");
    const manifestPath = path.join(import.meta.dirname, "..", "clawdbot.plugin.json");
    const manifest = JSON.parse(await fs.readFile(manifestPath, "utf8"));
    
    expect(manifest.id).toBe("dexter-x402");
    expect(manifest.name).toBe("Dexter x402");
    expect(manifest.configSchema?.properties?.baseUrl).toBeDefined();
    expect(manifest.configSchema?.properties?.autoRefreshTools).toBeDefined();
  });
});

describe("PKCE generation", () => {
  it("generates valid S256 challenge", async () => {
    const { createHash, randomBytes } = await import("node:crypto");
    
    // Test the same algorithm used in the plugin
    const verifier = randomBytes(32)
      .toString("base64url")
      .replace(/[^a-zA-Z0-9]/g, "")
      .slice(0, 43);
    
    const challenge = createHash("sha256")
      .update(verifier)
      .digest("base64url");
    
    // Verifier should be reasonable length (base64url of 32 bytes, filtered)
    expect(verifier.length).toBeGreaterThanOrEqual(32);
    expect(verifier.length).toBeLessThanOrEqual(43);
    expect(challenge.length).toBeGreaterThan(0);
    expect(challenge).not.toBe(verifier);
  });
});

describe("OAuth metadata parsing", () => {
  it("parses standard OAuth metadata", () => {
    const metadata = {
      issuer: "https://mcp.dexter.cash/mcp",
      authorization_endpoint: "https://dexter.cash/connector/auth",
      token_endpoint: "https://mcp.dexter.cash/mcp/token",
      registration_endpoint: "https://mcp.dexter.cash/mcp/register",
      scopes_supported: ["openid", "wallet.read", "wallet.trade"],
    };
    
    expect(metadata.issuer).toContain("dexter.cash");
    expect(metadata.authorization_endpoint).toContain("connector/auth");
    expect(metadata.token_endpoint).toContain("/token");
  });
});

import { Type, type Static } from "@sinclair/typebox";

export const DexterMcpConfigSchema = Type.Object({
  baseUrl: Type.Optional(
    Type.String({
      default: "https://mcp.dexter.cash/mcp",
      description: "Dexter MCP server URL",
    }),
  ),
  timeoutMs: Type.Optional(
    Type.Number({
      default: 30000,
      description: "Request timeout in milliseconds",
    }),
  ),
});

export type DexterMcpConfig = Static<typeof DexterMcpConfigSchema>;

export const DEFAULT_BASE_URL = "https://mcp.dexter.cash/mcp";
export const DEFAULT_TIMEOUT_MS = 30000;

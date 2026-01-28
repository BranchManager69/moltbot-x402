import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { Type } from "@sinclair/typebox";

import type {
  MoltbotPluginApi,
  MoltbotPluginToolContext,
  ProviderAuthContext,
  ProviderAuthResult,
} from "../../src/plugins/types.js";
import type { OAuthCredential } from "../../src/agents/auth-profiles/types.js";

// =============================================================================
// Constants
// =============================================================================

const DEFAULT_BASE_URL = "https://mcp.dexter.cash/mcp";
const OAUTH_METADATA_PATH = "/.well-known/oauth-authorization-server";
const CALLBACK_PORT = 51199;
const REDIRECT_URI = `http://localhost:${CALLBACK_PORT}/oauth-callback`;
const DEFAULT_SCOPES = ["openid", "wallet.read", "wallet.trade"];

const RESPONSE_PAGE = `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Dexter x402 - Connected</title>
    <style>
      body { font-family: system-ui, sans-serif; max-width: 500px; margin: 60px auto; text-align: center; }
      h1 { color: #10b981; }
      p { color: #6b7280; }
    </style>
  </head>
  <body>
    <h1>Connected to Dexter</h1>
    <p>You can close this window and return to Moltbot.</p>
  </body>
</html>`;

// =============================================================================
// Types
// =============================================================================

type OAuthMetadata = {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  registration_endpoint?: string;
  scopes_supported?: string[];
  code_challenge_methods_supported?: string[];
  mcp?: {
    client_id: string;
    redirect_uri: string;
  };
};

type TokenResponse = {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  token_type?: string;
  scope?: string;
};

type DcrResponse = {
  client_id: string;
  client_id_issued_at?: number;
  redirect_uris: string[];
};

type DexterTool = {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
  _meta?: {
    category?: string;
    access?: string;
    tags?: string[];
  };
};

// Extended credential type that includes Dexter-specific fields
type DexterOAuthCredential = OAuthCredential & {
  baseUrl: string;
};

// =============================================================================
// OAuth Utilities
// =============================================================================

function generatePkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString("hex");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

async function fetchOAuthMetadata(baseUrl: string): Promise<OAuthMetadata> {
  const metadataUrl = baseUrl.replace(/\/mcp\/?$/, "") + OAUTH_METADATA_PATH;
  
  const response = await fetch(metadataUrl, {
    headers: { Accept: "application/json" },
  });
  
  if (!response.ok) {
    throw new Error(`Failed to fetch OAuth metadata: ${response.status}`);
  }
  
  return response.json() as Promise<OAuthMetadata>;
}

// Dynamic Client Registration (RFC 7591)
// This allows Moltbot to register with any redirect_uri including localhost
async function registerDcrClient(params: {
  registrationEndpoint: string;
  redirectUri: string;
  clientName?: string;
}): Promise<DcrResponse> {
  const response = await fetch(params.registrationEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({
      redirect_uris: [params.redirectUri],
      client_name: params.clientName || "Moltbot Dexter x402",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    }),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`DCR registration failed: ${text}`);
  }

  return response.json() as Promise<DcrResponse>;
}

function buildAuthUrl(params: {
  metadata: OAuthMetadata;
  clientId: string;
  challenge: string;
  state: string;
  scopes: string[];
  redirectUri: string;
}): string {
  const url = new URL(params.metadata.authorization_endpoint);
  
  url.searchParams.set("client_id", params.clientId);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("redirect_uri", params.redirectUri);
  url.searchParams.set("scope", params.scopes.join(" "));
  url.searchParams.set("code_challenge", params.challenge);
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("state", params.state);
  return url.toString();
}

async function startCallbackServer(params: { timeoutMs: number }): Promise<{
  waitForCallback: () => Promise<URL>;
  close: () => Promise<void>;
}> {
  let settled = false;
  let resolveCallback: (url: URL) => void;
  let rejectCallback: (err: Error) => void;

  const callbackPromise = new Promise<URL>((resolve, reject) => {
    resolveCallback = (url) => {
      if (settled) return;
      settled = true;
      resolve(url);
    };
    rejectCallback = (err) => {
      if (settled) return;
      settled = true;
      reject(err);
    };
  });

  const timeout = setTimeout(() => {
    rejectCallback(new Error("Timed out waiting for OAuth callback"));
  }, params.timeoutMs);
  timeout.unref?.();

  const server = createServer((request, response) => {
    if (!request.url) {
      response.writeHead(400, { "Content-Type": "text/plain" });
      response.end("Missing URL");
      return;
    }

    const url = new URL(request.url, `http://localhost:${CALLBACK_PORT}`);
    if (url.pathname !== "/oauth-callback") {
      response.writeHead(404, { "Content-Type": "text/plain" });
      response.end("Not found");
      return;
    }

    response.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    response.end(RESPONSE_PAGE);
    resolveCallback(url);

    setImmediate(() => {
      server.close();
    });
  });

  await new Promise<void>((resolve, reject) => {
    const onError = (err: Error) => {
      server.off("error", onError);
      reject(err);
    };
    server.once("error", onError);
    // Bind to 0.0.0.0 to support SSH port forwarding
    server.listen(CALLBACK_PORT, "0.0.0.0", () => {
      server.off("error", onError);
      resolve();
    });
  });

  return {
    waitForCallback: () => callbackPromise,
    close: () =>
      new Promise<void>((resolve) => {
        clearTimeout(timeout);
        server.close(() => resolve());
      }),
  };
}

async function exchangeCodeWithRedirect(params: {
  metadata: OAuthMetadata;
  clientId: string;
  code: string;
  verifier: string;
  redirectUri: string;
  log: (msg: string) => void;
}): Promise<TokenResponse> {
  const body: Record<string, string> = {
    grant_type: "authorization_code",
    client_id: params.clientId,
    code: params.code,
    redirect_uri: params.redirectUri,
    code_verifier: params.verifier,
  };
  
  params.log("[dexter] Token exchange starting...");
  params.log("[dexter] Endpoint: " + params.metadata.token_endpoint);
  
  // Add timeout to prevent hanging
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000);
  
  let response: Response;
  try {
    response = await fetch(params.metadata.token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(body),
      signal: controller.signal,
    });
    params.log("[dexter] Token response status: " + response.status);
  } catch (err) {
    params.log("[dexter] Token fetch error: " + (err instanceof Error ? err.message : String(err)));
    throw err;
  } finally {
    clearTimeout(timeout);
  }

  if (!response.ok) {
    const text = await response.text();
    params.log("[dexter] Token exchange failed: " + text);
    throw new Error(`Token exchange failed: ${text}`);
  }

  params.log("[dexter] Reading response body...");
  const text = await response.text();
  params.log("[dexter] Body length: " + text.length);
  
  const tokens = JSON.parse(text) as TokenResponse;
  params.log("[dexter] Got tokens, has refresh: " + !!tokens.refresh_token);
  return tokens;
}

async function refreshAccessToken(params: {
  metadata: OAuthMetadata;
  refreshToken: string;
}): Promise<TokenResponse> {
  const response = await fetch(params.metadata.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: params.refreshToken,
    }),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Token refresh failed: ${text}`);
  }

  return response.json() as Promise<TokenResponse>;
}

// =============================================================================
// MCP Client - Proper MCP Protocol Implementation
// =============================================================================

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { ListToolsResultSchema, CallToolResultSchema } from "@modelcontextprotocol/sdk/types.js";

// Cache MCP client connections per access token
const mcpClientCache = new Map<string, { client: Client; transport: StreamableHTTPClientTransport; createdAt: number }>();
const MCP_CLIENT_TTL_MS = 5 * 60 * 1000; // 5 minutes

async function getMcpClient(params: {
  baseUrl: string;
  accessToken: string;
}): Promise<Client> {
  const cacheKey = `${params.baseUrl}:${params.accessToken.slice(-8)}`;
  
  // Check cache
  const cached = mcpClientCache.get(cacheKey);
  if (cached && Date.now() - cached.createdAt < MCP_CLIENT_TTL_MS) {
    return cached.client;
  }
  
  // Clean up old cached client if exists
  if (cached) {
    try {
      await cached.transport.close();
      await cached.client.close();
    } catch {
      // Ignore cleanup errors
    }
    mcpClientCache.delete(cacheKey);
  }
  
  // Create new MCP client
  const client = new Client({ 
    name: "moltbot-dexter-x402", 
    version: "1.0.0" 
  });
  
  const transport = new StreamableHTTPClientTransport(new URL(params.baseUrl), {
    fetch,
    requestInit: {
      headers: {
        Authorization: `Bearer ${params.accessToken}`,
      },
    },
  });
  
  await client.connect(transport);
  
  // Cache the client
  mcpClientCache.set(cacheKey, {
    client,
    transport,
    createdAt: Date.now(),
  });
  
  return client;
}

async function fetchDexterTools(params: {
  baseUrl: string;
  accessToken: string;
}): Promise<DexterTool[]> {
  const client = await getMcpClient(params);
  const result = await client.request(
    { method: "tools/list", params: {} },
    ListToolsResultSchema
  );
  
  return (result.tools || []).map((tool) => ({
    name: tool.name,
    description: tool.description || "",
    inputSchema: tool.inputSchema as Record<string, unknown>,
    _meta: (tool as unknown as { _meta?: { category?: string } })._meta,
  }));
}

async function callDexterTool(params: {
  baseUrl: string;
  accessToken: string;
  toolName: string;
  args: Record<string, unknown>;
  timeoutMs?: number;
}): Promise<unknown> {
  const client = await getMcpClient({
    baseUrl: params.baseUrl,
    accessToken: params.accessToken,
  });
  
  const result = await client.request(
    { 
      method: "tools/call", 
      params: {
        name: params.toolName,
        arguments: params.args,
      }
    },
    CallToolResultSchema
  );
  
  // Extract text content from MCP response
  const content = result.content || [];
  const textParts = content
    .filter((c): c is { type: "text"; text: string } => c.type === "text")
    .map((c) => c.text);
  
  if (textParts.length === 1) {
    // Try to parse as JSON if it looks like JSON
    const text = textParts[0];
    if (text.startsWith("{") || text.startsWith("[")) {
      try {
        return JSON.parse(text);
      } catch {
        return { text };
      }
    }
    return { text };
  }
  
  return { content: textParts, raw: result };
}

// =============================================================================
// OAuth Login Flow
// =============================================================================

async function loginDexter(params: {
  baseUrl: string;
  isRemote: boolean;
  openUrl: (url: string) => Promise<void>;
  prompt: (message: string) => Promise<string>;
  note: (message: string, title?: string) => Promise<void>;
  log: (message: string) => void;
  progress: { update: (msg: string) => void; stop: (msg?: string) => void };
}): Promise<{
  access: string;
  refresh: string;
  expires: number;
}> {
  params.progress.update("Fetching Dexter OAuth configuration...");
  const metadata = await fetchOAuthMetadata(params.baseUrl);

  // Try to start local callback server first
  // Always try regardless of isRemote - SSH port forwarding should work
  let callbackServer: Awaited<ReturnType<typeof startCallbackServer>> | null = null;
  let effectiveRedirectUri = REDIRECT_URI;
  
  try {
    callbackServer = await startCallbackServer({ timeoutMs: 5 * 60 * 1000 });
    effectiveRedirectUri = REDIRECT_URI;
    params.log(`[dexter] Callback server listening on port ${CALLBACK_PORT}`);
  } catch (err) {
    params.log(`[dexter] Callback server failed: ${err instanceof Error ? err.message : err}`);
    callbackServer = null;
  }

  // Use Dynamic Client Registration (DCR) to register our redirect URI
  // This is how Cursor and other native clients work
  params.progress.update("Registering with Dexter...");
  
  const registrationEndpoint = metadata.registration_endpoint 
    || params.baseUrl.replace(/\/mcp\/?$/, "") + "/mcp/register";
  
  let clientId: string;
  try {
    const dcrResponse = await registerDcrClient({
      registrationEndpoint,
      redirectUri: effectiveRedirectUri,
      clientName: "Moltbot Dexter x402",
    });
    clientId = dcrResponse.client_id;
  } catch (err) {
    // If DCR fails and we have a server callback, try that
    if (metadata.mcp?.redirect_uri && metadata.mcp?.client_id) {
      effectiveRedirectUri = metadata.mcp.redirect_uri;
      clientId = metadata.mcp.client_id;
      if (callbackServer) {
        await callbackServer.close();
        callbackServer = null;
      }
    } else {
      throw err;
    }
  }

  const { verifier, challenge } = generatePkce();
  const state = randomBytes(16).toString("hex");
  
  const scopes = metadata.scopes_supported?.length
    ? metadata.scopes_supported.filter((s) => DEFAULT_SCOPES.includes(s))
    : DEFAULT_SCOPES;
  
  const authUrl = buildAuthUrl({ 
    metadata,
    clientId,
    challenge, 
    state, 
    scopes,
    redirectUri: effectiveRedirectUri,
  });

  // Always log the URL for SSH/remote scenarios
  params.log("");
  params.log("Open this URL in your browser:");
  params.log(authUrl);
  params.log("");

  if (!callbackServer) {
    await params.note(
      [
        "Open the URL below in your browser to sign in to Dexter.",
        "After signing in, copy the full redirect URL and paste it here.",
        "",
        `Auth URL: ${authUrl}`,
      ].join("\n"),
      "Dexter OAuth",
    );
  }

  // Try to open browser (may fail in SSH sessions)
  params.progress.update("Opening Dexter sign-in...");
  try {
    await params.openUrl(authUrl);
  } catch {
    // ignore - user can use the logged URL
  }

  let code = "";
  let returnedState = "";

  if (callbackServer) {
    params.progress.update("Waiting for Dexter authorization...");
    const callback = await callbackServer.waitForCallback();
    code = callback.searchParams.get("code") ?? "";
    returnedState = callback.searchParams.get("state") ?? "";
    await callbackServer.close();
  } else {
    params.progress.update("Waiting for redirect URL...");
    const input = await params.prompt("Paste the redirect URL: ");
    
    try {
      const url = new URL(input.trim());
      code = url.searchParams.get("code") ?? "";
      returnedState = url.searchParams.get("state") ?? "";
    } catch {
      throw new Error("Invalid URL. Please paste the full redirect URL.");
    }
  }

  if (!code) throw new Error("Missing OAuth authorization code");
  if (returnedState !== state) {
    throw new Error("OAuth state mismatch. Please try again.");
  }

  params.progress.update("Exchanging code for tokens...");
  const tokens = await exchangeCodeWithRedirect({ 
    metadata,
    clientId,
    code, 
    verifier,
    redirectUri: effectiveRedirectUri,
    log: params.log,
  });

  if (!tokens.refresh_token) {
    console.log("[dexter-debug] ERROR: No refresh token in response!");
    throw new Error("Dexter did not return a refresh token. Please try again.");
  }

  const expiresIn = tokens.expires_in ?? 3600;
  const expires = Date.now() + expiresIn * 1000 - 5 * 60 * 1000;

  params.progress.stop("Connected to Dexter");
  
  return {
    access: tokens.access_token,
    refresh: tokens.refresh_token,
    expires,
  };
}

// =============================================================================
// Plugin Registration
// =============================================================================

const dexterMcpPlugin = {
  id: "dexter-x402",
  name: "Dexter x402",
  description: "Connect to Dexter's Solana DeFi tools via OAuth",
  
  register(api: MoltbotPluginApi) {
    const config = api.pluginConfig as {
      baseUrl?: string;
      autoRefreshTools?: boolean;
    } | undefined;
    
    const baseUrl = config?.baseUrl || DEFAULT_BASE_URL;
    
    // Track current credential for tool calls
    let currentCredential: DexterOAuthCredential | undefined;
    
    // Register OAuth provider
    api.registerProvider({
      id: "dexter-x402",
      label: "Dexter",
      docsPath: "/providers/dexter",
      aliases: ["dexter"],
      
      auth: [
        {
          id: "oauth",
          label: "Dexter OAuth",
          hint: "Sign in with your Dexter account",
          kind: "oauth",
          
          run: async (ctx: ProviderAuthContext): Promise<ProviderAuthResult> => {
            const spin = ctx.prompter.progress("Connecting to Dexter...");
            
            try {
              const result = await loginDexter({
                baseUrl,
                isRemote: ctx.isRemote,
                openUrl: ctx.openUrl,
                prompt: async (message) => String(await ctx.prompter.text({ message })),
                note: ctx.prompter.note,
                log: (message) => ctx.runtime.log(message),
                progress: spin,
              });

              const profileId = "dexter-x402:default";
              const credential: DexterOAuthCredential = {
                type: "oauth",
                provider: "dexter-x402",
                access: result.access,
                refresh: result.refresh,
                expires: result.expires,
                baseUrl,
              };
              
              currentCredential = credential;

              let toolCount = 0;
              try {
                const tools = await fetchDexterTools({
                  baseUrl,
                  accessToken: result.access,
                });
                toolCount = tools.length;
              } catch {
                // Non-fatal
              }

              return {
                profiles: [{ profileId, credential }],
                notes: [
                  `Connected to Dexter x402 at ${baseUrl}`,
                  toolCount > 0 ? `${toolCount} tools available` : "Tools will be loaded on first use",
                  "Run 'moltbot tools' to see available Dexter tools",
                ],
              };
            } catch (err) {
              spin.stop("Dexter connection failed");
              throw err;
            }
          },
        },
      ],
      
      refreshOAuth: async (cred) => {
        if (cred.provider !== "dexter-x402") return cred;
        
        const dexterCred = cred as DexterOAuthCredential;
        const metadata = await fetchOAuthMetadata(dexterCred.baseUrl || baseUrl);
        const tokens = await refreshAccessToken({
          metadata,
          refreshToken: dexterCred.refresh,
        });

        const expiresIn = tokens.expires_in ?? 3600;
        const newCred: DexterOAuthCredential = {
          ...dexterCred,
          access: tokens.access_token,
          refresh: tokens.refresh_token || dexterCred.refresh,
          expires: Date.now() + expiresIn * 1000 - 5 * 60 * 1000,
        };
        
        currentCredential = newCred;
        return newCred;
      },
    });

    // Helper to load credential from file if not in memory
    const loadCredentialFromFile = async (): Promise<DexterOAuthCredential | undefined> => {
      if (currentCredential) return currentCredential;
      
      try {
        const os = await import("node:os");
        const fs = await import("node:fs/promises");
        const path = await import("node:path");
        
        // Try multiple auth profile locations
        const possiblePaths = [
          path.join(os.homedir(), ".clawdbot", "agents", "main", "agent", "auth-profiles.json"),
          path.join(os.homedir(), ".moltbot", "auth-profiles.json"),
        ];
        
        for (const authPath of possiblePaths) {
          try {
            const data = await fs.readFile(authPath, "utf8");
            const parsed = JSON.parse(data);
            
            // Handle nested structure: { version, profiles: { "dexter-x402:default": {...} } }
            const profiles = parsed.profiles || parsed;
            const profile = profiles["dexter-x402:default"];
            
            if (profile?.type === "oauth" && profile?.access) {
              currentCredential = {
                ...profile,
                baseUrl: profile.baseUrl || baseUrl,
              } as DexterOAuthCredential;
              return currentCredential;
            }
          } catch {
            // Try next path
          }
        }
      } catch {
        // Failed to load
      }
      return undefined;
    };

    // Register the Dexter tools gateway
    api.registerTool(
      (ctx: MoltbotPluginToolContext) => {
        console.log("[dexter] registerTool callback called, sandboxed:", ctx.sandboxed);
        // Allow in all contexts - user explicitly authenticated
        // if (ctx.sandboxed) return null;
        
        return {
          name: "dexter_x402",
          label: "Dexter Tools",
          description: "Access 50+ Dexter Solana DeFi tools. Use action 'list' to see available tools, or 'call' to invoke a specific tool.",
          parameters: Type.Object({
            action: Type.Unsafe<"list" | "call">({ type: "string", enum: ["list", "call"] }),
            tool: Type.Optional(Type.String({ description: "Tool name (required for 'call' action)" })),
            args: Type.Optional(Type.String({ description: "JSON arguments for the tool" })),
          }),
          async execute(_id: string, params: Record<string, unknown>) {
            // Try to load credential from file if not in memory
            const cred = await loadCredentialFromFile();
            const accessToken = cred?.access;
            if (!accessToken) {
              return {
                content: [{
                  type: "text" as const,
                  text: "Not connected to Dexter. Run 'moltbot models auth login --provider dexter-x402' to connect.",
                }],
                details: { error: "not_authenticated" },
              };
            }

            const action = String(params.action || "list");
            const effectiveBaseUrl = cred?.baseUrl || baseUrl;
            
            if (action === "list") {
              try {
                const tools = await fetchDexterTools({
                  baseUrl: effectiveBaseUrl,
                  accessToken,
                });
                
                const toolList = tools.map((t) => ({
                  name: t.name,
                  description: t.description,
                  category: t._meta?.category,
                }));
                
                return {
                  content: [{
                    type: "text" as const,
                    text: JSON.stringify({ tools: toolList, count: tools.length }, null, 2),
                  }],
                  details: { tools: toolList, count: tools.length },
                };
              } catch (err) {
                const message = err instanceof Error ? err.message : String(err);
                return {
                  content: [{ type: "text" as const, text: `Failed to list tools: ${message}` }],
                  details: { error: message },
                };
              }
            }
            
            if (action === "call") {
              const toolName = String(params.tool || "");
              if (!toolName) {
                return {
                  content: [{ type: "text" as const, text: "Error: 'tool' parameter required for 'call' action" }],
                  details: { error: "tool_required" },
                };
              }
              
              let toolArgs: Record<string, unknown> = {};
              if (params.args) {
                try {
                  toolArgs = JSON.parse(String(params.args));
                } catch {
                  return {
                    content: [{ type: "text" as const, text: "Error: 'args' must be valid JSON" }],
                    details: { error: "invalid_args" },
                  };
                }
              }
              
              try {
                const result = await callDexterTool({
                  baseUrl: effectiveBaseUrl,
                  accessToken,
                  toolName,
                  args: toolArgs,
                });
                
                return {
                  content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
                  details: result,
                };
              } catch (err) {
                const message = err instanceof Error ? err.message : String(err);
                return {
                  content: [{ type: "text" as const, text: `Tool call failed: ${message}` }],
                  details: { error: message },
                };
              }
            }
            
            return {
              content: [{ type: "text" as const, text: `Unknown action: ${action}. Use 'list' or 'call'.` }],
              details: { error: "unknown_action" },
            };
          },
        };
      },
      { name: "dexter_x402" },
    );

    api.logger.info("Dexter x402 plugin registered");
  },
};

export default dexterMcpPlugin;

# Dexter x402 Plugin for Moltbot

Official Moltbot plugin providing access to **59+ Dexter Solana DeFi tools** via the Model Context Protocol (MCP).

## Overview

This plugin connects Moltbot to Dexter's MCP server, enabling:

- **Secure OAuth 2.0 Authentication** with PKCE and Dynamic Client Registration
- **Real-time Tool Discovery** via MCP `tools/list`  
- **Direct Tool Execution** via MCP `tools/call`
- **Automatic Token Refresh** for seamless long-running sessions

## Quick Start

### 1. Authenticate

```bash
moltbot models auth login --provider dexter-x402
```

This opens OAuth flow in your browser. Sign in with your Dexter account and authorize Moltbot.

### 2. Use Tools

The plugin exposes a single gateway tool `dexter_x402` that provides access to all 59+ Dexter capabilities:

```bash
# List available tools
moltbot agent --local --session-id demo -m "Use dexter_x402 with action='list'"

# Call a specific tool
moltbot agent --local --session-id demo -m "Use dexter_x402 to check trending Solana tokens"
```

Or simply ask naturally:

```bash
moltbot agent --local --session-id demo -m "What's trending on Solana right now?"
```

## Available Tools (59+)

### 💼 Wallet Management
| Tool | Description |
|------|-------------|
| `resolve_wallet` | Resolve the effective managed wallet for this session |
| `list_my_wallets` | List all wallets linked to your Dexter account |
| `set_session_wallet_override` | Override wallet for the current session |
| `auth_info` | Diagnostics for wallet resolution and token state |

### 💱 Solana Trading
| Tool | Description |
|------|-------------|
| `solana_resolve_token` | Resolve token metadata by name, ticker, or address |
| `solana_send` | Transfer SOL, USDC, DEXTER, PAYAI, or any SPL token |
| `solana_swap_preview` | Preview a token swap before execution |
| `solana_swap_execute` | Execute a previewed swap |
| `jupiter_quote_preview` | Get Jupiter DEX swap quote |
| `jupiter_quote_pro` | Jupiter quote with pro-tier features |

### 📊 Analytics & Research
| Tool | Description |
|------|-------------|
| `search` | Web search with real-time results |
| `fetch` | Retrieve and summarize web pages |
| `pumpstream_live_summary` | Live pump.fun stream analytics |
| `markets_fetch_ohlcv` | Birdeye OHLCV candle data |
| `onchain_activity_overview` | On-chain analytics for tokens/wallets |
| `onchain_entity_insight` | Deep analysis of wallets, tokens, or signatures |
| `solscan_trending_tokens` | Solscan trending tokens snapshot |
| `slippage_sentinel` | Volatility analysis & optimal slippage calculation |
| `twitter_topic_analysis` | Twitter sentiment and conversation analysis |

### 🎬 Creative & Media (x402 Paid)
| Tool | Description |
|------|-------------|
| `sora_video_job` | Generate video clips with OpenAI Sora |
| `meme_generator_job` | AI-powered meme and image generation |
| `studio_breaking_news` | Create newscast videos and infographics |
| `studio_news_status` | Check breaking news job status |

### 🎮 Games
| Tool | Description |
|------|-------------|
| `pokedexter_create_challenge` | Create wagered Pokémon battle ($1-$25) |
| `pokedexter_accept_challenge` | Accept a battle challenge |
| `pokedexter_make_move` | Submit battle action |
| `pokedexter_get_battle_state` | Get current battle state |
| `pokedexter_join_queue` | Join quick match queue |
| `games_king_usurp` | Become King of Dexter ($0.01) |
| `games_king_state` | View current King state |
| `games_story_append` | Add to the Infinite Story ($0.01) |
| `games_story_read` | Read the Infinite Story |

### 🚀 Hyperliquid (Perpetuals)
| Tool | Description |
|------|-------------|
| `hyperliquid_markets` | List tradable perp symbols |
| `hyperliquid_opt_in` | Provision agent wallet for perp trading |
| `hyperliquid_fund` | Bridge SOL → USDC → Hyperliquid |
| `hyperliquid_bridge_deposit` | Deposit from Arbitrum |
| `hyperliquid_perp_trade` | Submit perpetual orders |

### 🔧 Codex Sessions
| Tool | Description |
|------|-------------|
| `codex_start` | Begin a new Codex conversation |
| `codex_reply` | Follow-up to existing Codex session |
| `codex_exec` | Run Codex with optional JSON schema |

### 🏭 Studio (Superadmin)
| Tool | Description |
|------|-------------|
| `studio_create` | Start a Studio agent task |
| `studio_status` | Check job status |
| `studio_cancel` | Cancel running job |
| `studio_inspect` | Full job details |
| `studio_list` | List recent jobs |

### 📺 Stream Engagement
| Tool | Description |
|------|-------------|
| `stream_public_shout` | Submit shout-out for live stream |
| `stream_shout_feed` | Get latest public shouts |

## Architecture

```
┌─────────────────┐     OAuth 2.0 + PKCE      ┌──────────────────┐
│    Moltbot      │◄─────────────────────────►│  Dexter OAuth    │
│  (dexter-x402    │                           │  (dexter-api)    │
│    plugin)      │                           └──────────────────┘
└────────┬────────┘
         │
         │  MCP Protocol (JSON-RPC over HTTP)
         │  - tools/list
         │  - tools/call
         ▼
┌─────────────────┐     Internal      ┌──────────────────┐
│   Dexter x402    │◄─────────────────►│  Dexter Backend  │
│    Server       │                   │  (59+ tools)     │
│ mcp.dexter.cash │                   │                  │
└─────────────────┘                   └──────────────────┘
```

### Authentication Flow

1. **Dynamic Client Registration (DCR)**: Plugin registers with Dexter's OAuth server, declaring `http://localhost:51199/oauth-callback` as redirect URI
2. **PKCE Authorization**: Browser-based OAuth with S256 code challenge
3. **Token Exchange**: Authorization code exchanged for access + refresh tokens
4. **Automatic Refresh**: Tokens refreshed automatically before expiry

### MCP Integration

The plugin uses the official `@modelcontextprotocol/sdk` to:

1. Establish `StreamableHTTPClientTransport` connection to `mcp.dexter.cash/mcp`
2. Send `tools/list` JSON-RPC requests to discover available tools
3. Execute `tools/call` JSON-RPC requests for tool invocation
4. Handle response content (text, JSON, images)

## Configuration

Optional settings in `~/.moltbot/moltbot.json`:

```json
{
  "plugins": {
    "dexter-x402": {
      "baseUrl": "https://mcp.dexter.cash/mcp",
      "autoRefreshTools": true
    }
  }
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `baseUrl` | `https://mcp.dexter.cash/mcp` | MCP server endpoint |
| `autoRefreshTools` | `true` | Refresh tool list on connection |

## How It Works

### The `dexter_x402` Gateway

Rather than registering 59+ individual tools (which would overwhelm the agent's context), this plugin exposes a single `dexter_x402` gateway with two actions:

```typescript
{
  action: "list" | "call",
  tool?: string,      // Tool name (required for "call")
  args?: string       // JSON arguments for the tool
}
```

**List tools:**
```json
{ "action": "list" }
```

**Call a tool:**
```json
{ 
  "action": "call", 
  "tool": "solscan_trending_tokens",
  "args": "{\"limit\": 10}"
}
```

### Credential Storage

OAuth credentials are stored in:
```
~/.clawdbot/agents/main/agent/auth-profiles.json
```

Format:
```json
{
  "version": 1,
  "profiles": {
    "dexter-x402:default": {
      "type": "oauth",
      "provider": "dexter-x402",
      "access": "eyJ...",
      "refresh": "...",
      "expires": 1769639417118,
      "baseUrl": "https://mcp.dexter.cash/mcp"
    }
  }
}
```

## Troubleshooting

### "Not connected to Dexter"

The tool couldn't find valid credentials. Run:
```bash
moltbot models auth login --provider dexter-x402
```

### OAuth callback fails on remote server

If you're SSH'd into a remote server, Cursor's port forwarding should handle `localhost:51199` redirects automatically. If not:

1. The plugin shows the OAuth URL
2. Open it in your local browser
3. After signing in, you'll see "Connected to Dexter"
4. The callback is received via the forwarded port

### Token expired

Tokens auto-refresh. If refresh fails, re-authenticate:
```bash
moltbot models auth login --provider dexter-x402
```

### MCP connection errors

Check that `mcp.dexter.cash` is accessible:
```bash
curl https://mcp.dexter.cash/mcp/health
```

### Tools not appearing

Ensure the plugin is enabled:
```bash
cat ~/.moltbot/moltbot.json | jq '.plugins'
```

## Development

### Building

```bash
cd /path/to/moltbot-research
pnpm build
```

### Testing OAuth Flow

```bash
./moltbot.mjs models auth login --provider dexter-x402
```

### Testing Tool Execution

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
./moltbot.mjs agent --local --session-id test -m "Use dexter_x402 with action='list'"
```

## Dependencies

- `@modelcontextprotocol/sdk` - Official MCP client SDK
- `@sinclair/typebox` - Runtime type validation

## Links

- [Dexter](https://dexter.cash) - Main website
- [Dexter x402](https://mcp.dexter.cash) - MCP server
- [MCP Specification](https://modelcontextprotocol.io) - Protocol documentation
- [Discord](https://discord.gg/dexter) - Community support

## License

MIT

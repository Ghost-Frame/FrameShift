# MCP Server

Frameshift includes a stdio-based [Model Context Protocol](https://modelcontextprotocol.io/) server for integration with any MCP-capable agent -- Claude Code, Gemini CLI, Cline, opencode, Goose, IDE plugins, and anything else that speaks MCP.

No agent-specific knowledge lives in the MCP server. Every MCP-speaking agent that implements the protocol surfaces these tools and prompts the same way.

## Running

```bash
cargo run -p frameshift-mcp
# or if installed:
frameshift-mcp
```

The server communicates over stdin/stdout using JSON-RPC 2.0 (protocol version `2024-11-05`). Tracing output goes to stderr. Server name: `frameshift-mcp`, version `0.9.9`.

## Tools

Eight tools are exposed:

| Tool | Description |
|---|---|
| `frameshift_install` | Install a persona pack from a local path or marketplace |
| `frameshift_activate` | Set the active persona for the current project |
| `frameshift_list` | List installed personas and their status |
| `frameshift_grow_append` | Append an observation to a persona's growth log |
| `frameshift_select` | Score and rank personas for the current context and task |
| `frameshift_use` | Install, activate, and return the rendered persona in one call |
| `frameshift_automate` | Enable, disable, or query automate mode (on/off/status/lock/unlock) |
| `frameshift_prefs` | View or reset per-persona preference biases |

## Prompts

Three prompts provide context-aware persona management:

| Prompt | Purpose |
|---|---|
| `active_persona` | Load the currently active persona into the conversation |
| `select_persona` | Rank all installed personas and return a scored table |
| `automate_status` | Report automate mode state: on/off, active persona, recent transitions |

## Configuration

Add the MCP server to any agent that supports MCP servers via stdio transport:

```json
{
  "mcpServers": {
    "frameshift": {
      "command": "frameshift-mcp",
      "args": []
    }
  }
}
```

The exact configuration file depends on your agent:

- **Claude Code** -- `.mcp.json` in the project root or `~/.claude/mcp.json` globally
- **Gemini CLI** -- `settings.json` under `mcpServers`
- **Cline / opencode / Goose** -- See each agent's MCP server configuration docs
- **IDE plugins** -- VS Code, JetBrains, and others that support MCP have their own config format

## How it works internally

The MCP server is a thin stdio wrapper. It reads newline-delimited JSON-RPC requests from stdin, dispatches them to the same `frameshift-client` engine that the CLI uses, and writes JSON-RPC responses to stdout. There is no HTTP, no daemon dependency, and no background state -- each tool call is a standalone operation against the local project store.

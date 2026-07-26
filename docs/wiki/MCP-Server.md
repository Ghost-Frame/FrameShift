# MCP Server

FrameShift `0.10.0` includes a local stdio
[Model Context Protocol](https://modelcontextprotocol.io/) server. Any
MCP-capable host can expose the same tools and prompts without agent-specific
logic inside FrameShift.

## Running

```bash
cargo run -p frameshift-mcp
# or, if installed:
frameshift-mcp
```

The server exchanges JSON-RPC 2.0 messages over stdin and stdout. Diagnostic
tracing goes to stderr so it cannot corrupt the protocol stream. The maximum
input line is 8 MiB.

The newest implemented MCP protocol revision is `2025-11-25`. Initialization
also negotiates the supported `2025-06-18` and `2024-11-05` revisions for
compatible hosts.

## Tools

Sixteen tools are exposed:

| Tool | Description |
|---|---|
| `frameshift_install` | Install a persona pack for a project |
| `frameshift_activate` | Activate an installed persona |
| `frameshift_list` | List installed personas |
| `frameshift_grow_append` | Append a local growth observation |
| `frameshift_select` | Rank personas without changing active state |
| `frameshift_use` | Activate a persona and return its rendered content |
| `frameshift_automate` | Manage Automate policy with `on`, `off`, `status`, `lock`, or `unlock` |
| `frameshift_capabilities` | Report declared capabilities and annotate candidate agent tools |
| `frameshift_prefs` | Show, bump, decay, or reset preference biases |
| `frameshift_search` | Search the registry pack catalog |
| `frameshift_draft_create` | Create a private Creator Studio draft from a template, local source, or registry pack |
| `frameshift_draft_list` | List private Creator Studio drafts |
| `frameshift_draft_status` | Report a draft's lifecycle status and next valid actions |
| `frameshift_draft_preview` | Render a draft preview without granting publication authority |
| `frameshift_draft_read` | Read a bounded editable draft file |
| `frameshift_draft_write` | Replace a bounded editable draft file and invalidate stale review state |

`frameshift_automate` stores policy only. The connected host or FrameShift
daemon must invoke selection and activation.

### Creator Studio trust boundary

MCP can create, inspect, preview, and edit private drafts. It cannot perform
final artifact review or authorize a registry submission. Those actions bind
human intent to an exact artifact, publisher identity, and key, so they remain
available only through an interactive human-facing client.

There is intentionally no `frameshift_draft_review` MCP tool.

## Prompts

Three prompts provide context-aware persona management:

| Prompt | Purpose |
|---|---|
| `active_persona` | Load the currently active persona into the conversation |
| `select_persona` | Rank available personas and return a scored table |
| `automate_status` | Report Automate state, active persona, and recent transitions |

## Configuration

Add FrameShift to the host's stdio MCP server configuration:

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

Use the configuration location documented by your MCP host.

`FRAMESHIFT_PROJECT_ROOT` sets the default project root. A tool call's
`project_root` takes precedence; when neither is present, the server checks
Claude Code's `CLAUDE_PROJECT_DIR` and then the current working directory.
`FRAMESHIFT_TARGET` sets the default render target.

Start discovery workflows with `frameshift_search`. Start authoring workflows
with `frameshift_draft_create`, then query `frameshift_draft_status` before
choosing the next action.

## Runtime model

The MCP server is a thin local stdio wrapper around the same FrameShift engine
used by the CLI. It has no HTTP listener and does not require a background
daemon. Persistent project, persona, preference, and draft state remains in
the local FrameShift stores used by the underlying engine.

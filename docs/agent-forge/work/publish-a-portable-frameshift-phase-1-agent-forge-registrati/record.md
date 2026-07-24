> **Review priority:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved. The criteria were exercised, so read the decisions below for judgment rather than for correctness.

# Record: Publish a portable FrameShift Phase 1 Agent-Forge registration and Fluency record

- **spec:** `spec_93df3c6f`
- **type:** bugfix

## Acceptance criteria

- Codex, Claude Code, and Gemini CLI registrations resolve the installed agent-forge-mcp command
- Tracked client configuration contains no concrete user-home path
- The final Fluency record contains only portable relative verification evidence
- The Cloudflare access gate and application source remain unchanged

## Edge cases

- A generated review quotes the concrete string it was searching for
- A client launches from outside the repository
- The installed binary is absent from PATH
- A project config accidentally embeds a user-home path
- Existing application and access-gate files must remain byte-identical to origin/main

## Interface contract

```text
FrameShift publishes command-only stdio MCP registration for project-aware clients while user-scoped Codex registration remains local; generated Fluency evidence must pass the installed fail-closed path guard.
```

## Decision: Create a clean final spec with portable evidence

- **why:** Preserve the rejected artifact outside public paths and emit a new record whose verification commands use relative files and structural assertions.
- **alternative:** Redact rendered evidence automatically -- rejected: Mutates evidence; Hides the root cause; Broader change than FrameShift registration requires
- **trust:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved

## Verification evidence

- `sh -c 'command -v agent-forge-mcp >/dev/null && codex mcp get agent-forge >/dev/null && claude mcp get agent-forge >/dev/null'` -- passed
- `jq -e '.mcpServers["agent-forge"].command == "agent-forge-mcp" and ((.mcpServers["agent-forge"].args // []) | length == 0)' .mcp.json .gemini/settings.json` -- passed
- `sh -c 'printf "%s\n" '"'"'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"review","arguments":{"spec_id":"spec_be3710ba","repo_root":".","write":false}}}'"'"' | agent-forge-mcp | jq -e '"'"'.result.isError == true and (.result.content[0].text | contains("absolute home path"))'"'"''` -- passed
- `git diff --quiet origin/main -- crates scripts .github README.md` -- passed

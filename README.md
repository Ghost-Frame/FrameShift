<p align="center">
  <img src="personas/assets/banner.png" alt="FrameShift specialists moving modular frame plates through a physical studio" width="100%" />
</p>

# FrameShift

Versioned behavioral identity for AI coding agents.

FrameShift packages a persona's behavior, constraints, skills, and operating posture into a project-scoped runtime. One pack can render the instruction format expected by Claude Code, Codex, Gemini CLI, or a generic agent host. Packs are content-addressed, signed by their publishers, and locked per project.

[Get FrameShift Desktop](https://download.frameshift.syntheos.dev/) · [Desktop source](https://github.com/Ghost-Frame/FrameShift-Desktop) · [CLI releases](https://github.com/Ghost-Frame/FrameShift/releases) · [Documentation](docs/wiki/Home.md) · [Marketplace](https://frameshift.syntheos.dev/)

> **Pre-release:** The CLI, runtime, MCP server, watch daemon, and registry API are available. Hosted desktop downloads, the browser marketplace, and account features remain access-gated while release validation finishes.

FrameShift is not an `AGENTS.md` swapper. It treats behavioral identity as software: versioned, composable, inspectable, and portable across agent hosts.

## Start here

### Desktop

FrameShift Desktop is the shortest path from discovery to an active persona:

1. [Download the current build](https://download.frameshift.syntheos.dev/).
2. Open the project where you use an AI coding agent.
3. Browse Marketplace, install a persona, and activate it for that project.
4. Open Settings, choose your agent, and select Connect.

The desktop app installs its bundled CLI and MCP server when it connects an agent. Its complete public source, build instructions, and release provenance live in [Ghost-Frame/FrameShift-Desktop](https://github.com/Ghost-Frame/FrameShift-Desktop).

### Command line

Download the newest archive from the [releases list](https://github.com/Ghost-Frame/FrameShift/releases), verify it against `SHA256SUMS`, and put both `frameshift` and `frameshift-mcp` on your `PATH`. Use the releases list instead of a `releases/latest` URL while early-access builds are published as prereleases.

Then run these commands from the project FrameShift should manage:

```bash
frameshift install cryptographic
frameshift use cryptographic --target codex
```

Valid render targets are `claude`, `codex`, `gemini`, and `generic`. For local pack development:

```bash
frameshift install cryptographic@0.1.0 --from-path /path/to/cryptographic
frameshift use cryptographic --target generic
```

See [Getting Started](docs/wiki/Getting-Started.md) for platform notes, release archives, checksums, project selection, and first-run verification.

## What FrameShift guarantees

| Concern | FrameShift behavior |
| --- | --- |
| Project scope | Installation and activation are recorded against one project. The active version is pinned in that project's lock state. |
| Pack identity | A canonical SHA-256 identifies the logical pack contents independent of archive compression. |
| Publisher identity | Ed25519 signatures bind a pack hash to the publisher key that signed it. Account-backed publishers add ownership and key lifecycle records. |
| Host output | One persona can render native instructions for Claude Code, Codex, Gemini CLI, or a generic Markdown host. |
| Declared access | Capability manifests describe required tools, network egress, filesystem scope, and memory expectations before activation. |
| Local state | Installed objects live in a central store outside the project tree. The project retains its lock and configuration, not duplicated pack bodies. |

The detailed hashing, signing, trust, extraction, and publisher rules are documented in [Trust and Security](docs/wiki/Trust-and-Security.md).

## How it works

```text
persona source -> rendered pack -> hash and signature -> verified install -> project lock -> agent-native activation
```

A pack combines a typed manifest with behavioral content. Authors can use a freeform agent body or structured TOML source when they need composition and semantic editing. FrameShift renders the target-specific output, verifies the pack contract, stores content by hash, and activates the selected version without copying an unmanaged instruction tree into every project.

Automate mode lets a host integration rank installed personas against the task and project context. It records the mode, sensitivity, preferences, lock state, and transition history per project. Enabling it does not switch personas by itself; the host decides when to select and activate a result.

```bash
frameshift automate on --sensitivity 0.7
frameshift select --task "review this authentication boundary" --format json
```

The public [`personas/`](personas/) directory is a manifest catalog. Install public personas from the registry unless you also have their complete behavioral source. Read [How It Works](docs/wiki/How-It-Works.md), [Pack Format](docs/wiki/Pack-Format.md), and [Automate Mode](docs/wiki/Automate-Mode.md) for the full model.

## Connect an AI agent with MCP

`frameshift-mcp` lets an agent search, install, select, activate, and inspect personas through the Model Context Protocol. Install the release binaries first, then add the server from the project it should manage.

<details>
<summary>Claude Code</summary>

```bash
claude mcp add --scope local --transport stdio \
  --env FRAMESHIFT_TARGET=claude \
  frameshift -- frameshift-mcp
```

Claude Code supplies the project root. Run `/mcp` and confirm that `frameshift` is connected.

</details>

<details>
<summary>Codex</summary>

```bash
codex mcp add frameshift \
  --env FRAMESHIFT_TARGET=codex \
  --env FRAMESHIFT_PROJECT_ROOT=/absolute/path/to/your/project \
  -- frameshift-mcp
```

Run `/mcp` and confirm that `frameshift` is connected. Use a distinct server name for each fixed project entry.

</details>

<details>
<summary>Gemini CLI</summary>

```bash
gemini mcp add --scope project \
  --env FRAMESHIFT_TARGET=gemini \
  frameshift frameshift-mcp
```

Gemini stores this entry in the current project. Run `gemini mcp list` to confirm the connection.

</details>

Project resolution follows the explicit tool argument, `FRAMESHIFT_PROJECT_ROOT`, the host-provided project directory, then the MCP process working directory. See [MCP Server](docs/wiki/MCP-Server.md) for tool coverage, prompts, defaults, and multi-project setups.

## Create and publish

Local persona authoring does not require a hosted account. A complete pack can use a freeform instruction body, structured TOML source, or a composition of parent and mixin packs. Conformance bundles keep expected behavior testable as a persona evolves.

Registry publishing uses signed publisher identity and exact-snapshot review. Account creation and publisher management remain invite-only during the current release phase. Start with [Writing Personas](docs/wiki/Writing-Personas.md), then use [Composition](docs/wiki/Composition.md), [Conformance](docs/wiki/Conformance.md), and [Publishing and Moderation](docs/wiki/Publishing-and-Moderation.md) as needed.

## Repository and development

- [`crates/`](crates/) contains the Rust workspace: CLI, runtime, pack tooling, composition, conformance, memory, object storage, registry server, MCP server, watch daemon, orchestration, and selection.
- [`personas/`](personas/) contains the public persona manifest catalog and project artwork.
- [`docs/wiki/`](docs/wiki/) contains the maintained user, author, security, and operator documentation.

Source builds require Rust 1.88 or newer. The full workspace also requires the PostgreSQL client library used by Diesel (`libpq-dev` on Debian or Ubuntu, `libpq` on macOS).

```bash
cargo build --locked --workspace
cargo test --locked --workspace
```

Install the CLI from a source checkout with:

```bash
cargo install --locked --path crates/frameshift-cli
```

Report security issues through [GitHub private vulnerability reporting](https://github.com/Ghost-Frame/FrameShift/security/advisories/new). Do not include credentials or sensitive user data in a public issue. See [SECURITY.md](SECURITY.md) for the supported reporting process.

## Documentation

| Need | Start here |
| --- | --- |
| Install and orient | [Getting Started](docs/wiki/Getting-Started.md) · [How It Works](docs/wiki/How-It-Works.md) · [Troubleshooting](docs/wiki/Troubleshooting.md) |
| Use agents and automation | [MCP Server](docs/wiki/MCP-Server.md) · [Automate Mode](docs/wiki/Automate-Mode.md) · [CLI Reference](docs/wiki/CLI-Reference.md) |
| Build personas | [Writing Personas](docs/wiki/Writing-Personas.md) · [Pack Format](docs/wiki/Pack-Format.md) · [Composition](docs/wiki/Composition.md) · [Conformance](docs/wiki/Conformance.md) |
| Understand trust and privacy | [Trust and Security](docs/wiki/Trust-and-Security.md) · [Local Data and Privacy](docs/wiki/Local-Data-and-Privacy.md) · [Known Limits](docs/wiki/Security-Reporting-and-Known-Limits.md) |
| Publish and manage identity | [Accounts and Publisher Identity](docs/wiki/Accounts-and-Publisher-Identity.md) · [Creator Studio](docs/wiki/Creator-Studio.md) · [Publishing and Moderation](docs/wiki/Publishing-and-Moderation.md) |
| Operate or extend | [Architecture](docs/wiki/Architecture.md) · [Configuration](docs/wiki/Configuration.md) · [Memory Integration](docs/wiki/Memory-Integration.md) · [Operations](docs/wiki/Operations-and-Observability.md) |

## License

FrameShift source code is available under the [Elastic License 2.0](LICENSE). Persona packs can declare their own licenses.

Elastic License 2.0 does not permit offering FrameShift to third parties as a hosted or managed service. Commercial terms for hosted or managed offerings are available from `support@syntheos.dev`.

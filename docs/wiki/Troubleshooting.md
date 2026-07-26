# Troubleshooting

Start by confirming which binary and project FrameShift is using:

```bash
frameshift --version
frameshift project-id
frameshift list
```

FrameShift resolves the project from the current directory. Its managed state
is in the central data root, not normally in the repository.

## Install and sync failures

For a registry install, a content-hash mismatch, missing signature, signer-key
change, publisher change, or ownership mismatch is a hard trust failure. Do
not bypass it by copying the downloaded files into place. Confirm the registry
and requested version, then retry only after the publisher or registry record
is corrected.

A direct local-path install permits an unsigned pack. Use it only when you
trust and have reviewed that local source.

If an installed persona is in the lock but its cache or materialized files are
missing, run:

```bash
frameshift sync
```

The command reports failures per persona. Reinstall the exact locked source if
the required cache entry is no longer available.

## Activation failures

`persona is not present in frameshift.lock` means the persona is not installed
for this project. Check `frameshift list`, then install it before activation.

A persona with `memory_required = "hard"` will not activate until the central
project `config.toml` declares a `[memory]` adapter. A soft requirement only
warns.

For a templated persona, an activation error lists every missing required vault
token. Initialize the vault if necessary, set each named key, then activate
again:

```bash
frameshift vault init
frameshift vault set <key>
frameshift activate <persona>
```

Do not run `vault init` over an existing vault; the command refuses to
overwrite one.

## Automate does not switch

Check policy and ranking independently:

```bash
frameshift automate status
frameshift select --task "describe the current task" --format json
```

Automate stores project policy but does not run an autonomous background loop.
A connected host integration or daemon must invoke selection and activation.
An Automate lock pins the current persona until `frameshift automate unlock`.
Selection sensitivity and hysteresis can also keep the current persona when a
candidate's score improvement is too small.

Use `frameshift prefs show` to inspect learned biases. Use
`frameshift feedback` to record a correction or `frameshift prefs reset` to
clear the current project's biases.

## MCP connection problems

Run the stdio server as `frameshift-mcp`; do not send log text over its standard
output because that stream carries JSON-RPC messages. FrameShift supports MCP
protocol dates `2025-11-25`, `2025-06-18`, and `2024-11-05`.

If initialization succeeds but a tool is unavailable, compare the advertised
tool list with [[MCP Server]]. Creator Studio intentionally has no MCP tool for
final review confirmation or submission intent.

`frameshift_capabilities` is advisory. A host refusing a tool is a host
permission decision, not an MCP capability-filter malfunction.

## Vault problems

The CLI reads `FRAMESHIFT_VAULT_PASSPHRASE` first and otherwise prompts
secretly only in an interactive terminal. The daemon and MCP server cannot
prompt; set the environment variable in their private launch environment.

A wrong passphrase, damaged ciphertext, or unsupported vault schema is
reported as a vault-open failure. FrameShift has no passphrase recovery.
Restore your own known-good backup rather than reinitializing over the file.

`frameshift vault list` shows keys without values. Remember that
`frameshift vault get <key>` deliberately prints the raw value.

## Conformance failures

Exactly one input mode is required:

```bash
frameshift verify --persona <persona> --runner mock
frameshift verify --bundle <directory> --runner mock
```

The CLI runner requires `--persona`. A conformance integrity failure means the
declared baseline bundle hash does not match the shipped bundle. FrameShift
blocks an upgrade by default because that evidence may have been modified.
Investigate and republish the pack rather than suppressing the check.

## Account and publisher-key problems

Use read-only status commands first:

```bash
frameshift account status
frameshift keys list
frameshift keys remote-list --server <registry-url> --publisher <handle>
```

Login requires a usable system browser, an exact IP-loopback callback, and a
native credential store. Logout attempts provider revocation and then removes
the local session.

Publisher-key actions can affect release identity. Use
`frameshift keys <action> --help` before `select`, `enroll`, `rotate`, `revoke`,
`remote-revoke`, `recover`, `export`, or `import`. A manifest signer mismatch
means the selected publisher key does not match `author_pubkey`.

## Publishing and Creator Studio

Publication errors include the complete blocking validation report. Resolve
every reported public-inventory, schema, render, scanner, or conformance
finding and prepare a new artifact. Do not reuse a prior review after editing;
any draft mutation invalidates the review and submission binding.

For an MCP-managed draft, inspect `frameshift_draft_status` and
`frameshift_draft_preview`, make the necessary draft edit, then inspect the new
status. Final confirmation remains a human-client operation.

If the issue is not covered here, use the command's exact help:

```bash
frameshift <command> --help
```

For suspected vulnerabilities, use [[Security Reporting and Known Limits]]
rather than a public issue.

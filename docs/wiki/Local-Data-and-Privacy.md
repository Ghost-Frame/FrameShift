# Local Data and Privacy

FrameShift keeps its managed state outside project repositories. When
`XDG_DATA_HOME` is set, the data root is
`$XDG_DATA_HOME/frameshift`; otherwise it is
`$HOME/.local/share/frameshift`.

## What is stored locally

The central data root can contain:

- `cache/<canonical-hash>/`: content-addressed pack copies.
- `identity/`: local publisher-key material.
- `studio/drafts/<draft-id>/`: Creator Studio draft metadata and content.
- `projects/<project-id>/`: one project's configuration, lock, active marker,
  Automate policy and preferences, audit logs, selection history, vault, and
  materialized personas.

The default project ID is derived from the canonical project-root path.
`FRAMESHIFT_PROJECT_ID` can supply an explicit validated ID when a stable
cross-path identity is required.

Growth entries are local and append-only. FrameShift writes structured growth
to `growth.jsonl` and maintains the legacy `growth.md` view. Project selection
history is also an append-only JSONL record containing the persona, session
identifier, automatic/manual flag, optional rationale, and timestamp.
Selection preferences are stored separately and are the data the selection
engine actually reads.

## Telemetry

Selection telemetry is off by default:

```bash
frameshift config get telemetry_opt_in
```

Only an explicit setting enables it:

```bash
frameshift config set telemetry_opt_in true
```

When enabled, a selection event sends the persona name, a fresh random session
identifier, a random project identifier created for telemetry, and a
timestamp. It does not send filesystem paths or the locally recorded
selection rationale. The endpoint follows the configured registry unless
`FRAMESHIFT_TELEMETRY_URL` overrides it.

Disable future sends with:

```bash
frameshift config set telemetry_opt_in false
```

Disabling telemetry does not erase existing local configuration or data
already received by a configured endpoint.

## Account sessions

Account login uses an OIDC authorization-code flow with S256 PKCE, state, and
nonce validation. Access and refresh tokens are stored only through the
operating system's native credential store. The adjacent JSON metadata contains
non-secret issuer, client, registry, scope, and expiry information.

`frameshift account logout` attempts provider revocation, then removes the
exact local credential and its metadata. A provider being unreachable does not
turn the token into a local plaintext file.

## Vault privacy

Persona template-token values live in the per-project `vault.age`, never in the
project root or pack. The vault is age-encrypted with a passphrase.

Prefer the hidden prompt for values:

```bash
frameshift vault set principal_address
```

`frameshift vault list` prints keys only. `frameshift vault get <key>` prints
the raw value to standard output, and `vault set --value` places the supplied
value in the process arguments; use those forms only when their exposure is
acceptable. FrameShift has no built-in passphrase recovery.

## Removal and export boundaries

FrameShift does not provide one global "export everything" or "delete
everything" command.

- `frameshift uninstall <persona>` removes a persona from the current project
  and rematerializes project state.
- `frameshift gc` removes central-cache entries that no project lock references.
- `frameshift prefs reset` clears the current project's learned selection
  biases.
- `frameshift vault rm <key>` removes one vault value.
- `frameshift account logout` removes the current account session.
- Publisher keys have explicit `export`, `import`, `revoke`, and
  `remote-revoke` actions; inspect action-specific help before changing them.
- Local JSONL history and growth files can be copied as ordinary files. There
  is no dedicated history-export command.

These operations have different scopes. Inspect `frameshift project-id` and
the central project directory before removing data, especially when multiple
projects share the cache.

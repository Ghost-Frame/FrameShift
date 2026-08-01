# CLI Reference

This page documents the FrameShift `0.10.0` command surface. Run
`frameshift --version` to check the binary on your path and
`frameshift <command> --help` for the complete option set accepted by that
binary.

## Installation

Build the CLI from this workspace:

```bash
cargo build --release -p frameshift-cli
```

The binary is named `frameshift`.

## Command index

| Command | Purpose |
|---|---|
| `account` | Register, log in, inspect, or end an account session |
| `install` | Install a persona pack into the central store |
| `activate` | Activate an installed persona for the current project |
| `uninstall` | Remove an installed persona from the current project |
| `list` | List personas installed for the current project |
| `sync` | Reconcile the central store with the project lockfile |
| `gc` | Remove unreferenced central-cache entries |
| `project-id` | Print the current project's stable ID |
| `rule` | Add or remove a typed rule in persona source |
| `skill` | Add or remove a typed skill in persona source |
| `diff` | Compare two persona sources semantically |
| `render` | Render persona source for an agent target |
| `migrate` | Move legacy project files into the central store |
| `grow` | Append, inspect, or summarize local growth |
| `verify` | Run persona conformance checks |
| `publish` | Package a persona locally or publish it to a registry |
| `publication` | Review, submit, inspect, withdraw, and appeal account-backed publications |
| `moderation` | Inspect, decide, and promote quarantined submissions |
| `register` | Register this machine's author key under a registry handle |
| `keys` | Manage local and account-enrolled publisher keys |
| `search` | Search the registry pack catalog |
| `select` | Rank personas without activating one |
| `use` | Activate a persona and print its rendered output |
| `automate` | Manage per-project Automate policy |
| `prefs` | Inspect or adjust selection preference biases |
| `feedback` | Record a selection override for preference learning |
| `config` | Get or set current-project configuration |
| `vault` | Manage encrypted template-token values |

## Persona lifecycle

### `frameshift account <ACTION>`

Use `register`, `login`, `status`, or `logout` to manage the current account
session. Registration and first-party login collect secrets only through hidden
interactive prompts. `login --first-party` selects password login when the
registry also advertises OIDC.

### `frameshift install [OPTIONS] <SPEC>`

Install a persona by `name@version`. Use `--from-path <PATH>` to install from a
local pack directory instead of the registry.

```bash
frameshift install cryptographic@0.1.0 --from-path ./personas/cryptographic
```

### `frameshift activate <PERSONA>`

Activate an installed persona for the current project.

### `frameshift uninstall <PERSONA>`

Remove an installed persona from the current project.

### `frameshift list`

List the personas installed for the current project.

### `frameshift sync`

Reconcile installed content with the project lockfile and report any
materialization failures.

### `frameshift gc`

Remove central-cache entries that no project lockfile references.

### `frameshift use [OPTIONS] <NAME>`

Activate a persona and print its rendered content. `--from <DIR>` installs
`<DIR>/<NAME>` first if the persona is not already installed. `--target`
selects `claude`, `codex`, `gemini`, or `generic`; the default is `generic`.

```bash
frameshift use cryptographic --from ./personas --target codex
```

### `frameshift project-id`

Print the SHA-256 project ID derived from the canonical project-root path.

## Discovery and Automate

### `frameshift search [QUERY] [--tag <TAG>] [--limit <COUNT>]`

Search the registry catalog by text and optional tag.

### `frameshift select [--task <TEXT>] [--library <DIR>] [--format table|json]`

Rank personas without changing active state. Table output is the default. JSON
output includes the context snapshot, component scores, matches, and rationale.

```bash
frameshift select --task "debug a rust compilation error"
frameshift select --task "debug a rust compilation error" --format json
```

### `frameshift automate <ACTION>`

Actions are `on`, `off`, `status`, `lock`, and `unlock`. `on` accepts an
optional sensitivity from `0.0` to `1.0`.

Enabling Automate stores project policy. It does not independently select or
activate a persona. A connected host or the FrameShift daemon must run the
selection and activation loop. `lock` pins the current persona; `unlock`
allows the host loop to switch again.

### `frameshift prefs <ACTION>`

Actions are `show`, `bump`, `decay`, and `reset`. The mutation actions operate
on per-persona preference biases used by selection.

### `frameshift feedback --chosen <PERSONA> [OPTIONS]`

Record a manual selection override. Optional fields include the automatic
pick, task, inferred intent, and reason.

```bash
frameshift feedback --auto-pick frontend --chosen rust --intent debugging
```

## Source authoring and growth

### `frameshift rule add|remove`

Modify typed rules in a persona's `rules.toml`.

### `frameshift skill add|remove`

Modify typed skills in a persona's `skills.toml`.

### `frameshift diff [--json] <PERSONA_A> <PERSONA_B>`

Compare two persona sources. The report covers rule, skill, voice, and anchor
changes; `--json` emits machine-readable output.

### `frameshift render [--target <TARGET>] <PERSONA>`

Render source for `claude`, `codex`, `gemini`, or `generic`.

### `frameshift migrate`

Move supported legacy project files into the central FrameShift store.

### `frameshift grow <ACTION>`

`append` records a local observation, `log` reads growth history, and `summary`
produces the deduplicated summary.

```bash
frameshift grow append --persona rust --text "Prefer a newtype when trait coherence blocks a direct implementation."
```

## Verification, identity, and publishing

### `frameshift verify [OPTIONS]`

Run conformance checks. Exactly one of `--persona <PERSONA>` or
`--bundle <DIR>` is required. Optional controls include `--canned-response`,
`--threshold`, `--runner mock|cli`, and `--model`. The `cli` runner requires
`--persona`.

```bash
frameshift verify --persona rust --runner mock
```

### `frameshift register --server <URL> --handle <HANDLE> [--display-name <NAME>]`

Register this machine's author key under a registry handle.

### `frameshift keys <ACTION>`

Manage publisher keys. Available actions are `init`, `list`, `create`, `label`,
`select`, `enroll`, `remote-list`, `rotate`, `revoke`, `remote-revoke`,
`recover`, `export`, and `import`. Use the action-specific `--help` before a
mutation.

### `frameshift publish --persona <PERSONA> [OPTIONS]`

Package a persona into `--out <DIR>` or publish it through `--server <URL>`
under `--handle <HANDLE>`.

### `frameshift publication <ACTION>`

Use `review` to bind human confirmation to an exact Creator Studio snapshot,
`submit` to create the authenticated publication intent and upload that signed
snapshot, and `status` to inspect the resulting submission. Use `withdraw` for
an eligible non-public submission, `decisions` for immutable publisher-scoped
lifecycle evidence, `appeal` for one adverse moderation decision, and `appeals`
for private appeal history. The submit command requires separate confirmations
for the archive hash, publisher, signer key, and submission intent.

```bash
frameshift publication withdraw --server https://registry.example --submission-id <UUID> --reason-code author_request
frameshift publication decisions --server https://registry.example --publisher alice
frameshift publication appeal --server https://registry.example --publisher alice --decision-id <UUID> --statement "The unchanged artifact meets policy."
frameshift publication appeals --server https://registry.example --publisher alice
```

Withdrawal and appeal failures print the generated operation and request UUID
flags so an ambiguous request can be retried exactly. Decision and appeal
history use newest-first keyset pagination with a bounded `--limit`; supply
`--before-created-at` and `--before-id` together to request the next page.

### `frameshift moderation <ACTION>`

Active moderators and administrators can inspect a known submission UUID with
`show`, download its exact quarantine archive with `artifact`, apply `approve`,
`request-changes`, or `reject` with `decide`, and publish an approved submission
with `promote`. Active administrators can also suspend publishers, tombstone
public releases, inspect global lifecycle and appeal evidence, and resolve
appeals. The server enforces role membership, lifecycle transitions, and
independent-review separation.

```bash
frameshift moderation show --server https://registry.example --submission-id <UUID>
frameshift moderation artifact --server https://registry.example --submission-id <UUID> --out submission.tar.gz
frameshift moderation decide --server https://registry.example --submission-id <UUID> --action approve --reason-code reviewed
frameshift moderation promote --server https://registry.example --submission-id <UUID>
frameshift moderation suspend-publisher --server https://registry.example --publisher-id <UUID> --reason-code policy.abuse
frameshift moderation tombstone --server https://registry.example --name reviewed-pack --version 1.0.0 --reason tos-violation
frameshift moderation decisions --server https://registry.example
frameshift moderation appeals --server https://registry.example
frameshift moderation resolve-appeal --server https://registry.example --appeal-id <UUID> --disposition overturn --rationale "Independent evidence supports reversal."
```

`artifact` refuses to overwrite its destination. Mutation failures print the
generated operation and request UUID flags so an ambiguous request can be
retried with the same identifiers. Global decision and appeal listings use
newest-first pagination with a bounded `--limit`; supply `--before-created-at`
and `--before-id` together for the next page.

## Project configuration and vault

### `frameshift config get|set`

Read or update a key in the current project's central `config.toml`.

### `frameshift vault <ACTION>`

Actions are `init`, `set`, `get`, `rm`, and `list`. The vault holds encrypted
values used to resolve persona template tokens.

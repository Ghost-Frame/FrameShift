# Publishing and Moderation

Account-backed publication is a staged process. It separates local authoring,
human approval, signed submission, quarantine, moderation, and public
promotion so that none of those transitions can silently stand in for another.

## Before submission

The publisher needs:

1. an authenticated account with an active membership in the publisher
   profile;
2. an active enrolled device key;
3. a valid Creator Studio snapshot;
4. final human review bound to the exact artifact, publisher, and key; and
5. a separate submission-intent confirmation with the same binding.

The client creates an authenticated publication intent for that exact
publisher, key, and artifact. Submission then uses both the account bearer
token and an Ed25519-signed request. A local manifest without a valid signature
cannot enter the account-backed publication pipeline, and the selected signer
must match the manifest's `author_pubkey`.

The `frameshift publication review`, `submit`, and `status` commands expose the
account-backed workflow through the CLI. Final submission is not exposed
through the MCP server.

## Quarantine and review

A successful upload enters quarantine; it does not become a public release.
The server rechecks the bounded archive and the publication report before
admitting the submission.

Submission states are:

- `Quarantined`
- `NeedsReview`
- `Approved`
- `Rejected`
- `Promoted`
- `Withdrawn`

An authorized moderator can approve, request changes, or reject a submission.
Promotion is a distinct step that registers the reviewed artifact as an active
public release. A request for changes or rejection does not mutate the submitted
artifact; the publisher prepares and submits a new exact snapshot when content
must change.

The role-gated CLI accepts the submission UUID returned to the publisher:

```bash
frameshift moderation show --server https://registry.example --submission-id <UUID>
frameshift moderation artifact --server https://registry.example --submission-id <UUID> --out submission.tar.gz
frameshift moderation decide --server https://registry.example --submission-id <UUID> --action approve --reason-code reviewed
frameshift moderation promote --server https://registry.example --submission-id <UUID>
```

The artifact command writes to a new destination and refuses to replace an
existing file. The server still enforces active moderator or administrator
membership and requires an independent reviewer for artifact access and
promotion.

## Withdrawal and decisions

A publisher owner can withdraw an eligible non-public submission. Withdrawal
does not erase the audit trail and cannot be used as a silent replacement for a
release that is already public.

Accepted lifecycle transitions and their reasons are recorded as immutable
decision evidence. Publisher owners can read the decision stream scoped to
their publisher profile.

## Appeals

A publisher owner may file one appeal within 30 days of a `request_changes` or
`reject` decision. An administrator resolves it by either:

- `uphold`, which preserves the adverse state; or
- `overturn`, which approves the exact unchanged submission.

The original reviewer cannot resolve the appeal when another active
administrator is available. A sole administrator must record a bounded
separation exception. Appeal filing and resolution use caller-generated request
IDs so retries cannot silently become different actions.

## Suspension and tombstones

Publisher suspension blocks publisher authority without rewriting historical
release evidence. An administrator can also tombstone an active release.

A tombstone is a one-way public removal transition with an explicit reason and
audit evidence. Direct downloads stop serving the tombstoned version, and the
catalog recomputes the latest version from the remaining active releases.
Historical signer and decision records remain evidence of what happened.

## Legacy CLI publication is different

`frameshift publish --server ... --handle ...` is the older author-handle
upload path. It builds a pack from an installed persona and can use
`FRAMESHIFT_ACCESS_TOKEN`, but it does not expose the Creator Studio human
review, account-backed publication intent, quarantine review, or submission
confirmation workflow described above.

Use [[Creator Studio]] for the safe authoring boundary and
[[Accounts and Publisher Identity]] for publisher and device-key ownership.
See [[Trust and Security]] for pack verification after promotion.

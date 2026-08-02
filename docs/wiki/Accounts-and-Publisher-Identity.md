# Accounts and Publisher Identity

You do not need a FrameShift account to browse the public catalog, install a
persona, or use personas locally. An account becomes relevant when you publish:
it owns publisher profiles, authorizes device-key enrollment and recovery, and
provides durable server-side publication history.

Registration is invite-only. You can submit an invite application through the
marketplace, but an application does not create an account or guarantee an
invitation. A reviewer must approve the application and issue a single-use,
email-bound invitation before registration.

FrameShift does not treat an account password or login session as the signing
identity. A publisher has a stable UUID, while individual devices hold
rotatable Ed25519 signing keys.

## First-party account sessions

The registry exposes first-party account routes at:

| Route | Purpose |
|---|---|
| `POST /v1/auth/register` | Redeem an unexpired invitation and create an account |
| `POST /v1/auth/login` | Verify an Argon2id password and create a new session |
| `POST /v1/auth/logout` | Revoke the current first-party session |

Invite redemption binds the account to the invitation email and marks that
email verified. The server consumes the invitation, creates the account and
credential, and creates the first session in one database transaction. A
second redemption cannot reuse the invitation.

Browser clients receive a Secure, HttpOnly, SameSite=Strict cookie and must
send an exact configured Origin for registration, login, and authenticated
writes. Desktop and CLI clients request an explicit bearer session. The
registry stores only SHA-256 token digests, so it cannot recover an issued
invite or session token from the database.

## Password policy

New first-party passwords must contain at least 15 Unicode scalar values and
at most 1,024 UTF-8 bytes. FrameShift does not impose character-class or
composition rules. It preserves the accepted password bytes exactly for
Argon2id hashing.

Password creation also rejects known compromised values and expected
FrameShift-specific variants. Comparison ignores outer whitespace and ASCII
case, but that normalization is used only for the blocklist lookup. Login does
not apply creation policy, so a credential created under an older policy can
still be verified and migrated safely.

The embedded baseline comes from [SecLists commit
`e5e49caa6fb648476f3bca391b26a45a4f5d3f13`](https://github.com/danielmiessler/SecLists/blob/e5e49caa6fb648476f3bca391b26a45a4f5d3f13/Passwords/Common-Credentials/xato-net-10-million-passwords-100.txt), file
`Passwords/Common-Credentials/xato-net-10-million-passwords-100.txt`. The
source file SHA-256 is
`3b9909eacc7322317399992a2d308b04be3ab903f06bfc935fc4c5796235531e`.
FrameShift stores only sorted SHA-256 digests of lowercase comparison values
in `crates/frameshift-server/src/password_blocklist.txt`. Reviewable
FrameShift-specific values remain explicit in `password_blocklist.rs`.

To update the baseline, pin a reviewed SecLists commit, fetch that exact file,
verify and record its SHA-256, remove blank lines, lowercase ASCII, append the
reviewed FrameShift-specific variants in the Rust source when needed, hash each
source-list value without a trailing newline, then sort and deduplicate the
digest lines. Update the commit, source hash, and provenance here in the same
change. Run the server password-policy tests and review both blocklist diffs
before committing.

## Sign in securely

```bash
frameshift account register
frameshift account login
frameshift account login --first-party
frameshift account status
frameshift account update-profile --server https://frameshift-api.syntheos.dev --display-name "YOUR NAME"
```

`frameshift account register` redeems a single-use invitation through hidden
terminal prompts. `frameshift account login` uses the registry's advertised
provider, preferring OIDC when both OIDC and first-party login are available.
Use `--first-party` to select password login explicitly. OIDC opens the provider
in your system browser and uses an exact IP-loopback callback with S256 PKCE.

The CLI accepts no password or invitation through arguments or environment.
First-party credentials require an interactive terminal, and secret values use
hidden prompts. OIDC and first-party bearer credentials remain in the operating
system's native credential store. Provider-tagged JSON metadata in the managed
FrameShift data directory contains no token.

`account status` asks the registry for the authenticated account and its
publisher memberships. `account logout` requests the matching provider's
revocation endpoint and then removes the exact local credential and metadata.

A saved session is bound to the registry used during login. Remote key commands
reuse and refresh that session only when their `--server` value names the same
registry base URL. For another registry, set `FRAMESHIFT_ACCESS_TOKEN` or enter
a token at the hidden interactive prompt. FrameShift never accepts an account
token as a command-line argument or prints it.

## Publisher profiles and memberships

A publisher profile is the durable owner shown with account-backed releases.
Its handle is the public name; its UUID is the stable identity used for
ownership checks even if display metadata changes.

Anyone can inspect the public profile without an account session:

```bash
frameshift account show-publisher \
  --server https://frameshift-api.syntheos.dev \
  --handle PUBLISHER_HANDLE
```

Publisher operations require an active account membership with the appropriate
role. Create the profile from the authenticated CLI session:

```bash
frameshift account create-publisher \
  --server https://frameshift-api.syntheos.dev \
  --handle YOUR_PUBLISHER_HANDLE \
  --display-name "YOUR PUBLISHER NAME" \
  --biography "OPTIONAL PUBLIC BIOGRAPHY"
```

The profile begins in pending moderation, and the registry creates an active
owner membership for the authenticated account. Confirm both records with
`frameshift account status` before enrolling a device.

Owners can replace public metadata later. The display name is required on every
update. Omit both biography options to keep the existing biography, provide
`--biography` to replace it, or use `--clear-biography` to remove it.

```bash
frameshift account update-publisher \
  --server https://frameshift-api.syntheos.dev \
  --handle YOUR_PUBLISHER_HANDLE \
  --display-name "UPDATED PUBLISHER NAME" \
  --clear-biography
```

Publisher updates require an active owner membership and a fresh authentication
session.

## Create and enroll a device key

Initialize local key storage, then inspect it:

```bash
frameshift keys init
frameshift keys list
```

Private key material prefers the native credential store. When that is
unavailable, FrameShift uses an age-encrypted fallback unlocked by
`FRAMESHIFT_KEY_PASSPHRASE` or a hidden prompt.

Create a labeled key and enroll either that key or the currently selected key:

```bash
frameshift keys create --label "workstation"
frameshift keys enroll \
  --server https://frameshift-api.syntheos.dev \
  --publisher YOUR_PUBLISHER_HANDLE
frameshift keys remote-list \
  --server https://frameshift-api.syntheos.dev \
  --publisher YOUR_PUBLISHER_HANDLE
```

The first local key becomes selected automatically. Later keys are created
without changing the selection. `frameshift keys select KEY_ID` changes which
active local key future signing operations use.

The server requires both the authenticated publisher owner and a signature from
an active enrolled key for account-backed publisher writes. The login session
proves account authority; the device key proves control of a registered signer.

## Rotate, revoke, and recover

Rotate a selected key when moving to a new signer:

```bash
frameshift keys rotate \
  --server https://frameshift-api.syntheos.dev \
  --publisher YOUR_PUBLISHER_HANDLE \
  --label "replacement workstation"
```

Rotation creates and enrolls the replacement before selecting it and revoking
the old remote key. If an intermediate step fails, FrameShift preserves enough
local state to report the partial result instead of pretending rotation
completed.

`frameshift keys revoke` coordinates local and matching remote revocation.
`frameshift keys remote-revoke` revokes one server record when the local private
key is no longer available. Revoked records remain historical evidence but
cannot authorize a new publication.

After account recovery on a new device, `frameshift keys recover` creates and
enrolls a replacement signer under the recovered publisher membership. Account
recovery does not recreate an old private key.

Encrypted recovery packages are a separate portability mechanism:

```bash
frameshift keys export KEY_ID --out publisher-key.recovery
frameshift keys import --input publisher-key.recovery --label "restored device"
```

Exports never overwrite an existing file. Protect the recovery passphrase and
package independently, and revoke a lost device's remote key as soon as account
access is restored.

Continue with [[Creator Studio]] to prepare a draft and
[[Publishing and Moderation]] for the release lifecycle.

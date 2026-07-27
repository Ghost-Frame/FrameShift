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

## Sign in securely

```bash
frameshift account login
frameshift account status
```

The current `frameshift account login` command uses the configured OIDC
provider. It opens the provider in your browser and uses an exact IP-loopback
callback with S256 PKCE. The desktop first-party login API exists for clients
that implement the explicit bearer-session flow; the CLI command has not
switched to that flow.

The CLI stores OIDC access and refresh tokens in the operating system's native
credential store. The JSON metadata in the managed FrameShift data directory
contains no token.

`account status` asks the registry for the authenticated account and its
publisher memberships. `account logout` attempts provider revocation and then
removes the exact local credential and metadata.

A saved session is bound to the registry used during login. Remote key commands
reuse and refresh that session only when their `--server` value names the same
registry base URL. For another registry, set `FRAMESHIFT_ACCESS_TOKEN` or enter
a token at the hidden interactive prompt. FrameShift never accepts an account
token as a command-line argument or prints it.

## Publisher profiles and memberships

A publisher profile is the durable owner shown with account-backed releases.
Its handle is the public name; its UUID is the stable identity used for
ownership checks even if display metadata changes.

Publisher operations require an active account membership with the appropriate
role. The current key CLI assumes that the publisher profile and your
membership already exist. Use `frameshift account status` to confirm membership
before enrolling a device.

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

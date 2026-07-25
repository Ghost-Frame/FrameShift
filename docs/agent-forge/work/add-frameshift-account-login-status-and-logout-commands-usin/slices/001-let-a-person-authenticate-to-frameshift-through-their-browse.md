# Slice 001: Let a person authenticate to FrameShift through their browser without ever copying a bearer token into a terminal or agent-visible channel.

- **spec:** `spec_5be98a7c`

## Components

- frameshift-client account API
- native session persistence
- frameshift CLI account login/status/logout
- loopback callback listener
- account-session documentation

## Hard-won conditions

- Access gate remains enabled
- Provider redirects are disabled
- Issuer and endpoints are credential-free HTTPS
- CLI callback is explicit IP-loopback HTTP
- Tokens never enter CLI arguments, stdin, metadata, Debug, or docs
- Metadata opens use O_NOFOLLOW and owner-only permissions on Unix
- Full workspace, embeddings, Postgres, audit, and strict Clippy pass

## Decision: Versioned metadata file plus native credential-store payload

- **why:** Keep provider/server/session metadata in an atomic owner-only JSON file while storing the secret token payload in the OS credential store under a derived stable account.
- **alternative:** Store all session state in the native credential store -- rejected: Harder to discover, migrate, and validate sessions without secret-store access.; Credential size limits vary by platform.; Status/config diagnostics become opaque.
- **trust:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved

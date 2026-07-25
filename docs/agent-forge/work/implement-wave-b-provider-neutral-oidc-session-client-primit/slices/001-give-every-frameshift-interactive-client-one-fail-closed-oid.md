# Slice 001: Give every FrameShift interactive client one fail-closed OIDC Authorization Code foundation so users never have to paste bearer tokens into a CLI, desktop app, or agent-visible channel.

- **spec:** `spec_6227e8a3`

## Components

- frameshift-client session module
- OIDC discovery validation
- S256 PKCE authorization flow
- callback state and redirect validation
- bounded token exchange and refresh
- optional revocation and device endpoint capability metadata
- deterministic protocol tests

## Hard-won conditions

- No production issuer or client registration is selected by this slice.
- Only Authorization Code with S256 PKCE is accepted.
- Issuer identity must match discovery exactly.
- Provider endpoints must be credential-free HTTPS URLs.
- Native plaintext callbacks are limited to loopback hosts.
- HTTP redirects are disabled for discovery and token calls.
- Access, refresh, ID token, PKCE verifier, callback state, and nonce values never appear in Debug output.
- OIDC ID-token validation remains a higher-level caller responsibility; FrameShift API identity comes from the server-validated access token.
- All workspace, Postgres, embeddings, Clippy, formatting, and RustSec gates passed.

## Decision: Small typed synchronous session module over existing ureq

- **why:** Implement the exact required discovery, S256 PKCE, callback, token, refresh, and revocation contract with strict validation on top of the existing blocking HTTP stack.
- **alternative:** Adopt a full OpenID Connect client crate -- rejected: Large dependency and transitive risk increase.; Async/runtime integration conflicts with the synchronous frameshift-client API.; Harder to enforce FrameShift-specific endpoint, response-size, redirect, and redaction constraints.
- **trust:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved

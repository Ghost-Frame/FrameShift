# Slice 001: Remove the two high-severity quick-xml advisories from the release dependency graph without changing the R2 adapter contract.

- **spec:** `spec_ec5c8e26`

## Components

- frameshift-objects-r2 dependency declaration
- Cargo.lock resolved dependency graph
- R2 adapter compatibility tests
- RustSec audit evidence

## Hard-won conditions

- quick-xml resolves only to 0.41.0
- crc-fast resolves to 1.9.0, which supports the workspace Rust 1.88 contract
- R2 adapter tests remain green
- Full workspace tests and Clippy remain green
- cargo audit reports zero known vulnerabilities

## Decision: Upgrade object_store to 0.14.1

- **why:** Raise the direct frameshift-objects-r2 dependency to object_store 0.14.1, which depends on quick-xml 0.41.0, pin its crc-fast dependency to the Rust 1.88-compatible 1.9.0 release, and validate API compatibility.
- **alternative:** Patch quick-xml under object_store 0.13 -- rejected: object_store 0.13 declares an incompatible semver range; Would require a fork or unsupported patch
- **trust:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved

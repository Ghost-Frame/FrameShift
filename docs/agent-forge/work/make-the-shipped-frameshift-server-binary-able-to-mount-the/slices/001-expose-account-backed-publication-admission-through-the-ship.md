# Slice 001: Expose account-backed publication admission through the shipped server binary only with explicit isolated quarantine configuration.

- **spec:** `spec_fc56b59f`

## Components

- frameshift-server config
- binary startup wiring
- router dispatch
- startup-policy tests
- public configuration docs

## Hard-won conditions

- cargo test -p frameshift-server passed 193 tests
- Agent-Forge direct binary-policy verification passed 6 tests
- git diff --check passed
- all touched files passed comment coverage checks

## Decision: Explicit parallel quarantine backend configuration

- **why:** Add disabled-by-default FS/R2 quarantine fields to ServerConfig, validate store separation, construct the quarantine PackStore in main, and select a new library run helper.
- **alternative:** Filesystem-only quarantine root -- rejected: Not suitable for multi-instance production; Cannot use the existing R2 deployment pattern; Would create another migration before release
- **trust:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved

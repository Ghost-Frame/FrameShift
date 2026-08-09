# Slice 001: Add bounded PackStore primitive without disturbing concurrent Unit C2 edits.

- **spec:** `spec_100f7d94`

## Components

- PackStore trait
- object-store error
- FS adapter
- R2 adapter
- server mock

## Hard-won conditions

- Do not touch cloud_dispatcher.rs
- Do not touch mcp_cloud_tools.rs
- Do not run Cargo until root clearance
- Repository-wide PackStore inventory found exactly two production implementations (FsPackStore and R2PackStore), one shared server test mock, and one concurrent test-only ObservingPackStore. A required get_bounded method with default get compatibility affects implementers but does not require existing get callers to change; only cloud archive verification should opt into the finite limit. (Manual dependency-risk and breakage search because this Agent-Forge build exposes neither dep_risk nor check_breakage.)

## Decision: Required bounded primitive with default get compatibility

- **why:** Require every PackStore implementation to provide get_bounded; make get delegate to it with usize::MAX. Production adapters precheck metadata and enforce during reads.
- **alternative:** Default bounded wrapper over existing get -- rejected: Memory amplification happens before the check; New production adapters can accidentally inherit unsafe behavior
- **trust:** not independently verified

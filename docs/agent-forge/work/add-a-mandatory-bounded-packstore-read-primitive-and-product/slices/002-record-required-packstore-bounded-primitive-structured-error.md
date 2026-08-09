# Slice 002: Record required PackStore bounded primitive, structured error, production adapters, and focused tests.

- **spec:** `spec_100f7d94`

## Components

- frameshift-objects
- frameshift-objects-fs
- frameshift-objects-r2
- server MockPackStore

## Hard-won conditions

- ObservingPackStore still requires concurrent owner update
- cloud verifier still requires bounded call integration
- Repository-wide PackStore inventory found exactly two production implementations (FsPackStore and R2PackStore), one shared server test mock, and one concurrent test-only ObservingPackStore. A required get_bounded method with default get compatibility affects implementers but does not require existing get callers to change; only cloud archive verification should opt into the finite limit. (Manual dependency-risk and breakage search because this Agent-Forge build exposes neither dep_risk nor check_breakage.)

## Decision: Required bounded primitive with default get compatibility

- **why:** Require every PackStore implementation to provide get_bounded; make get delegate to it with usize::MAX. Production adapters precheck metadata and enforce during reads.
- **alternative:** Default bounded wrapper over existing get -- rejected: Memory amplification happens before the check; New production adapters can accidentally inherit unsafe behavior
- **trust:** not independently verified

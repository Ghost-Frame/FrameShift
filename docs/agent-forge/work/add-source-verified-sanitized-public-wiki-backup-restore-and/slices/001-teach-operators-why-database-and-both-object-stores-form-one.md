# Slice 001: Teach operators why database and both object stores form one recovery set, and how to contain incidents without destroying evidence or weakening trust checks.

- **spec:** `spec_d4a443ed`

## Components

- current database inventory
- separated object-store recovery model
- isolated restore acceptance
- five incident runbooks
- retention boundary

## Hard-won conditions

- canonical Wiki validates
- no patch whitespace errors
- no private topology markers
- no destructive command examples
- all touched files pass comment and adversarial review

## Decision: One sanitized evidence-contract page

- **why:** Document source-backed invariants, isolated restore acceptance, and bounded incident checklists without private topology.
- **alternative:** Provider-specific executable scripts -- rejected: Would encode deployment assumptions; Could create destructive or credential-handling risk; Cannot prove production compatibility from this repo
- **trust:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved

# Slice 001: Give the moderation authority chain an origin so the publishing pipeline is reachable in production: administrators can grant and revoke platform roles and set account status, while the platform can never be left with zero administrators.

- **spec:** `spec_7a731e47`

## Components

- frameshift-catalog
- frameshift-catalog-postgres
- frameshift-server
- docs/wiki

## Hard-won conditions

- platform roles were previously read-only in all non-test code, so no production deployment could ever moderate or promote anything
- authority is checked before target lookup so the routes are not an account-existence oracle
- authority requires an active role and an active account, so suspending an administrator removes their coverage
- revocation marks state revoked and never deletes the assignment row
- the last active administrator is protected because no in-application path recovers from zero administrators
- the concurrency test asserts the coverage outcome only and does not prove the table lock is load-bearing, since deadlock detection alone also prevents the double commit

## Decision: SHARE ROW EXCLUSIVE table lock before the count, then write

- **why:** Take LOCK TABLE account_platform_roles IN SHARE ROW EXCLUSIVE MODE at the start of every role-revocation and account-status transaction, then count active administrators and write
- **alternative:** Database CHECK or trigger enforcing a minimum administrator count -- rejected: A trigger cannot express the intended actor-aware error, so the API would surface an opaque database failure; Adds a migration and hidden control flow far from the authorization code; Would also block the legitimate documented bootstrap and any future recovery SQL
- **trust:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved

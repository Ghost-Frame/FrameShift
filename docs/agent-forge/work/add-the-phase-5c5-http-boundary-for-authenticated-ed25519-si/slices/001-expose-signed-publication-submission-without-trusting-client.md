# Slice 001: Expose signed publication submission without trusting client-repeated identity or hash bindings and without conflating quarantine storage with public objects.

- **spec:** `spec_17401d2a`

## Components

- frameshift-server publication submission routes
- explicit quarantine-service router builder
- bearer plus Ed25519 authorization composition
- bounded admission error mapping

## Hard-won conditions

- Production main binary remains unwired to quarantine storage
- Public object storage is never passed implicitly
- All client-repeated identity and hash bindings are excluded from the request
- D4 moderation and appeal policy remains outside this slice
- Phase 1 remains active and unchanged

## Decision: Explicit quarantine-store app builder

- **why:** Keep the standard app unchanged and add an explicit builder that receives only a quarantine PackStore. The builder constructs PublicationAdmissionService with the router's catalog, so authorization and atomic intent consumption cannot use different catalog authorities. The handler reloads the intent and publisher key before admission.
- **alternative:** Optional quarantine store in AppState -- rejected: Forces mechanical changes to every AppState constructor; Makes it easier for callers to accidentally pass the public object store; Mixes storage composition into general shared state
- **trust:** not independently verified

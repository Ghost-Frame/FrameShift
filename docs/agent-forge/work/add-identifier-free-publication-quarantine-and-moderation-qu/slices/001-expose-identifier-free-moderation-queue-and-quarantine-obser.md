# Slice 001: Expose identifier-free moderation queue and quarantine observability so operators can see review backlog and reviewer coverage without any account, publisher, key, submission, or artifact identifiers crossing the metrics boundary.

- **spec:** `spec_71032dbe`

## Components

- frameshift-catalog
- frameshift-catalog-postgres
- frameshift-server
- docs/wiki

## Hard-won conditions

- snapshot unavailable resets all dependent gauges and sets availability to 0
- no identifier labels on any moderation gauge
- queue and quarantine aggregates come from one MVCC snapshot
- reviewer count computed in SQL via COUNT(DISTINCT)
- future timestamps clamp age to zero

## Decision: Scrape-time catalog snapshot gauges

- **why:** Add an optional catalog snapshot contract and refresh fixed-name gauges during authenticated metrics scrapes.
- **alternative:** Mutation-time counters and histograms -- rejected: Retries can double count; Misses out-of-process database changes; Cannot reliably show current oldest queue age or reviewer availability
- **trust:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved

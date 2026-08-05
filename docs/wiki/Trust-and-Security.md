# Trust and Security

FrameShift treats persona identity as versioned content rather than an
untracked prompt file. Its trust model combines deterministic content hashes,
Ed25519 signatures, registry ownership records, per-project lock pins, and a
validated publication boundary.

## Pack integrity

A pack's canonical hash is computed from its public manifest and pack files in
a deterministic order. Registry downloads are checked in two stages:

1. The downloaded archive's SHA-256 hash must match the registry version
   record.
2. The pack's Ed25519 signature must verify against the exact public key in
   that version record.

The client does not trust a key embedded only in the downloaded manifest.
Direct local-path installs are a different trust boundary: FrameShift verifies
a signature when one is present, but permits an unsigned local pack.

## Publisher continuity

Registry installs pin the publisher handle and signing key. When ownership
metadata is available, the lock also preserves the stable publisher ID. A
different publisher fails closed. A newly presented signing key produces a
key-change error until the registry can provide a valid rotation proof.

A revoked key can remain evidence for a historical release, but it cannot sign
a new publication.

## Project lock and cache

Each project lock records the persona name, version, author handle, signer
public key, and canonical hash. Materialized persona files come from the
content-addressed central cache. `frameshift sync` checks the lock and rebuilds
project state from those pinned entries.

The lock proves which content the project selected. It does not make the
rendered instructions safe by itself.

## Rendered prompt policy

FrameShift applies a versioned, deterministic content policy to rendered
agent instructions. The policy blocks narrow classes of behavioral override,
safety and approval bypass, secret exfiltration, instruction-hierarchy claims,
and hidden Unicode controls. References to dangerous commands and sensitive
paths are reported as warnings instead of being treated as automatically
malicious.

Publication validation scans every generated Claude, Codex, Gemini, and
Generic render, plus every raw render candidate shipped by a pack. The client
is the final enforcement boundary: it scans the exact content after
composition, local infrastructure overlays, and template substitution, before
replacing an active persona. A rejected install does not write a new lock or
replace the last successfully materialized persona.

Policy errors contain stable finding codes and the policy version. They do not
echo matched prompt text or substituted vault values. The scanner normalizes
Unicode compatibility forms, compares Unicode UTS #39 confusable skeletons,
and checks for hidden format controls. It is still not a general proof that
arbitrary natural language is semantically safe.

Local research packs can bypass this content policy only through the explicit
CLI combination `--from-path <path> --trust-local-prompt-content`. FrameShift
records that choice in the project lock and preserves it across `sync`.
Ordinary local installs and every registry install remain strict. The bypass
does not skip pack hashing, signature checks when present, or cache integrity
checks.

## Publication boundary

Publication validation builds an exact public-file inventory and rejects
symlinks, special files, traversal, unknown paths, private-state paths, growth
data, malformed schemas, stale renders, prompt-policy violations, and invalid
conformance evidence. The publisher copies only hash-matching inventoried bytes
into a private temporary snapshot, independently revalidates that snapshot,
and signs and archives those same bytes. It never signs a source directory that
can continue changing during review.

Creator Studio binds human review and submission intent to the exact manifest,
scanner report, archive hash, manifest hash, inventory hash, publisher ID, and
publisher-key ID. Freeze revalidates the exact in-memory snapshot bytes rather
than rereading the mutable draft. Any later draft mutation clears both
confirmations.

## Capabilities and host enforcement

A pack's `capability_manifest` declares expected agent tools, network access,
filesystem scope, and memory requirements. This declaration is useful for
review and selection, but it is not a sandbox.

The MCP `frameshift_capabilities` result is advisory. FrameShift reports how a
proposed tool list compares with the active persona's declaration; the MCP
server does not block or hide tools owned by the host agent. The host remains
responsible for enforcing its permissions.

MCP can create, inspect, validate, preview, read, and write Creator Studio
drafts. It intentionally cannot confirm the final human review or submission
intent.

See [[Security Reporting and Known Limits]] for the private reporting channel
and current platform limitations.

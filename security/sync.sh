#!/bin/bash
# Per-context sync wrapper. Delegates to the shared sync library.
# Edit AGENTS.md, then run this to validate and propagate.

set -euo pipefail

CTX_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export CTX_DIR
CONTEXT_PHRASES=("noise level" "authorization scope" "Safety-Layer Awareness")
export CONTEXT_PHRASES

source "$CTX_DIR/../bin/sync-context.sh"

#!/bin/bash
set -euo pipefail
CTX_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export CTX_DIR
CONTEXT_PHRASES=("embedding" "vector" "recall" "knowledge graph")
export CONTEXT_PHRASES
source "$CTX_DIR/../bin/sync-context.sh"

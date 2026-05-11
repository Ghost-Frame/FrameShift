#!/bin/bash
set -euo pipefail
CTX_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export CTX_DIR
CONTEXT_PHRASES=("deployment risk" "rollback" "fleet" "pipeline")
export CONTEXT_PHRASES
source "$CTX_DIR/../bin/sync-context.sh"

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AVAILABLE_STACKS=("grafana-stack" "openobserve")

usage() {
    echo "Usage: $0 <stack-name> [docker-compose args...]"
    echo ""
    echo "Available stacks:"
    for stack in "${AVAILABLE_STACKS[@]}"; do
        echo "  - $stack"
    done
    echo ""
    echo "Examples:"
    echo "  $0 openobserve up -d"
    echo "  $0 grafana-stack up -d"
    echo "  $0 openobserve down"
    echo "  $0 openobserve logs -f"
    exit 1
}

if [ $# -lt 1 ]; then
    usage
fi

STACK="$1"
shift

STACK_DIR="${SCRIPT_DIR}/${STACK}"

if [ ! -d "$STACK_DIR" ]; then
    echo "Error: Stack '$STACK' not found at $STACK_DIR"
    echo ""
    usage
fi

if [ ! -f "$STACK_DIR/docker-compose.yml" ]; then
    echo "Error: No docker-compose.yml found in $STACK_DIR"
    exit 1
fi

echo "==> Using stack: $STACK"
cd "$STACK_DIR"

# Load .env if present
if [ -f .env ]; then
    echo "==> Loading .env"
fi

docker compose "$@"

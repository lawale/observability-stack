#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHARED_DIR="${SCRIPT_DIR}/shared"
AVAILABLE_STACKS=("grafana-stack" "openobserve")

usage() {
    echo "Usage: $0 <stack-name> [docker-compose args...]"
    echo ""
    echo "Available targets:"
    echo "  shared         - Shared infrastructure only (Caddy, Redis, autolog-service)"
    for stack in "${AVAILABLE_STACKS[@]}"; do
        echo "  $stack"
    done
    echo ""
    echo "Shared services are started automatically before any stack."
    echo ""
    echo "Examples:"
    echo "  $0 openobserve up -d       # Start shared + openobserve"
    echo "  $0 grafana-stack up -d     # Start shared + grafana-stack"
    echo "  $0 shared up -d            # Start shared infrastructure only"
    echo "  $0 openobserve logs -f     # View openobserve logs"
    echo "  $0 shared down             # Stop shared services"
    exit 1
}

if [ $# -lt 1 ]; then
    usage
fi

STACK="$1"
shift

# Handle "shared" as a direct target
if [ "$STACK" = "shared" ]; then
    echo "==> Using: shared"
    cd "$SHARED_DIR"
    if [ -f .env ]; then
        echo "==> Loading shared/.env"
    fi
    docker compose "$@"
    exit 0
fi

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

# Start shared services first (for 'up' commands)
COMPOSE_CMD="${1:-}"
if [ "$COMPOSE_CMD" = "up" ]; then
    echo "==> Starting shared infrastructure..."
    cd "$SHARED_DIR"
    if [ -f .env ]; then
        echo "==> Loading shared/.env"
    fi
    docker compose up -d
    echo "==> Shared services started"
    echo ""
fi

echo "==> Using stack: $STACK"
cd "$STACK_DIR"

if [ -f .env ]; then
    echo "==> Loading $STACK/.env"
fi

docker compose "$@"

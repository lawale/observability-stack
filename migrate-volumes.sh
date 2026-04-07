#!/usr/bin/env bash
set -euo pipefail

# Migrate Docker volumes from the old single-compose observability stack
# to the new multi-compose structure (shared/ + grafana-stack/ + openobserve/).
#
# Old volumes (prefixed with observability_):
#   observability_grafana-storage     → grafana-stack_grafana-storage
#   observability_prometheus-storage  → grafana-stack_prometheus-storage
#   observability_loki-storage        → grafana-stack_loki-storage
#   observability_tempo-storage       → grafana-stack_tempo-storage
#   observability_alertmanager-storage→ grafana-stack_alertmanager-storage
#   observability_redis-autolog       → shared_redis-autolog
#   observability_caddy-data          → shared_caddy-data
#   observability_caddy-config        → shared_caddy-config
#   observability_caddy-logs          → shared_caddy-logs
#
# Usage:
#   ./migrate-volumes.sh          # dry-run (shows what would happen)
#   ./migrate-volumes.sh --run    # actually perform migration

DRY_RUN=true
if [ "${1:-}" = "--run" ]; then
  DRY_RUN=false
fi

OLD_PREFIX="observability"

# source → destination mappings
declare -A VOLUME_MAP=(
  ["${OLD_PREFIX}_grafana-storage"]="grafana-stack_grafana-storage"
  ["${OLD_PREFIX}_prometheus-storage"]="grafana-stack_prometheus-storage"
  ["${OLD_PREFIX}_loki-storage"]="grafana-stack_loki-storage"
  ["${OLD_PREFIX}_tempo-storage"]="grafana-stack_tempo-storage"
  ["${OLD_PREFIX}_alertmanager-storage"]="grafana-stack_alertmanager-storage"
  ["${OLD_PREFIX}_redis-autolog"]="shared_redis-autolog"
  ["${OLD_PREFIX}_caddy-data"]="shared_caddy-data"
  ["${OLD_PREFIX}_caddy-config"]="shared_caddy-config"
  ["${OLD_PREFIX}_caddy-logs"]="shared_caddy-logs"
)

clone_volume() {
  local src="$1"
  local dst="$2"

  # Check source exists
  if ! docker volume inspect "$src" >/dev/null 2>&1; then
    echo "SKIP: source volume '$src' does not exist"
    return 0
  fi

  # Check destination doesn't already have data
  if docker volume inspect "$dst" >/dev/null 2>&1; then
    # Volume exists — check if it has data
    local file_count
    file_count=$(docker run --rm -v "$dst:/target:ro" alpine sh -c "find /target -mindepth 1 -maxdepth 1 | wc -l" 2>/dev/null || echo "0")
    if [ "$file_count" -gt 0 ]; then
      echo "SKIP: destination volume '$dst' already has data ($file_count items)"
      return 0
    fi
  fi

  if [ "$DRY_RUN" = true ]; then
    echo "WOULD: clone '$src' → '$dst'"
    return 0
  fi

  echo "CLONING: '$src' → '$dst'"

  # Create destination volume if it doesn't exist
  docker volume create "$dst" >/dev/null

  # Copy data using a temporary alpine container
  docker run --rm \
    -v "$src:/source:ro" \
    -v "$dst:/target" \
    alpine sh -c "cp -a /source/. /target/"

  echo "OK: cloned '$src' → '$dst'"
}

echo "========================================="
echo "Volume Migration: old stack → new structure"
echo "========================================="
echo ""

if [ "$DRY_RUN" = true ]; then
  echo "DRY RUN — no changes will be made."
  echo "Run with --run to perform migration."
  echo ""
fi

# List existing old volumes for context
echo "Existing old volumes:"
docker volume ls --format '{{.Name}}' | grep "^${OLD_PREFIX}_" || echo "  (none found)"
echo ""

# Perform migrations
for src in "${!VOLUME_MAP[@]}"; do
  dst="${VOLUME_MAP[$src]}"
  clone_volume "$src" "$dst"
done

echo ""
if [ "$DRY_RUN" = true ]; then
  echo "Done (dry run). Run with --run to execute."
else
  echo "Migration complete."
  echo ""
  echo "Next steps:"
  echo "  1. Stop the old stack:    docker compose -p observability down"
  echo "  2. Start shared:          ./deploy.sh shared up -d"
  echo "  3. Start openobserve:     ./deploy.sh openobserve up -d"
  echo "  4. Start grafana-stack:   ./deploy.sh grafana-stack up -d"
  echo ""
  echo "Once verified, you can remove old volumes with:"
  echo "  docker volume rm ${OLD_PREFIX}_grafana-storage ${OLD_PREFIX}_prometheus-storage \\"
  echo "    ${OLD_PREFIX}_loki-storage ${OLD_PREFIX}_tempo-storage \\"
  echo "    ${OLD_PREFIX}_alertmanager-storage ${OLD_PREFIX}_redis-autolog \\"
  echo "    ${OLD_PREFIX}_caddy-data ${OLD_PREFIX}_caddy-config ${OLD_PREFIX}_caddy-logs"
fi

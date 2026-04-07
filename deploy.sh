#!/usr/bin/env bash

# Consolidated deploy script for the multi-stack observability platform.
#
# Deploys from a clean release directory at /opt/observability-deploy/
# instead of the git working tree. Supports versioned releases with
# automatic backup and rollback.
#
# Usage:
#   ./deploy.sh <stack>           Deploy shared + stack (versioned release)
#   ./deploy.sh shared            Deploy shared services only
#   ./deploy.sh status            Show running services
#
# Available stacks: grafana-stack, openobserve

set -euo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_ROOT="${DEPLOY_ROOT:-/opt/observability-deploy}"
RELEASE_ID="${RELEASE_ID:-$(date +%Y%m%d-%H%M%S)}"
RELEASE_DIR="$DEPLOY_ROOT/releases/$RELEASE_ID"
CURRENT_LINK="$DEPLOY_ROOT/current"
BACKUP_STATEFUL_VOLUMES="${BACKUP_STATEFUL_VOLUMES:-1}"
HEALTH_TIMEOUT_SECONDS="${HEALTH_TIMEOUT_SECONDS:-180}"
ENV_SOURCE="${ENV_SOURCE:-auto}"
KEEP_RELEASES="${KEEP_RELEASES:-5}"
KEEP_BACKUPS="${KEEP_BACKUPS:-10}"
ENABLE_DOCKER_PRUNE="${ENABLE_DOCKER_PRUNE:-1}"
DOCKER_PRUNE_UNTIL="${DOCKER_PRUNE_UNTIL:-336h}"
PRUNE_UNUSED_IMAGES="${PRUNE_UNUSED_IMAGES:-0}"
AVAILABLE_STACKS=("grafana-stack" "openobserve")

# ==================== COMPOSE HELPERS ====================

compose_shared() {
  docker compose -p shared -f "$RELEASE_DIR/shared/docker-compose.yml" "$@"
}

compose_stack() {
  docker compose -p "$STACK" -f "$RELEASE_DIR/$STACK/docker-compose.yml" "$@"
}

# ==================== UTILITY FUNCTIONS ====================

fix_service_volume_permissions() {
  local compose_fn="$1"
  local service_name="$2"
  local mount_dest="$3"
  local owner_uid="$4"
  local owner_gid="$5"
  local required_subdirs="$6"

  local container_id
  container_id="$($compose_fn ps --all -q "$service_name" | head -n1 || true)"
  if [ -z "$container_id" ]; then
    echo "WARN: missing container for service '$service_name'"
    return 0
  fi

  local mount_info
  mount_info="$(docker inspect "$container_id" \
    --format "{{range .Mounts}}{{if eq .Destination \"$mount_dest\"}}{{.Type}}|{{.Name}}|{{.Source}}{{end}}{{end}}" \
    2>/dev/null || true)"
  if [ -z "$mount_info" ]; then
    echo "WARN: missing mount '$mount_dest' for service '$service_name'"
    return 0
  fi

  local mount_type mount_name mount_source
  IFS='|' read -r mount_type mount_name mount_source <<< "$mount_info"

  local mkdir_cmd="mkdir -p /target"
  if [ -n "$required_subdirs" ]; then
    for subdir in $required_subdirs; do
      mkdir_cmd="$mkdir_cmd /target/$subdir"
    done
  fi

  if [ "$mount_type" = "volume" ] && [ -n "$mount_name" ]; then
    docker run --rm -v "$mount_name:/target" alpine sh -c \
      "$mkdir_cmd && chown -R $owner_uid:$owner_gid /target && chmod -R 755 /target"
    echo "OK: fixed volume '$mount_name' for $service_name"
    return 0
  fi

  if [ "$(id -u)" -eq 0 ] && [ -n "$mount_source" ]; then
    mkdir -p "$mount_source"
    if [ -n "$required_subdirs" ]; then
      for subdir in $required_subdirs; do
        mkdir -p "$mount_source/$subdir"
      done
    fi
    chown -R "$owner_uid:$owner_gid" "$mount_source"
    chmod -R 755 "$mount_source"
    echo "OK: fixed bind mount '$mount_source' for $service_name"
    return 0
  fi

  echo "WARN: cannot chown bind mount '$mount_source' without root"
}

backup_service_mount() {
  local compose_fn="$1"
  local service_name="$2"
  local mount_dest="$3"
  local backup_name="$4"
  local backup_dir="$DEPLOY_ROOT/backups/$RELEASE_ID"

  local container_id
  container_id="$($compose_fn ps --all -q "$service_name" | head -n1 || true)"
  if [ -z "$container_id" ]; then
    echo "WARN: cannot backup '$service_name' (container missing)"
    return 0
  fi

  local mount_info
  mount_info="$(docker inspect "$container_id" \
    --format "{{range .Mounts}}{{if eq .Destination \"$mount_dest\"}}{{.Type}}|{{.Name}}|{{.Source}}{{end}}{{end}}" \
    2>/dev/null || true)"
  if [ -z "$mount_info" ]; then
    echo "WARN: cannot backup '$service_name' mount '$mount_dest' (mount missing)"
    return 0
  fi

  local mount_type mount_name mount_source
  IFS='|' read -r mount_type mount_name mount_source <<< "$mount_info"
  mkdir -p "$backup_dir"

  if [ "$mount_type" = "volume" ] && [ -n "$mount_name" ]; then
    docker run --rm -v "$mount_name:/source:ro" -v "$backup_dir:/backup" alpine sh -c \
      "tar czf /backup/${backup_name}.tar.gz -C /source ."
    echo "OK: backup '$service_name' → $backup_dir/${backup_name}.tar.gz"
    return 0
  fi

  if [ -n "$mount_source" ] && [ -d "$mount_source" ]; then
    tar czf "$backup_dir/${backup_name}.tar.gz" -C "$mount_source" .
    echo "OK: backup '$service_name' → $backup_dir/${backup_name}.tar.gz"
    return 0
  fi

  echo "WARN: cannot backup '$service_name' mount '$mount_dest'"
}

service_ready() {
  local compose_fn="$1"
  local service_name="$2"
  local container_id
  container_id="$($compose_fn ps --all -q "$service_name" | head -n1 || true)"
  if [ -z "$container_id" ]; then
    return 1
  fi

  local status health
  status="$(docker inspect --format '{{.State.Status}}' "$container_id" 2>/dev/null || true)"
  health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$container_id" 2>/dev/null || true)"

  if [ "$status" != "running" ]; then
    return 1
  fi

  # No healthcheck configured → running is good enough
  if [ "$health" = "none" ] || [ "$health" = "healthy" ]; then
    return 0
  fi

  return 1
}

wait_for_services() {
  local compose_fn="$1"
  local timeout="$2"
  shift 2
  local services=("$@")
  local start_ts now_ts elapsed

  start_ts="$(date +%s)"
  while true; do
    local pending=0
    for svc in "${services[@]}"; do
      if ! service_ready "$compose_fn" "$svc"; then
        pending=1
      fi
    done

    if [ "$pending" -eq 0 ]; then
      return 0
    fi

    now_ts="$(date +%s)"
    elapsed=$((now_ts - start_ts))
    if [ "$elapsed" -ge "$timeout" ]; then
      return 1
    fi

    sleep 3
  done
}

cleanup_old_dirs() {
  local base_dir="$1"
  local keep_count="$2"
  local label="$3"
  local pruned=0

  if [ "$keep_count" -lt 0 ]; then
    echo "WARN: invalid keep count for $label: $keep_count"
    return 0
  fi

  if [ ! -d "$base_dir" ]; then
    return 0
  fi

  mapfile -t items < <(ls -1dt "$base_dir"/* 2>/dev/null || true)
  if [ "${#items[@]}" -le "$keep_count" ]; then
    echo "OK: $label retention satisfied (${#items[@]} <= $keep_count)"
    return 0
  fi

  for item in "${items[@]:$keep_count}"; do
    rm -rf "$item"
    pruned=$((pruned + 1))
  done

  echo "OK: pruned $pruned old $label item(s)"
}

prune_docker_cache() {
  if [ "$ENABLE_DOCKER_PRUNE" != "1" ]; then
    echo "Skipping Docker prune (ENABLE_DOCKER_PRUNE=$ENABLE_DOCKER_PRUNE)"
    return 0
  fi

  echo "Pruning dangling Docker images older than $DOCKER_PRUNE_UNTIL..."
  docker image prune -f --filter "until=$DOCKER_PRUNE_UNTIL" || true

  if [ "$PRUNE_UNUSED_IMAGES" = "1" ]; then
    docker image prune -af --filter "until=$DOCKER_PRUNE_UNTIL" || true
  fi

  docker builder prune -f --filter "until=$DOCKER_PRUNE_UNTIL" || true
  docker container prune -f --filter "until=$DOCKER_PRUNE_UNTIL" || true
}

resolve_env() {
  local component_dir="$1"
  local source_env="$SOURCE_DIR/$component_dir/.env"
  local current_env="$CURRENT_LINK/$component_dir/.env"
  local release_env="$RELEASE_DIR/$component_dir/.env"
  local example_env="$RELEASE_DIR/$component_dir/.env.example"

  if [ "$ENV_SOURCE" = "current" ]; then
    if [ ! -f "$current_env" ]; then
      echo "ERROR: ENV_SOURCE=current but no .env at $current_env"
      exit 1
    fi
    cp "$current_env" "$release_env"
    echo "  $component_dir: using $current_env"
  elif [ "$ENV_SOURCE" = "source" ]; then
    if [ ! -f "$source_env" ]; then
      echo "ERROR: ENV_SOURCE=source but no .env at $source_env"
      exit 1
    fi
    cp "$source_env" "$release_env"
    echo "  $component_dir: using $source_env"
  else
    # auto: prefer current, then source, then .env.example
    if [ -f "$current_env" ]; then
      cp "$current_env" "$release_env"
      echo "  $component_dir: using $current_env"
    elif [ -f "$source_env" ]; then
      cp "$source_env" "$release_env"
      echo "  $component_dir: using $source_env"
    elif [ -f "$example_env" ]; then
      cp "$example_env" "$release_env"
      echo "  $component_dir: using .env.example (WARN: update secrets!)"
    else
      echo "  $component_dir: no .env found (skipping)"
    fi
  fi
}

# ==================== STACK-SPECIFIC DEPLOY FUNCTIONS ====================

deploy_shared() {
  echo ""
  echo "==> Deploying shared services..."

  compose_shared create caddy redis-autolog 2>/dev/null || true

  if [ "$BACKUP_STATEFUL_VOLUMES" = "1" ]; then
    echo "Backing up shared volumes..."
    backup_service_mount compose_shared "redis-autolog" "/data" "shared-redis-autolog"
  fi

  compose_shared up -d

  echo "Waiting for shared services..."
  if ! wait_for_services compose_shared "$HEALTH_TIMEOUT_SECONDS" \
    caddy redis-autolog autolog-service; then
    echo "ERROR: shared services health check failed"
    compose_shared ps
    compose_shared logs --tail=60 caddy redis-autolog autolog-service || true
    return 1
  fi

  echo "OK: shared services healthy"
}

deploy_grafana_stack() {
  echo ""
  echo "==> Deploying grafana-stack..."

  # Fix file permissions for bind-mounted configs
  find "$RELEASE_DIR/grafana-stack/grafana/provisioning" "$RELEASE_DIR/grafana-stack/grafana/dashboards" \
    -type d -exec chmod a+rx {} + 2>/dev/null || true
  find "$RELEASE_DIR/grafana-stack/grafana/provisioning" "$RELEASE_DIR/grafana-stack/grafana/dashboards" \
    -type f \( -name "*.yml" -o -name "*.yaml" -o -name "*.json" \) -exec chmod a+r {} + 2>/dev/null || true
  chmod a+r "$RELEASE_DIR"/grafana-stack/prometheus/*.yml \
    "$RELEASE_DIR"/grafana-stack/prometheus/alerts/*.yml \
    "$RELEASE_DIR"/grafana-stack/loki/loki.yml \
    "$RELEASE_DIR"/grafana-stack/tempo/tempo.yml \
    "$RELEASE_DIR"/grafana-stack/promtail/*.yml \
    "$RELEASE_DIR"/grafana-stack/alertmanager/alertmanager.yml \
    "$RELEASE_DIR"/grafana-stack/otel-collector/otel-collector-config.yml 2>/dev/null || true

  echo "Creating stateful services..."
  compose_stack create grafana prometheus loki tempo alertmanager >/dev/null

  if [ "$BACKUP_STATEFUL_VOLUMES" = "1" ]; then
    echo "Backing up grafana-stack volumes..."
    backup_service_mount compose_stack "grafana" "/var/lib/grafana" "grafana-storage"
    backup_service_mount compose_stack "prometheus" "/prometheus" "prometheus-storage"
    backup_service_mount compose_stack "loki" "/loki" "loki-storage"
    backup_service_mount compose_stack "tempo" "/tmp/tempo" "tempo-storage"
    backup_service_mount compose_stack "alertmanager" "/alertmanager" "alertmanager-storage"
  fi

  echo "Fixing persistent volume permissions..."
  fix_service_volume_permissions compose_stack "grafana" "/var/lib/grafana" "472" "472" ""
  fix_service_volume_permissions compose_stack "prometheus" "/prometheus" "65534" "65534" ""
  fix_service_volume_permissions compose_stack "loki" "/loki" "10001" "10001" "chunks rules compactor"
  fix_service_volume_permissions compose_stack "tempo" "/tmp/tempo" "10001" "10001" "blocks wal generator"
  fix_service_volume_permissions compose_stack "alertmanager" "/alertmanager" "65534" "65534" ""

  echo "Starting services..."
  compose_stack up -d grafana prometheus loki tempo alertmanager promtail
  compose_stack up -d otel-collector

  echo "Waiting for grafana-stack services..."
  if ! wait_for_services compose_stack "$HEALTH_TIMEOUT_SECONDS" \
    grafana prometheus loki tempo alertmanager otel-collector; then
    echo "ERROR: grafana-stack health check failed"
    compose_stack ps
    compose_stack logs --tail=120 tempo prometheus alertmanager otel-collector || true
    return 1
  fi

  echo "OK: grafana-stack services healthy"
}

deploy_openobserve() {
  echo ""
  echo "==> Deploying openobserve..."

  chmod a+r "$RELEASE_DIR"/openobserve/otel-collector/otel-collector-config.yml 2>/dev/null || true

  echo "Creating stateful services..."
  compose_stack create openobserve >/dev/null

  if [ "$BACKUP_STATEFUL_VOLUMES" = "1" ]; then
    echo "Backing up openobserve volumes..."
    backup_service_mount compose_stack "openobserve" "/data" "openobserve-data"
  fi

  echo "Starting services..."
  compose_stack up -d openobserve
  compose_stack up -d otel-collector-openobserve

  echo "Waiting for openobserve services..."
  if ! wait_for_services compose_stack "$HEALTH_TIMEOUT_SECONDS" \
    openobserve otel-collector-openobserve; then
    echo "ERROR: openobserve health check failed"
    compose_stack ps
    compose_stack logs --tail=120 openobserve otel-collector-openobserve || true
    return 1
  fi

  echo "OK: openobserve services healthy"
}

# ==================== ROLLBACK ====================

rollback() {
  if [ -n "$PREVIOUS_RELEASE" ] && [ -d "$PREVIOUS_RELEASE" ]; then
    echo ""
    echo "Rolling back to previous release: $PREVIOUS_RELEASE"

    # Rollback shared
    if [ -f "$PREVIOUS_RELEASE/shared/docker-compose.yml" ]; then
      docker compose -p shared -f "$PREVIOUS_RELEASE/shared/docker-compose.yml" up -d || true
    fi

    # Rollback stack
    if [ -n "${STACK:-}" ] && [ -f "$PREVIOUS_RELEASE/$STACK/docker-compose.yml" ]; then
      docker compose -p "$STACK" -f "$PREVIOUS_RELEASE/$STACK/docker-compose.yml" up -d || true
    fi

    ln -sfn "$PREVIOUS_RELEASE" "$CURRENT_LINK"
    echo "Rolled back to: $PREVIOUS_RELEASE"
  else
    echo "No previous release to roll back to"
  fi
}

# ==================== USAGE ====================

usage() {
  echo "Usage: $0 <target>"
  echo ""
  echo "Targets:"
  echo "  shared            Deploy shared infrastructure only (Caddy, Redis, autolog-service)"
  echo "  grafana-stack     Deploy shared + Grafana stack"
  echo "  openobserve       Deploy shared + OpenObserve stack"
  echo "  status            Show running services across all components"
  echo ""
  echo "Environment variables:"
  echo "  DEPLOY_ROOT          Deploy directory (default: /opt/observability-deploy)"
  echo "  ENV_SOURCE           auto|current|source (default: auto)"
  echo "  HEALTH_TIMEOUT_SECONDS  Health check timeout (default: 180)"
  echo "  BACKUP_STATEFUL_VOLUMES 0|1 (default: 1)"
  echo "  ENABLE_DOCKER_PRUNE  0|1 (default: 1)"
  echo ""
  echo "Examples:"
  echo "  $0 openobserve                        # Deploy shared + openobserve"
  echo "  $0 grafana-stack                      # Deploy shared + grafana-stack"
  echo "  $0 shared                             # Deploy shared services only"
  echo "  DEPLOY_ROOT=/tmp/test $0 openobserve  # Test deploy to /tmp"
  exit 1
}

# ==================== MAIN ====================

if [ $# -lt 1 ]; then
  usage
fi

TARGET="$1"

# Handle status command
if [ "$TARGET" = "status" ]; then
  echo "=== Shared services ==="
  if [ -L "$CURRENT_LINK" ] && [ -f "$CURRENT_LINK/shared/docker-compose.yml" ]; then
    docker compose -p shared -f "$CURRENT_LINK/shared/docker-compose.yml" ps 2>/dev/null || echo "(not running)"
  else
    echo "(not deployed)"
  fi

  for stack in "${AVAILABLE_STACKS[@]}"; do
    echo ""
    echo "=== $stack ==="
    if [ -L "$CURRENT_LINK" ] && [ -f "$CURRENT_LINK/$stack/docker-compose.yml" ]; then
      docker compose -p "$stack" -f "$CURRENT_LINK/$stack/docker-compose.yml" ps 2>/dev/null || echo "(not running)"
    else
      echo "(not deployed)"
    fi
  done

  echo ""
  if [ -L "$CURRENT_LINK" ]; then
    echo "Current release: $(readlink "$CURRENT_LINK")"
  fi
  exit 0
fi

# Validate target
STACK=""
if [ "$TARGET" = "shared" ]; then
  STACK=""
elif printf '%s\n' "${AVAILABLE_STACKS[@]}" | grep -qx "$TARGET"; then
  STACK="$TARGET"
else
  echo "ERROR: unknown target '$TARGET'"
  echo ""
  usage
fi

# Prerequisites
if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker is not installed"
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: docker compose plugin is not installed"
  exit 1
fi

if ! command -v rsync >/dev/null 2>&1; then
  echo "ERROR: rsync is required"
  exit 1
fi

if [ "$ENV_SOURCE" != "auto" ] && [ "$ENV_SOURCE" != "current" ] && [ "$ENV_SOURCE" != "source" ]; then
  echo "ERROR: ENV_SOURCE must be one of: auto, current, source"
  exit 1
fi

echo "========================================="
echo "  Deploying release $RELEASE_ID"
echo "  Target: $TARGET"
echo "  Deploy root: $DEPLOY_ROOT"
echo "========================================="

# Track previous release for rollback
PREVIOUS_RELEASE=""
if [ -L "$CURRENT_LINK" ]; then
  PREVIOUS_RELEASE="$(readlink "$CURRENT_LINK")"
fi

# Create release directory and rsync repo
mkdir -p "$RELEASE_DIR"
mkdir -p "$DEPLOY_ROOT/releases"

echo ""
echo "Syncing source to release directory..."
rsync -a --delete \
  --exclude '.git' \
  --exclude '.env' \
  --exclude '.claude' \
  --exclude '.idea' \
  "$SOURCE_DIR/" "$RELEASE_DIR/"

# Resolve .env files
echo ""
echo "Resolving environment files..."
resolve_env "shared"
if [ -n "$STACK" ]; then
  resolve_env "$STACK"
fi

# Pull images
echo ""
echo "Pulling images..."
compose_shared pull
if [ -n "$STACK" ]; then
  compose_stack pull
fi

# Deploy shared services (always)
if ! deploy_shared; then
  rollback
  exit 1
fi

# Deploy stack (if specified)
if [ -n "$STACK" ]; then
  case "$STACK" in
    grafana-stack)
      if ! deploy_grafana_stack; then
        rollback
        exit 1
      fi
      ;;
    openobserve)
      if ! deploy_openobserve; then
        rollback
        exit 1
      fi
      ;;
  esac
fi

# Finalize
ln -sfn "$RELEASE_DIR" "$CURRENT_LINK"

echo ""
echo "Cleaning up..."
cleanup_old_dirs "$DEPLOY_ROOT/releases" "$KEEP_RELEASES" "release"
cleanup_old_dirs "$DEPLOY_ROOT/backups" "$KEEP_BACKUPS" "backup"
prune_docker_cache

echo ""
echo "========================================="
echo "  Deployment complete"
echo "========================================="
echo "Release: $RELEASE_DIR"
echo "Status:  $0 status"

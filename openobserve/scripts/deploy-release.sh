#!/usr/bin/env bash

# Deploy from a clean release directory instead of the git working tree.
# Adapted for the OpenObserve stack (fewer stateful volumes, simpler permissions).

set -euo pipefail

SOURCE_DIR="${SOURCE_DIR:-$(pwd)}"
DEPLOY_ROOT="${DEPLOY_ROOT:-/opt/openobserve-deploy}"
PROJECT_NAME="${PROJECT_NAME:-openobserve}"
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

compose() {
  docker compose -p "$PROJECT_NAME" -f "$RELEASE_DIR/docker-compose.yml" "$@"
}

fix_service_volume_permissions() {
  local service_name="$1"
  local mount_dest="$2"
  local owner_uid="$3"
  local owner_gid="$4"
  local required_subdirs="$5"

  local container_id
  container_id="$(compose ps --all -q "$service_name" | head -n1 || true)"
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
  local service_name="$1"
  local mount_dest="$2"
  local backup_name="$3"
  local backup_dir="$DEPLOY_ROOT/backups/$RELEASE_ID"

  local container_id
  container_id="$(compose ps --all -q "$service_name" | head -n1 || true)"
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
    echo "OK: backup created for $service_name at $backup_dir/${backup_name}.tar.gz"
    return 0
  fi

  if [ -n "$mount_source" ] && [ -d "$mount_source" ]; then
    tar czf "$backup_dir/${backup_name}.tar.gz" -C "$mount_source" .
    echo "OK: backup created for $service_name at $backup_dir/${backup_name}.tar.gz"
    return 0
  fi

  echo "WARN: cannot backup '$service_name' mount '$mount_dest'"
}

service_ready() {
  local service_name="$1"
  local container_id
  container_id="$(compose ps --all -q "$service_name" | head -n1 || true)"
  if [ -z "$container_id" ]; then
    return 1
  fi

  local status health
  status="$(docker inspect --format '{{.State.Status}}' "$container_id" 2>/dev/null || true)"
  health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$container_id" 2>/dev/null || true)"

  if [ "$status" != "running" ]; then
    return 1
  fi

  if [ "$health" = "none" ] || [ "$health" = "healthy" ]; then
    return 0
  fi

  return 1
}

wait_for_services() {
  local timeout="$1"
  shift
  local services=("$@")
  local start_ts now_ts elapsed

  start_ts="$(date +%s)"
  while true; do
    local pending=0
    for svc in "${services[@]}"; do
      if ! service_ready "$svc"; then
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
    echo "OK: $label retention already satisfied (${#items[@]} <= $keep_count)"
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
    echo "Pruning unused Docker images older than $DOCKER_PRUNE_UNTIL..."
    docker image prune -af --filter "until=$DOCKER_PRUNE_UNTIL" || true
  fi

  echo "Pruning build cache older than $DOCKER_PRUNE_UNTIL..."
  docker builder prune -f --filter "until=$DOCKER_PRUNE_UNTIL" || true

  echo "Pruning stopped containers older than $DOCKER_PRUNE_UNTIL..."
  docker container prune -f --filter "until=$DOCKER_PRUNE_UNTIL" || true
}

# ==================== MAIN ====================

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker is not installed"
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: docker compose plugin is not installed"
  exit 1
fi

echo "Deploying release $RELEASE_ID"
mkdir -p "$RELEASE_DIR"
mkdir -p "$DEPLOY_ROOT/releases"

PREVIOUS_RELEASE=""
if [ -L "$CURRENT_LINK" ]; then
  PREVIOUS_RELEASE="$(readlink "$CURRENT_LINK")"
fi

if ! command -v rsync >/dev/null 2>&1; then
  echo "ERROR: rsync is required"
  exit 1
fi

if [ "$ENV_SOURCE" != "auto" ] && [ "$ENV_SOURCE" != "current" ] && [ "$ENV_SOURCE" != "source" ]; then
  echo "ERROR: ENV_SOURCE must be one of: auto, current, source"
  exit 1
fi

rsync -a --delete \
  --exclude '.git' \
  --exclude '.env' \
  --exclude 'backups' \
  "$SOURCE_DIR/" "$RELEASE_DIR/"

# Resolve .env file
ENV_FILE_USED=""
if [ "$ENV_SOURCE" = "current" ]; then
  if [ ! -f "$CURRENT_LINK/.env" ]; then
    echo "ERROR: ENV_SOURCE=current but no .env exists at $CURRENT_LINK/.env"
    exit 1
  fi
  cp "$CURRENT_LINK/.env" "$RELEASE_DIR/.env"
  ENV_FILE_USED="$CURRENT_LINK/.env"
elif [ "$ENV_SOURCE" = "source" ]; then
  if [ ! -f "$SOURCE_DIR/.env" ]; then
    echo "ERROR: ENV_SOURCE=source but no .env exists at $SOURCE_DIR/.env"
    exit 1
  fi
  cp "$SOURCE_DIR/.env" "$RELEASE_DIR/.env"
  ENV_FILE_USED="$SOURCE_DIR/.env"
else
  if [ -f "$CURRENT_LINK/.env" ]; then
    cp "$CURRENT_LINK/.env" "$RELEASE_DIR/.env"
    ENV_FILE_USED="$CURRENT_LINK/.env"
  elif [ -f "$SOURCE_DIR/.env" ]; then
    cp "$SOURCE_DIR/.env" "$RELEASE_DIR/.env"
    ENV_FILE_USED="$SOURCE_DIR/.env"
  elif [ -f "$RELEASE_DIR/.env.example" ]; then
    cp "$RELEASE_DIR/.env.example" "$RELEASE_DIR/.env"
    ENV_FILE_USED="$RELEASE_DIR/.env.example"
    echo "WARN: no existing .env found; seeded from .env.example"
  else
    echo "ERROR: no .env or .env.example available"
    exit 1
  fi
fi
echo "Using environment file: $ENV_FILE_USED"

# Fix config file permissions
chmod a+r "$RELEASE_DIR"/otel-collector/otel-collector-config.yml 2>/dev/null || true

echo "Pulling images..."
compose pull

# OpenObserve data volume — runs as root inside container by default
echo "Creating stateful services..."
compose create openobserve >/dev/null

if [ "$BACKUP_STATEFUL_VOLUMES" = "1" ]; then
  echo "Creating pre-deploy backups..."
  backup_service_mount "openobserve" "/data" "openobserve-data"
fi

echo "Starting services..."
compose up -d openobserve
compose up -d otel-collector-openobserve

echo "Waiting for service health..."
if ! wait_for_services "$HEALTH_TIMEOUT_SECONDS" \
  openobserve otel-collector-openobserve; then
  echo "ERROR: deployment health check failed"
  compose ps
  compose logs --tail=120 openobserve otel-collector-openobserve || true

  if [ -n "$PREVIOUS_RELEASE" ] && [ -f "$PREVIOUS_RELEASE/docker-compose.yml" ]; then
    echo "Rolling back to previous release: $PREVIOUS_RELEASE"
    docker compose -p "$PROJECT_NAME" -f "$PREVIOUS_RELEASE/docker-compose.yml" up -d
    ln -sfn "$PREVIOUS_RELEASE" "$CURRENT_LINK"
  fi

  exit 1
fi

ln -sfn "$RELEASE_DIR" "$CURRENT_LINK"

cleanup_old_dirs "$DEPLOY_ROOT/releases" "$KEEP_RELEASES" "release"
cleanup_old_dirs "$DEPLOY_ROOT/backups" "$KEEP_BACKUPS" "backup"
prune_docker_cache

echo "Deployment complete."
echo "Current release: $RELEASE_DIR"
echo "Project name: $PROJECT_NAME"
echo "Check status: docker compose -p $PROJECT_NAME -f $RELEASE_DIR/docker-compose.yml ps"

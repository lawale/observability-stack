#!/usr/bin/env bash

# Setup script for the multi-stack observability deployment.
# Generates secrets and configures .env files for shared/, grafana-stack/, and openobserve/.
#
# Usage:
#   ./setup.sh                  # Interactive setup
#   ./setup.sh --non-interactive # Use defaults + auto-generated secrets

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NON_INTERACTIVE=false

if [ "${1:-}" = "--non-interactive" ]; then
  NON_INTERACTIVE=true
fi

escape_sed_replacement() {
  printf '%s' "$1" | sed -e 's/[&|\\]/\\&/g'
}

upsert_env() {
  local file="$1" key="$2" value="$3"
  local value_escaped
  value_escaped=$(escape_sed_replacement "$value")

  if grep -q "^${key}=" "$file" 2>/dev/null; then
    sed -i.bak "s|^${key}=.*|${key}=${value_escaped}|" "$file"
  else
    echo "${key}=${value}" >> "$file"
  fi
}

prompt_or_default() {
  local prompt="$1" default="$2" var_name="$3"
  if [ "$NON_INTERACTIVE" = true ]; then
    eval "$var_name=\"$default\""
    return
  fi
  read -p "$prompt [$default]: " input
  eval "$var_name=\"${input:-$default}\""
}

generate_secret() {
  openssl rand -hex 16
}

generate_password() {
  openssl rand -base64 16
}

# ==================== CHECKS ====================

if ! command -v openssl >/dev/null 2>&1; then
  echo "ERROR: openssl is required for secret generation"
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker is not installed"
  exit 1
fi

echo "========================================="
echo "  Observability Stack Setup"
echo "========================================="
echo ""
echo "This will configure .env files for:"
echo "  - shared/      (Caddy, Redis, autolog-service)"
echo "  - grafana-stack/ (Grafana, Prometheus, Loki, Tempo)"
echo "  - openobserve/  (OpenObserve)"
echo ""

# ==================== DOMAIN ====================

prompt_or_default "Enter your domain" "yourdomain.com" DOMAIN
echo ""

# ==================== SHARED ====================

echo "--- Configuring shared/.env ---"

SHARED_ENV="$SCRIPT_DIR/shared/.env"

if [ -f "$SHARED_ENV" ]; then
  echo "shared/.env already exists."
  if [ "$NON_INTERACTIVE" = false ]; then
    read -p "Regenerate secrets? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      echo "Keeping existing shared/.env"
      AUTOLOG_SECRET=$(grep "^AUTOLOG_WEBHOOK_SECRET=" "$SHARED_ENV" | cut -d'=' -f2-)
      SKIP_SHARED=true
    fi
  fi
fi

if [ "${SKIP_SHARED:-}" != "true" ]; then
  cp "$SCRIPT_DIR/shared/.env.example" "$SHARED_ENV"

  AUTOLOG_SECRET=$(generate_secret)

  upsert_env "$SHARED_ENV" "DOMAIN" "$DOMAIN"
  upsert_env "$SHARED_ENV" "AUTOLOG_WEBHOOK_SECRET" "$AUTOLOG_SECRET"

  rm -f "${SHARED_ENV}.bak"
  echo "Generated shared/.env"
fi

echo ""

# ==================== GRAFANA STACK ====================

echo "--- Configuring grafana-stack/.env ---"

GRAFANA_ENV="$SCRIPT_DIR/grafana-stack/.env"

if [ -f "$GRAFANA_ENV" ]; then
  echo "grafana-stack/.env already exists."
  if [ "$NON_INTERACTIVE" = false ]; then
    read -p "Regenerate secrets? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      echo "Keeping existing grafana-stack/.env"
      GRAFANA_PASSWORD=$(grep "^GRAFANA_ADMIN_PASSWORD=" "$GRAFANA_ENV" | cut -d'=' -f2-)
      SKIP_GRAFANA=true
    fi
  fi
fi

if [ "${SKIP_GRAFANA:-}" != "true" ]; then
  cp "$SCRIPT_DIR/grafana-stack/.env.example" "$GRAFANA_ENV"

  GRAFANA_PASSWORD=$(generate_password)

  upsert_env "$GRAFANA_ENV" "DOMAIN" "$DOMAIN"
  upsert_env "$GRAFANA_ENV" "GRAFANA_ADMIN_PASSWORD" "$GRAFANA_PASSWORD"
  upsert_env "$GRAFANA_ENV" "AUTOLOG_WEBHOOK_SECRET" "$AUTOLOG_SECRET"

  rm -f "${GRAFANA_ENV}.bak"
  echo "Generated grafana-stack/.env"
fi

echo ""

# ==================== OPENOBSERVE ====================

echo "--- Configuring openobserve/.env ---"

OO_ENV="$SCRIPT_DIR/openobserve/.env"

if [ -f "$OO_ENV" ]; then
  echo "openobserve/.env already exists."
  if [ "$NON_INTERACTIVE" = false ]; then
    read -p "Regenerate secrets? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      echo "Keeping existing openobserve/.env"
      SKIP_OO=true
    fi
  fi
fi

if [ "${SKIP_OO:-}" != "true" ]; then
  cp "$SCRIPT_DIR/openobserve/.env.example" "$OO_ENV"

  prompt_or_default "OpenObserve admin email" "admin@${DOMAIN}" ZO_EMAIL
  ZO_PASSWORD=$(generate_password)
  ZO_TOKEN=$(echo -n "${ZO_EMAIL}:${ZO_PASSWORD}" | base64)

  upsert_env "$OO_ENV" "ZO_ROOT_USER_EMAIL" "$ZO_EMAIL"
  upsert_env "$OO_ENV" "ZO_ROOT_USER_PASSWORD" "$ZO_PASSWORD"
  upsert_env "$OO_ENV" "ZO_TOKEN" "$ZO_TOKEN"

  rm -f "${OO_ENV}.bak"
  echo "Generated openobserve/.env"
fi

echo ""

# ==================== SUMMARY ====================

echo "========================================="
echo "  Setup Complete"
echo "========================================="
echo ""
echo "Generated credentials (save these!):"
echo "─────────────────────────────────────"
echo "Domain:                    $DOMAIN"
if [ "${SKIP_SHARED:-}" != "true" ]; then
  echo "Autolog webhook secret:    $AUTOLOG_SECRET"
fi
if [ "${SKIP_GRAFANA:-}" != "true" ]; then
  echo "Grafana admin password:    $GRAFANA_PASSWORD"
fi
if [ "${SKIP_OO:-}" != "true" ]; then
  echo "OpenObserve admin email:   $ZO_EMAIL"
  echo "OpenObserve admin password:$ZO_PASSWORD"
  echo "OpenObserve OTEL token:    $ZO_TOKEN"
fi
echo "─────────────────────────────────────"
echo ""
echo "Next steps:"
echo "  1. (Optional) Configure SMTP in grafana-stack/.env for email alerts"
echo "  2. ./deploy.sh shared up -d"
echo "  3. ./deploy.sh openobserve up -d"
echo "  4. ./deploy.sh grafana-stack up -d"
echo ""
echo "UIs will be available at:"
echo "  - https://observe.${DOMAIN}"
echo "  - https://grafana.${DOMAIN}"
echo "  - https://autolog.${DOMAIN}"

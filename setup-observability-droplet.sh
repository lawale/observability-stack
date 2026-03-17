#!/bin/bash

# Observability Droplet Setup Script (Multi-Droplet Deployment)
# Run this on the dedicated observability droplet

set -e

LOCAL_TEST="${LOCAL_TEST:-0}"
OS_NAME="$(uname -s)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

DEPLOY_SCRIPT="$SCRIPT_DIR/scripts/deploy-release.sh"
SOURCE_DIR="${SOURCE_DIR:-$SCRIPT_DIR}"
DEPLOY_ROOT="${DEPLOY_ROOT:-/opt/observability-deploy}"
PROJECT_NAME="${PROJECT_NAME:-observability}"

escape_sed_replacement() {
    # Escape chars that are special in sed replacement strings.
    printf '%s' "$1" | sed -e 's/[&|\\]/\\&/g'
}

upsert_env_var() {
    local key="$1"
    local value="$2"
    local value_escaped
    value_escaped=$(escape_sed_replacement "$value")

    if grep -q "^${key}=" .env 2>/dev/null; then
        sed -i.bak "s|^${key}=.*|${key}=${value_escaped}|" .env
    else
        echo "${key}=${value}" >> .env
    fi
}

get_env_var() {
    local key="$1"
    grep -E "^${key}=" .env 2>/dev/null | tail -n1 | cut -d'=' -f2-
}

configure_alerting() {
    local smtp_host smtp_port smtp_username smtp_password alert_email critical_alert_email
    local smtp_host_default smtp_port_default smtp_username_default smtp_password_default
    local alert_email_default critical_alert_email_default

    read -p "Do you want to configure email alert settings now? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "ℹ️  Skipping alert email setup"
        return 0
    fi

    smtp_host_default="$(get_env_var SMTP_HOST)"
    smtp_port_default="$(get_env_var SMTP_PORT)"
    smtp_username_default="$(get_env_var SMTP_USERNAME)"
    smtp_password_default="$(get_env_var SMTP_PASSWORD)"
    alert_email_default="$(get_env_var ALERT_EMAIL)"
    critical_alert_email_default="$(get_env_var CRITICAL_ALERT_EMAIL)"

    smtp_host_default="${smtp_host_default:-smtp.gmail.com}"
    smtp_port_default="${smtp_port_default:-587}"
    smtp_username_default="${smtp_username_default:-your-email@gmail.com}"
    alert_email_default="${alert_email_default:-alerts@yourdomain.com}"
    critical_alert_email_default="${critical_alert_email_default:-critical@yourdomain.com}"

    read -r -p "SMTP host [$smtp_host_default]: " smtp_host
    smtp_host="${smtp_host:-$smtp_host_default}"

    read -r -p "SMTP port [$smtp_port_default]: " smtp_port
    smtp_port="${smtp_port:-$smtp_port_default}"

    read -r -p "SMTP username [$smtp_username_default]: " smtp_username
    smtp_username="${smtp_username:-$smtp_username_default}"

    read -r -s -p "SMTP password (leave blank to keep existing): " smtp_password
    echo
    if [ -z "$smtp_password" ]; then
        smtp_password="$smtp_password_default"
    fi

    read -r -p "Alert email [$alert_email_default]: " alert_email
    alert_email="${alert_email:-$alert_email_default}"

    read -r -p "Critical alert email [$critical_alert_email_default]: " critical_alert_email
    critical_alert_email="${critical_alert_email:-$critical_alert_email_default}"

    upsert_env_var "SMTP_HOST" "$smtp_host"
    upsert_env_var "SMTP_PORT" "$smtp_port"
    upsert_env_var "SMTP_USERNAME" "$smtp_username"
    if [ -n "$smtp_password" ]; then
        upsert_env_var "SMTP_PASSWORD" "$smtp_password"
    fi
    upsert_env_var "ALERT_EMAIL" "$alert_email"
    upsert_env_var "CRITICAL_ALERT_EMAIL" "$critical_alert_email"

    rm -f .env.bak
    echo "✅ Alert email settings updated"
}

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   Observability Droplet - Multi-Droplet Setup               ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check execution mode
if [ "$LOCAL_TEST" = "1" ]; then
    echo "🧪 Running in LOCAL_TEST mode (server-only steps will be skipped)"
    if [ "$OS_NAME" = "Darwin" ] && [ "$EUID" -eq 0 ]; then
        echo "❌ On macOS local testing, run without sudo:"
        echo "   LOCAL_TEST=1 ./setup-observability-droplet.sh"
        exit 1
    fi
elif [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root (use sudo), or use LOCAL_TEST=1 for local validation"
    exit 1
fi

echo "🔍 Checking prerequisites..."

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "📦 Docker not found. Installing..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    rm get-docker.sh
    echo "✅ Docker installed"
else
    echo "✅ Docker is installed"
fi

# Check if Docker Compose is installed
if ! docker compose version &> /dev/null; then
    if [ "$LOCAL_TEST" = "1" ]; then
        echo "❌ Docker Compose plugin not found. Install Docker Compose first."
        exit 1
    fi
    echo "📦 Docker Compose plugin not found. Installing..."
    apt-get update
    apt-get install -y docker-compose-plugin
    echo "✅ Docker Compose installed"
else
    echo "✅ Docker Compose is installed"
fi

# Check if rsync is installed (required by release deploy script)
if ! command -v rsync &> /dev/null; then
    if [ "$LOCAL_TEST" = "1" ]; then
        echo "❌ rsync not found. Install rsync first for local validation."
        exit 1
    fi
    echo "📦 rsync not found. Installing..."
    apt-get update
    apt-get install -y rsync
    echo "✅ rsync installed"
else
    echo "✅ rsync is installed"
fi

if [ ! -f "$DEPLOY_SCRIPT" ]; then
    echo "❌ Deploy script not found: $DEPLOY_SCRIPT"
    exit 1
fi

echo ""

# Get droplet information
echo "📋 Droplet Configuration"
echo "─────────────────────────"

# Get private IP and VPC network
if [ "$LOCAL_TEST" = "1" ]; then
    PRIVATE_IP="127.0.0.1"
    VPC_CIDR="127.0.0.0/8"
else
    PRIVATE_IP=$(ip addr show eth1 | grep "inet\b" | awk '{print $2}' | cut -d/ -f1 || echo "")
    VPC_CIDR=$(ip addr show eth1 | grep "inet\b" | awk '{print $2}' || echo "")

    if [ -z "$PRIVATE_IP" ]; then
        echo "⚠️  Warning: Could not auto-detect private IP"
        echo "Please enter your droplet's private IP address (e.g., 10.0.1.10):"
        read -r PRIVATE_IP
        echo "Please enter your VPC CIDR range (e.g., 10.0.0.0/16):"
        read -r VPC_CIDR
    else
        # Extract network from CIDR (e.g., 10.0.1.10/16 -> 10.0.0.0/16)
        if [ -n "$VPC_CIDR" ]; then
            # Convert to network address
            IFS=/ read -r ip prefix <<< "$VPC_CIDR"
            VPC_CIDR=$(echo "$ip" | awk -F. -v prefix="$prefix" '{
                if (prefix >= 24) print $1"."$2"."$3".0/"prefix;
                else if (prefix >= 16) print $1"."$2".0.0/"prefix;
                else if (prefix >= 8) print $1".0.0.0/"prefix;
                else print "0.0.0.0/"prefix;
            }')
        else
            echo "Please enter your VPC CIDR range (e.g., 10.0.0.0/16):"
            read -r VPC_CIDR
        fi
    fi
fi

echo "Private IP: $PRIVATE_IP"
echo "VPC CIDR: $VPC_CIDR"
echo ""

# Get domain
echo "Please enter your domain (e.g., example.com):"
read -r DOMAIN

# Get email for Let's Encrypt
echo "Please enter your email for Let's Encrypt certificates:"
read -r EMAIL

echo ""
echo "Configuration Summary:"
echo "  Private IP: $PRIVATE_IP"
echo "  VPC CIDR: $VPC_CIDR"
echo "  Domain: $DOMAIN"
echo "  Email: $EMAIL"
echo "  Grafana URL: https://grafana.$DOMAIN"
echo ""
read -p "Is this correct? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted. Please run again."
    exit 1
fi

echo ""
echo "🔧 Setting up environment..."

# Create .env file
if [ ! -f .env ]; then
    echo "Creating .env file..."
    cp .env.example .env

    # Generate secure keys
    if command -v openssl &> /dev/null; then
        AUTOLOG_KEY=$(openssl rand -hex 16)
        GRAFANA_PASSWORD=$(openssl rand -base64 16)
        AUTOLOG_KEY_ESCAPED=$(escape_sed_replacement "$AUTOLOG_KEY")
        GRAFANA_PASSWORD_ESCAPED=$(escape_sed_replacement "$GRAFANA_PASSWORD")
        DOMAIN_ESCAPED=$(escape_sed_replacement "$DOMAIN")

        # Update .env
        # Use -i.bak for BSD/GNU sed compatibility.
        sed -i.bak "s|changeme-generate-random-string|$AUTOLOG_KEY_ESCAPED|" .env
        sed -i.bak "s|changeme-strong-password|$GRAFANA_PASSWORD_ESCAPED|" .env
        sed -i.bak "s|DOMAIN=yourdomain.com|DOMAIN=$DOMAIN_ESCAPED|" .env

        echo "✅ Generated secure keys"
        echo ""
        echo "🔐 IMPORTANT: Save these credentials!"
        echo "─────────────────────────────────────"
        echo "Grafana admin password: $GRAFANA_PASSWORD"
        echo "Auto-Log webhook secret: $AUTOLOG_KEY"
        echo "─────────────────────────────────────"
        echo ""
    else
        echo "⚠️  openssl not found. Please manually update .env with secure keys"
    fi
else
    echo "✅ .env file already exists (secrets preserved)"
fi

upsert_env_var "DOMAIN" "$DOMAIN"
upsert_env_var "PRIVATE_IP" "$PRIVATE_IP"
upsert_env_var "VPC_CIDR" "$VPC_CIDR"
upsert_env_var "ACME_EMAIL" "$EMAIL"
rm -f .env.bak
echo "✅ Updated environment values for this deployment"

echo ""
configure_alerting

echo ""
echo "🔥 Configuring firewall..."

# Configure UFW
if [ "$LOCAL_TEST" = "1" ]; then
    echo "⚠️  LOCAL_TEST mode: skipping firewall configuration"
elif command -v ufw &> /dev/null; then

    # Allow SSH (don't lock yourself out!)
    ufw allow 22/tcp comment "SSH"

    # Allow HTTP/HTTPS for Caddy
    ufw allow 80/tcp comment "HTTP"
    ufw allow 443/tcp comment "HTTPS"
    ufw allow 443/udp comment "HTTP/3"

    # Allow OTLP from VPC
    ufw allow from $VPC_CIDR to any port 4317 proto tcp comment "OTLP gRPC"
    ufw allow from $VPC_CIDR to any port 4318 proto tcp comment "OTLP HTTP"

    # Allow Loki from VPC
    ufw allow from $VPC_CIDR to any port 3100 proto tcp comment "Loki"

    # Allow Auto-Log API from VPC
    ufw allow from $VPC_CIDR to any port 5000 proto tcp comment "Auto-Log API"

    # Enable firewall
    ufw --force enable

    echo "✅ Firewall configured"
    echo ""
    ufw status numbered
else
    echo "⚠️  UFW not found. Please configure firewall manually"
fi

echo ""
echo "🔧 Fixing configuration file permissions..."

# Grafana provisioning/dashboard files are bind-mounted read-only.
# They only need to be readable; avoid forcing exact modes on tracked files.
if [ -d grafana ]; then
    find grafana/provisioning grafana/dashboards -type d -exec chmod a+rx {} + 2>/dev/null || true
    find grafana/provisioning grafana/dashboards -type f \( -name "*.yml" -o -name "*.yaml" -o -name "*.json" \) \
        -exec chmod a+r {} + 2>/dev/null || true
    echo "  ✓ Grafana provisioning/dashboard files are readable"
fi

# All config files must be readable for non-root containers.
chmod a+r prometheus/*.yml prometheus/alerts/*.yml loki/loki.yml tempo/tempo.yml \
    promtail/*.yml alertmanager/alertmanager.yml otel-collector/otel-collector-config.yml \
    caddy/Caddyfile 2>/dev/null || true
echo "  ✓ Config files: read permission ensured"

# All directories must be traversable.
chmod a+rx prometheus prometheus/alerts loki tempo promtail alertmanager \
    otel-collector caddy 2>/dev/null || true
echo "  ✓ Service directories: execute/read permission ensured"

echo "✅ Configuration file permissions fixed"

echo ""
echo "🚀 Running release deployment..."
if [ "$LOCAL_TEST" = "1" ]; then
    BACKUP_STATEFUL_VOLUMES="${BACKUP_STATEFUL_VOLUMES:-0}"
    ENABLE_DOCKER_PRUNE="${ENABLE_DOCKER_PRUNE:-0}"
else
    BACKUP_STATEFUL_VOLUMES="${BACKUP_STATEFUL_VOLUMES:-1}"
    ENABLE_DOCKER_PRUNE="${ENABLE_DOCKER_PRUNE:-1}"
fi
KEEP_RELEASES="${KEEP_RELEASES:-5}"
KEEP_BACKUPS="${KEEP_BACKUPS:-10}"
DOCKER_PRUNE_UNTIL="${DOCKER_PRUNE_UNTIL:-336h}"
PRUNE_UNUSED_IMAGES="${PRUNE_UNUSED_IMAGES:-0}"
HEALTH_TIMEOUT_SECONDS="${HEALTH_TIMEOUT_SECONDS:-180}"
ENV_SOURCE="${ENV_SOURCE:-source}"

SOURCE_DIR="$SOURCE_DIR" \
DEPLOY_ROOT="$DEPLOY_ROOT" \
PROJECT_NAME="$PROJECT_NAME" \
BACKUP_STATEFUL_VOLUMES="$BACKUP_STATEFUL_VOLUMES" \
HEALTH_TIMEOUT_SECONDS="$HEALTH_TIMEOUT_SECONDS" \
KEEP_RELEASES="$KEEP_RELEASES" \
KEEP_BACKUPS="$KEEP_BACKUPS" \
ENABLE_DOCKER_PRUNE="$ENABLE_DOCKER_PRUNE" \
DOCKER_PRUNE_UNTIL="$DOCKER_PRUNE_UNTIL" \
PRUNE_UNUSED_IMAGES="$PRUNE_UNUSED_IMAGES" \
ENV_SOURCE="$ENV_SOURCE" \
bash "$DEPLOY_SCRIPT"

echo ""
echo "🌐 Caddy will automatically obtain SSL certificates..."
echo "   (This happens on first request to your domain)"
echo ""

PUBLIC_IP="$(curl -s ifconfig.me 2>/dev/null || true)"
if [ -z "$PUBLIC_IP" ]; then
    PUBLIC_IP="<droplet-public-ip>"
fi

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              Observability Stack Ready! 🎉                   ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "🌐 Access URLs (HTTPS will be configured automatically):"
echo "   • Grafana: https://grafana.$DOMAIN (admin / [see above])"
echo ""
echo "📡 Telemetry Endpoints (from app droplets via VPC):"
echo "   • OTLP gRPC:     http://$PRIVATE_IP:4317"
echo "   • OTLP HTTP:     http://$PRIVATE_IP:4318"
echo "   • Loki:          http://$PRIVATE_IP:3100"
echo "   • Auto-Log API:  http://$PRIVATE_IP:5000"
echo ""
echo "📊 Services Running:"
echo "   • Grafana       - Dashboards, alerting, visualization"
echo "   • Prometheus    - Metrics storage"
echo "   • Loki          - Log aggregation"
echo "   • Tempo         - Distributed tracing"
echo "   • Alertmanager  - Alert routing and notifications"
echo "   • OTEL Collector - Telemetry ingestion"
echo "   • Auto-Log      - Intelligent verbose logging"
echo "   • Caddy         - Reverse proxy with auto-HTTPS"
echo ""
echo "📋 Next Steps:"
echo ""
echo "1. IMPORTANT: Set DNS record (if not done already):"
echo "   grafana.$DOMAIN → $PUBLIC_IP"
echo ""
echo "2. Visit https://grafana.$DOMAIN to verify Caddy + Let's Encrypt"
echo "   (First visit will obtain SSL certificate)"
echo ""
echo "3. Configure your application droplets to send telemetry to:"
echo "   OTEL_EXPORTER_OTLP_ENDPOINT=http://$PRIVATE_IP:4317"
echo ""
echo "4. Configure error monitoring alerts in Grafana to trigger auto-logging"
echo ""
echo "5. View logs: docker compose -p $PROJECT_NAME -f $DEPLOY_ROOT/current/docker-compose.yml logs -f"
echo ""
echo "6. Check health: docker compose -p $PROJECT_NAME -f $DEPLOY_ROOT/current/docker-compose.yml ps"
echo ""
echo "💡 Caddy Features:"
echo "   • Automatic HTTPS with Let's Encrypt"
echo "   • Auto-renewal of certificates"
echo "   • HTTP/3 support"
echo "   • Security headers configured"
echo ""
echo "📚 Documentation: See README.md for comprehensive documentation"
echo ""

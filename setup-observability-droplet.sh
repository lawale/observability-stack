#!/bin/bash

# Observability Droplet Setup Script (Multi-Droplet Deployment)
# Run this on the dedicated observability droplet

set -e

fix_service_volume_permissions() {
    local container_name="$1"
    local mount_dest="$2"
    local owner_uid="$3"
    local owner_gid="$4"
    local required_subdirs="$5"

    local volume_path
    volume_path=$(docker inspect "$container_name" \
        --format "{{range .Mounts}}{{if eq .Destination \"$mount_dest\"}}{{.Source}}{{end}}{{end}}" \
        2>/dev/null || true)

    if [ -z "$volume_path" ]; then
        echo "⚠️  Could not resolve mount path for $container_name ($mount_dest)"
        return 0
    fi

    mkdir -p "$volume_path"

    if [ -n "$required_subdirs" ]; then
        for subdir in $required_subdirs; do
            mkdir -p "$volume_path/$subdir"
        done
    fi

    chown -R "$owner_uid:$owner_gid" "$volume_path"
    chmod -R 755 "$volume_path"

    echo "  ✓ $container_name volume fixed at: $volume_path (owner $owner_uid:$owner_gid)"
}

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   Observability Droplet - Multi-Droplet Setup               ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root (use sudo)"
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
    echo "📦 Docker Compose plugin not found. Installing..."
    apt-get update
    apt-get install -y docker-compose-plugin
    echo "✅ Docker Compose installed"
else
    echo "✅ Docker Compose is installed"
fi

echo ""

# Get droplet information
echo "📋 Droplet Configuration"
echo "─────────────────────────"

# Get private IP and VPC network
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

rm -f .env

# Create .env file
if [ ! -f .env ]; then
    echo "Creating .env file..."
    cp .env.example .env

    # Generate secure keys
    if command -v openssl &> /dev/null; then
        AUTOLOG_KEY=$(openssl rand -hex 16)
        GRAFANA_PASSWORD=$(openssl rand -base64 16)

        # Update .env
        sed -i.bak "s/changeme-generate-random-string/$AUTOLOG_KEY/" .env
        sed -i "s/changeme-strong-password/$GRAFANA_PASSWORD/" .env
        sed -i "s/DOMAIN=yourdomain.com/DOMAIN=$DOMAIN/" .env
        echo "PRIVATE_IP=$PRIVATE_IP" >> .env
        echo "VPC_CIDR=$VPC_CIDR" >> .env
        echo "ACME_EMAIL=$EMAIL" >> .env
        rm -f .env.bak

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
    echo "✅ .env file already exists"
fi

echo ""
echo "🔥 Configuring firewall..."

# Configure UFW
if command -v ufw &> /dev/null; then

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
# They only need to be world-readable; ownership is handled on data volumes later.
if [ -d grafana ]; then
    chmod -R 755 grafana/provisioning grafana/dashboards 2>/dev/null || true
    chmod -R 644 grafana/provisioning/**/*.yml grafana/provisioning/**/*.yaml \
        grafana/dashboards/**/*.json 2>/dev/null || true
    echo "  ✓ Grafana provisioning/dashboard files are readable"
fi

# All config files must be readable (644) for non-root containers
chmod 644 prometheus/*.yml prometheus/alerts/*.yml loki/loki.yml tempo/tempo.yml \
    promtail/*.yml alertmanager/alertmanager.yml otel-collector/otel-collector-config.yml \
    caddy/Caddyfile 2>/dev/null || true
echo "  ✓ Config files: permissions set to 644"

# All directories must be accessible (755)
chmod 755 prometheus prometheus/alerts loki tempo promtail alertmanager \
    otel-collector caddy 2>/dev/null || true
echo "  ✓ Service directories: permissions set to 755"

echo "✅ Configuration file permissions fixed"

echo ""
echo "Stopping any running containers..."
docker compose -f docker-compose.yml down -v || true

echo ""
echo "📥 Pulling Docker images..."
docker compose -f docker-compose.yml pull

echo ""
echo "🚀 Starting observability stack..."
docker compose -f docker-compose.yml up -d

echo ""
echo "🔧 Fixing persistent volume permissions..."
docker compose -f docker-compose.yml stop grafana prometheus loki tempo alertmanager >/dev/null 2>&1 || true

# Grafana runs as UID 472
fix_service_volume_permissions "grafana" "/var/lib/grafana" "472" "472" ""

# Prometheus runs as nobody in compose (UID/GID 65534)
fix_service_volume_permissions "prometheus" "/prometheus" "65534" "65534" ""

# Loki and Tempo store data with UID/GID 10001 in this stack
fix_service_volume_permissions "loki" "/loki" "10001" "10001" "chunks rules compactor"
fix_service_volume_permissions "tempo" "/tmp/tempo" "10001" "10001" "blocks wal generator"

# Alertmanager commonly runs as nobody (UID/GID 65534)
fix_service_volume_permissions "alertmanager" "/alertmanager" "65534" "65534" ""

docker compose -f docker-compose.yml up -d grafana prometheus loki tempo alertmanager

echo ""
echo "⏳ Waiting for services to be healthy..."
sleep 15

echo ""
echo "🌐 Caddy will automatically obtain SSL certificates..."
echo "   (This happens on first request to your domain)"
echo ""

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
echo "   grafana.$DOMAIN → $(curl -s ifconfig.me)"
echo ""
echo "2. Visit https://grafana.$DOMAIN to verify Caddy + Let's Encrypt"
echo "   (First visit will obtain SSL certificate)"
echo ""
echo "3. Configure your application droplets to send telemetry to:"
echo "   OTEL_EXPORTER_OTLP_ENDPOINT=http://$PRIVATE_IP:4317"
echo ""
echo "4. Configure error monitoring alerts in Grafana to trigger auto-logging"
echo ""
echo "5. View logs: docker compose logs -f"
echo ""
echo "6. Check health: docker compose ps"
echo ""
echo "💡 Caddy Features:"
echo "   • Automatic HTTPS with Let's Encrypt"
echo "   • Auto-renewal of certificates"
echo "   • HTTP/3 support"
echo "   • Security headers configured"
echo ""
echo "📚 Documentation: See README.md for comprehensive documentation"
echo ""

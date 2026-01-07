# Observability Stack - Comprehensive Guide

A production-ready observability solution combining the **Grafana Stack** (Loki, Tempo, Prometheus) with **OpenTelemetry**, **Grafana Unified Alerting**, and an **Auto-Logging Service** for intelligent debugging.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Components](#components)
4. [Quick Start](#quick-start)
5. [Configuration](#configuration)
6. [Integrating Applications](#integrating-applications)
7. [OpenTelemetry Labels](#opentelemetry-labels)
8. [Grafana Dashboards](#grafana-dashboards)
9. [Alerting](#alerting)
10. [Auto-Logging Service](#auto-logging-service)
11. [Caddy Reverse Proxy](#caddy-reverse-proxy)
12. [Multi-Application Setup](#multi-application-setup)
13. [Troubleshooting](#troubleshooting)
14. [Maintenance](#maintenance)
15. [API Reference](#api-reference)

---

## Overview

This observability stack provides complete visibility into your applications:

| Pillar | Tool | Purpose |
|--------|------|---------|
| **Logs** | Loki | Centralized log aggregation with LogQL |
| **Traces** | Tempo | Distributed tracing with TraceQL |
| **Metrics** | Prometheus | Time-series metrics with PromQL |
| **Alerting** | Grafana Unified Alerting | Alert rules, routing, and notifications |
| **Auto-Logging** | Custom Go Service | Intelligent verbose logging triggered by errors |
| **Visualization** | Grafana | Unified dashboards with correlated data |

### Key Features

- **Unified Telemetry**: All data flows through OpenTelemetry Collector
- **Automatic HTTPS**: Caddy provides Let's Encrypt certificates
- **Auto-Logging**: System detects errors and enables verbose logging automatically
- **Multi-Application Support**: Track multiple services across environments
- **Self-Hosted**: Complete ownership of your data
- **Production-Ready**: Health checks, graceful shutdown, resource limits

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       Your Applications                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                      │
│  │  Jaiye   │  │EstateVault│  │  Other   │                     │
│  │   API    │  │    API    │  │ Services │                     │
│  └────┬─────┘  └────┬──────┘  └────┬─────┘                     │
│       │ OpenTelemetry SDK          │                           │
└───────┼─────────────┼──────────────┼───────────────────────────┘
        │             │              │
        ▼             ▼              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    OTEL Collector (4317/4318)                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Receivers: OTLP gRPC/HTTP                              │   │
│  │  Processors: Batch, Memory Limiter, Resource Attributes │   │
│  │  Exporters: Tempo, Loki (OTLP), Prometheus Remote Write │   │
│  └─────────────────────────────────────────────────────────┘   │
└───┬───────────────┬───────────────┬────────────────────────────┘
    │               │               │
    ▼               ▼               ▼
┌────────┐    ┌────────┐    ┌──────────┐
│  Loki  │    │ Tempo  │    │Prometheus│
│ (Logs) │    │(Traces)│    │(Metrics) │
│  3100  │    │  3200  │    │   9090   │
└───┬────┘    └───┬────┘    └────┬─────┘
    │             │              │
    │             │              ▼
    │             │       ┌─────────────┐
    │             │       │AlertManager │
    │             │       │    9093     │
    │             │       └──────┬──────┘
    │             │              │
    │             │              ▼
    │             │       ┌─────────────┐
    │             │       │  Auto-Log   │
    │             │       │  Service    │
    │             │       │    5000     │
    │             │       └─────────────┘
    │             │
    └─────────────┴──────────────┐
                                 ▼
                          ┌─────────────┐
                          │   Grafana   │
                          │    3000     │
                          └──────┬──────┘
                                 │
                                 ▼
                          ┌─────────────┐
                          │    Caddy    │
                          │   80/443    │
                          └─────────────┘
                                 │
                                 ▼
                            Internet
```

---

## Components

### Core Services

| Service | Image | Port | Purpose |
|---------|-------|------|---------|
| **Grafana** | grafana/grafana:11.4.0 | 3000 | Visualization, dashboards, alerting |
| **Prometheus** | prom/prometheus:v3.1.0 | 9090 | Metrics storage, PromQL queries |
| **Loki** | grafana/loki:3.3.2 | 3100 | Log aggregation, LogQL queries |
| **Tempo** | grafana/tempo:2.7.2 | 3200 | Trace storage, TraceQL queries |
| **Alertmanager** | prom/alertmanager:v0.28.1 | 9093 | Alert routing and notifications |
| **OTEL Collector** | otel/opentelemetry-collector-contrib:0.115.1 | 4317/4318 | Telemetry ingestion |
| **Promtail** | grafana/promtail:3.3.2 | - | Container log collection |

### Supporting Services

| Service | Image | Port | Purpose |
|---------|-------|------|---------|
| **Auto-Log Service** | Custom (Go) | 5000 | Intelligent auto-logging orchestration |
| **Redis** | redis:7.4-alpine | 6379 | Auto-log session state storage |
| **Caddy** | caddy:2.8-alpine | 80/443 | Reverse proxy with auto-HTTPS |

---

## Quick Start

### Prerequisites

- Docker and Docker Compose installed
- At least 8GB RAM available
- 20GB disk space
- Domain name with DNS access (for HTTPS)

### Step 1: Run Setup Script

```bash
cd /opt/observability
sudo ./setup-observability-droplet.sh
```

The script will:
1. Install Docker and Docker Compose (if needed)
2. Detect VPC CIDR from network interface
3. Configure UFW firewall rules
4. Fix config file permissions
5. Generate secure credentials
6. Start all services
7. Fix Tempo volume ownership

### Step 2: Set DNS Records

```
Type: A
Name: grafana
Value: <droplet-public-ip>
```

### Step 3: Access Grafana

Visit `https://grafana.yourdomain.com`

- Caddy automatically obtains Let's Encrypt certificate
- Default credentials: `admin` / (password shown by setup script)

### Step 4: Verify Services

```bash
# Check all services are running
docker compose ps

# View service logs
docker compose logs -f

# Health check
curl http://localhost:3000/api/health
```

---

## Configuration

### Environment Variables

Create or edit `.env` file:

```bash
# Domain Configuration
DOMAIN=yourdomain.com
ACME_EMAIL=admin@yourdomain.com

# Security
GRAFANA_ADMIN_PASSWORD=your-secure-password
AUTOLOG_WEBHOOK_SECRET=your-webhook-secret

# Data Retention
PROMETHEUS_RETENTION=30d

# Auto-Logging Thresholds
ERROR_THRESHOLD_COUNT=10
ERROR_THRESHOLD_WINDOW_MINUTES=5
AUTOLOG_TTL_MINUTES=30
AUTOLOG_LOG_LEVEL=INFO

# Email Alerts (Optional)
SMTP_USERNAME=alerts@yourcompany.com
SMTP_PASSWORD=your-app-password
ALERT_EMAIL=team@yourcompany.com
CRITICAL_ALERT_EMAIL=oncall@yourcompany.com
```

### File Structure

```
observability/
├── docker-compose.yml          # Service definitions
├── .env                        # Environment variables
├── setup-observability-droplet.sh  # Setup script
│
├── grafana/
│   ├── provisioning/
│   │   ├── datasources/        # Data source configs
│   │   ├── dashboards/         # Dashboard provisioning
│   │   └── alerting/           # Alert rules (provisioned)
│   │       ├── contactpoints.yml
│   │       ├── policies.yml
│   │       └── rules.yml
│   └── dashboards/             # JSON dashboard files
│       ├── applications/
│       ├── infrastructure/
│       └── default/
│
├── prometheus/
│   ├── prometheus.yml          # Main config
│   └── alerts/                 # Prometheus alert rules
│
├── loki/
│   └── loki.yml               # Loki configuration
│
├── tempo/
│   └── tempo.yml              # Tempo configuration
│
├── alertmanager/
│   └── alertmanager.yml       # Alert routing
│
├── otel-collector/
│   └── otel-collector-config.yml  # OTEL pipeline config
│
├── promtail/
│   └── promtail-local.yml     # Log collection config
│
├── caddy/
│   └── Caddyfile              # Reverse proxy config
│
└── autolog-service/
    ├── main.go                # Go service code
    ├── Dockerfile             # Multi-stage build
    └── README.md              # Service documentation
```

---

## Integrating Applications

### .NET Application Setup

#### 1. Add NuGet Packages

```xml
<PackageReference Include="OpenTelemetry.Exporter.OpenTelemetryProtocol" Version="1.14.0-rc.1" />
<PackageReference Include="OpenTelemetry.Extensions.Hosting" Version="1.13.1" />
<PackageReference Include="OpenTelemetry.Instrumentation.AspNetCore" Version="1.13.0" />
<PackageReference Include="OpenTelemetry.Instrumentation.EntityFrameworkCore" Version="1.13.0-beta.1" />
<PackageReference Include="OpenTelemetry.Instrumentation.Http" Version="1.13.0" />
<PackageReference Include="OpenTelemetry.Instrumentation.Runtime" Version="1.13.0" />
<PackageReference Include="Serilog.Sinks.OpenTelemetry" Version="4.2.0" />
```

#### 2. Configure OpenTelemetry in Program.cs

```csharp
var otelCollectorUrl = builder.Configuration.GetValue<string>("Observability:Endpoint");

var resourceBuilder = ResourceBuilder.CreateDefault()
    .AddService("YourAppName", serviceInstanceId: Environment.MachineName)
    .AddAttributes(new Dictionary<string, object>
    {
        ["environment"] = builder.Environment.EnvironmentName,
        ["deployment.environment"] = builder.Environment.EnvironmentName,
    });

// Configure Serilog to send logs via OTLP
builder.Host.UseSerilog((ctx, loggerConfig) =>
{
    loggerConfig.ReadFrom.Configuration(ctx.Configuration)
        .Enrich.FromLogContext()
        .Enrich.WithProperty("Application", "YourAppName")
        .Enrich.WithProperty("Environment", ctx.HostingEnvironment.EnvironmentName)
        .WriteTo.OpenTelemetry(opt =>
        {
            opt.ResourceAttributes = resourceBuilder.Build().Attributes.ToDictionary();
            opt.Endpoint = otelCollectorUrl;
            opt.Protocol = OtlpProtocol.Grpc;
        })
        .WriteTo.Console();
});

// Configure OpenTelemetry for Metrics and Traces
builder.Services.AddOpenTelemetry()
    .WithMetrics(m =>
    {
        m.SetResourceBuilder(resourceBuilder)
            .AddAspNetCoreInstrumentation()
            .AddRuntimeInstrumentation()
            .AddHttpClientInstrumentation()
            .AddOtlpExporter(o =>
            {
                o.Endpoint = new Uri(otelCollectorUrl);
                o.Protocol = OtlpExportProtocol.Grpc;
            });
    })
    .WithTracing(t =>
    {
        t.SetResourceBuilder(resourceBuilder)
            .AddAspNetCoreInstrumentation(c => c.RecordException = true)
            .AddHttpClientInstrumentation(c => c.RecordException = true)
            .AddEntityFrameworkCoreInstrumentation()
            .AddOtlpExporter(o =>
            {
                o.Endpoint = new Uri(otelCollectorUrl);
                o.Protocol = OtlpExportProtocol.Grpc;
            });
    });
```

#### 3. Application Configuration

```json
{
  "Observability": {
    "Endpoint": "http://otel-collector:4317",
    "Tracing": {
      "IgnoredUrls": ["localhost", "127.0.0.1"]
    }
  },
  "AutoLog": {
    "ServiceUrl": "http://autolog-service:5000",
    "AppName": "yourapp"
  }
}
```

#### 4. Docker Compose Network

```yaml
services:
  your-api:
    image: yourapp:latest
    environment:
      - Observability__Endpoint=http://otel-collector:4317
      - AutoLog__ServiceUrl=http://autolog-service:5000
    networks:
      - observability

networks:
  observability:
    external: true
    name: observability_observability
```

---

## OpenTelemetry Labels

The stack uses standardized OpenTelemetry semantic conventions for resource attributes.

### Required Attributes

| Attribute | Label in Grafana | Description |
|-----------|------------------|-------------|
| `service.name` | `service_name` | Application/service identifier |
| `deployment.environment` | `deployment_environment` | Environment (production, staging, development) |

### Log Severity Levels

Logs use the OpenTelemetry severity text convention:

| Severity | Use Case |
|----------|----------|
| `TRACE` | Detailed debugging information |
| `DEBUG` | Debugging information |
| `INFO` | Informational messages |
| `WARN` | Warning messages |
| `ERROR` | Error conditions |
| `FATAL` | Critical failures |

### Example LogQL Queries

```logql
# All logs from a service
{service_name="jaiye"}

# Error logs with JSON parsing
{service_name="jaiye"} | json | severity_text=~"ERROR|FATAL"

# Logs by environment
{deployment_environment="production"} | json

# Search log body
{service_name="jaiye"} |= "database connection"
```

---

## Grafana Dashboards

### Pre-Built Dashboards

| Dashboard | Path | Purpose |
|-----------|------|---------|
| **Application Overview** | `/dashboards/applications/application-overview.json` | Service health, request rates, latency |
| **Logs Explorer** | `/dashboards/applications/logs-explorer.json` | Log search with collapsible panels |
| **Traces Explorer** | `/dashboards/applications/traces-explorer.json` | Distributed trace search |
| **Trace Search** | `/dashboards/applications/trace-search.json` | TraceQL query interface |
| **Metrics Explorer** | `/dashboards/applications/metrics-explorer.json` | Prometheus metrics browser |
| **Errors Dashboard** | `/dashboards/default/errors-dashboard.json` | Error monitoring and trends |
| **System Overview** | `/dashboards/default/system-overview.json` | Infrastructure metrics |
| **Observability Stack** | `/dashboards/infrastructure/observability-stack.json` | Stack health monitoring |

### Dashboard Variables

All dashboards support these variables:

| Variable | Description | Example Values |
|----------|-------------|----------------|
| `$service` | Filter by service name | `jaiye`, `estatevault` |
| `$environment` | Filter by environment | `production`, `staging` |
| `$severity` | Filter by log severity | `ERROR`, `FATAL`, `WARN` |

### Data Links

Dashboards are interconnected with data links:

- **Logs -> Traces**: Click TraceID in logs to view full trace
- **Traces -> Logs**: View logs for specific trace span
- **Metrics -> Logs**: Jump from metric anomaly to related logs

---

## Alerting

### Grafana Unified Alerting

The stack uses Grafana's Unified Alerting with file-based provisioning.

#### Contact Points (`grafana/provisioning/alerting/contactpoints.yml`)

| Contact Point | Type | Purpose |
|---------------|------|---------|
| `default-receiver` | Webhook | Default notifications |
| `critical-alerts` | Webhook | High-priority critical alerts |
| `autolog-webhook` | Webhook | Triggers auto-logging service |
| `application-alerts` | Webhook | Application-specific alerts |
| `infrastructure-alerts` | Webhook | Infrastructure alerts |

#### Alert Rules (`grafana/provisioning/alerting/rules.yml`)

**Error Alerts:**
- High Error Rate - Sustained error rate > 0.1/sec
- Fatal Error Detected - Any FATAL severity log (triggers auto-logging)
- Sustained High Error Count - >100 errors in 15 minutes (triggers auto-logging)
- Database Errors - Database-related error patterns
- Authentication Errors - Auth failure patterns
- External Service Errors - Third-party API failures

**Infrastructure Alerts:**
- High CPU Usage - >85% for 5 minutes
- High Memory Usage - >90% for 5 minutes
- Disk Space Low - >85% usage

**Service Health Alerts:**
- Service Down - No logs received for 5 minutes
- High Latency - P95 latency >2 seconds
- High Trace Error Rate - Error rate >5%

#### Notification Policies (`grafana/provisioning/alerting/policies.yml`)

```yaml
# Routing hierarchy:
# 1. Critical severity -> critical-alerts contact point
# 2. autolog="true" label -> autolog-webhook (triggers auto-logging)
# 3. category="application" -> application-alerts
# 4. category="infrastructure" -> infrastructure-alerts
# 5. Default -> default-receiver
```

### Adding Email Notifications

1. Configure SMTP in Alertmanager (`alertmanager/alertmanager.yml`)
2. Set environment variables:

```bash
SMTP_USERNAME=alerts@yourcompany.com
SMTP_PASSWORD=your-app-password
ALERT_EMAIL=team@yourcompany.com
CRITICAL_ALERT_EMAIL=oncall@yourcompany.com
```

### Testing Alerts

```bash
# Send test alert to Alertmanager
curl -X POST http://localhost:9093/api/v1/alerts \
  -H "Content-Type: application/json" \
  -d '[{
    "labels": {
      "alertname": "TestAlert",
      "severity": "critical",
      "service_name": "test",
      "deployment_environment": "test"
    },
    "annotations": {
      "summary": "This is a test alert"
    }
  }]'
```

---

## Auto-Logging Service

### Overview

The Auto-Logging Service automatically enables verbose logging when error thresholds are exceeded, helping debug production issues without manual intervention.

### How It Works

```
1. Error Detection
   ↓ Grafana/Alertmanager detects high error rate
2. Webhook Trigger
   ↓ Sends webhook to /webhook/autolog
3. Auto-Log Activation
   ↓ Service stores session in Redis with TTL
4. Application Query
   ↓ App polls /api/autolog/check endpoint
5. Verbose Logging
   ↓ App increases log verbosity
6. Auto Expiry
   ↓ After TTL, logging returns to normal
```

### Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `ERROR_THRESHOLD_COUNT` | 10 | Errors before triggering |
| `ERROR_THRESHOLD_WINDOW_MINUTES` | 5 | Time window for counting |
| `AUTOLOG_TTL_MINUTES` | 30 | How long to keep enabled |
| `ALERTMANAGER_WEBHOOK_SECRET` | - | Webhook authentication |

### API Endpoints

```bash
# Health check
GET /health

# Prometheus metrics
GET /metrics

# Check if auto-logging is enabled
GET /api/autolog/check?app=jaiye&environment=production&service=api

# Manually enable auto-logging
POST /api/autolog/enable
{
  "app": "jaiye",
  "environment": "production",
  "service": "api",
  "reason": "Manual investigation",
  "ttl_minutes": 30
}

# Manually disable auto-logging
POST /api/autolog/disable
{
  "app": "jaiye",
  "environment": "production",
  "service": "api"
}

# List all active sessions
GET /api/autolog/list

# Webhook endpoints (for alerting systems)
POST /webhook/autolog
POST /webhook/critical
POST /webhook/application
POST /webhook/infrastructure
```

### Application Integration

#### C# Example

```csharp
public class AutoLogMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly string _autoLogServiceUrl;
    private readonly string _appName;

    public async Task InvokeAsync(HttpContext context)
    {
        var autoLogEnabled = await IsAutoLogEnabledAsync();

        if (autoLogEnabled)
        {
            // Set OpenTelemetry activity tags
            Activity.Current?.SetTag("autolog.enabled", true);

            // Store in HttpContext for downstream components
            context.Items["AutoLogEnabled"] = true;

            // Log verbose request details
            LogVerboseRequest(context);
        }

        await _next(context);
    }

    private async Task<bool> IsAutoLogEnabledAsync()
    {
        var client = _httpClientFactory.CreateClient();
        client.Timeout = TimeSpan.FromMilliseconds(500);

        var response = await client.GetAsync(
            $"{_autoLogServiceUrl}/api/autolog/check?app={_appName}&environment={_environment}"
        );

        if (response.IsSuccessStatusCode)
        {
            var result = await response.Content.ReadFromJsonAsync<AutoLogResponse>();
            return result?.Enabled ?? false;
        }

        return false;
    }
}
```

### Prometheus Metrics

```
autolog_webhook_requests_total      # Total webhook requests received
autolog_triggers_total              # Auto-logging triggers by source
autolog_active_count                # Currently active sessions
autolog_error_events_total          # Error events processed
autolog_webhook_duration_seconds    # Webhook processing duration
```

---

## Caddy Reverse Proxy

### Features

- **Automatic HTTPS** with Let's Encrypt
- **Auto-renewal** of certificates (30 days before expiry)
- **HTTP/3** support for better performance
- **Security headers** pre-configured
- **Zero configuration** SSL setup

### Caddyfile Configuration

```caddyfile
# Grafana
grafana.{$DOMAIN} {
    reverse_proxy grafana:3000

    header {
        Strict-Transport-Security "max-age=31536000"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
    }
}
```

### Adding Basic Auth (Optional)

```bash
# Generate password hash
docker exec caddy caddy hash-password
# Enter password, copy the hash
```

```caddyfile
grafana.{$DOMAIN} {
    basicauth {
        admin $2a$14$... # Paste hash here
    }
    reverse_proxy grafana:3000
}
```

### Certificate Management

```bash
# Check certificate status
docker compose exec caddy caddy list-certificates

# View Caddy logs
docker compose logs caddy

# Force certificate renewal
docker compose restart caddy
```

---

## Multi-Application Setup

### Adding a New Application

1. **Instrument the Application**
   - Add OpenTelemetry SDK packages
   - Configure exporter endpoint
   - Set resource attributes (`service.name`, `deployment.environment`)

2. **Configure Docker Network**
   ```yaml
   networks:
     - observability

   networks:
     observability:
       external: true
       name: observability_observability
   ```

3. **Update Dashboards**
   - Dashboards automatically pick up new services via variables
   - Optionally create service-specific dashboards

4. **Configure Alerts**
   - Add service-specific alert rules in Grafana
   - Update notification policies if needed

### Environment Management

Each environment should have:

1. **Unique resource attributes**:
   ```csharp
   .AddAttributes(new Dictionary<string, object>
   {
       ["deployment.environment"] = "staging",
   });
   ```

2. **Environment-specific alert routing**:
   - Production: Critical alerts to on-call
   - Staging: Email notifications only
   - Development: Slack or silent

3. **Dashboard filtering**:
   - Use `$environment` variable to switch views

---

## Troubleshooting

### Service Won't Start

```bash
# Check container logs
docker compose logs <service-name>

# Check service health
docker compose ps

# Restart specific service
docker compose restart <service-name>

# Rebuild and restart
docker compose build <service-name>
docker compose up -d <service-name>
```

### Prometheus Permission Errors

```bash
# Fix config file permissions
chmod 644 prometheus/prometheus.yml prometheus/alerts/*.yml
chmod 755 prometheus prometheus/alerts
docker compose restart prometheus
```

### Tempo Permission Errors

```bash
# Fix volume permissions
docker compose stop tempo
TEMPO_VOL=$(docker volume inspect observability_tempo-storage --format '{{ .Mountpoint }}')
sudo chown -R 10001:10001 "$TEMPO_VOL"
docker compose start tempo
```

### Loki Configuration Errors

Loki 3.x removed these deprecated fields:
```yaml
# REMOVE if present:
limits_config:
  enforce_metric_name: false  # REMOVED in Loki 3.x

compactor:
  shared_store: filesystem    # REMOVED in Loki 3.x
```

### Logs Not Appearing

```bash
# Verify Loki is receiving logs
curl http://localhost:3100/loki/api/v1/labels

# Check available label values
curl http://localhost:3100/loki/api/v1/label/service_name/values

# Verify OTEL Collector pipeline
docker compose logs otel-collector
```

### Traces Not Appearing

```bash
# Check Tempo health
curl http://localhost:3200/ready

# Verify OTEL Collector is exporting traces
docker compose logs otel-collector | grep -i trace

# Check trace ingestion
curl http://localhost:3200/api/search
```

### Caddy Certificate Issues

```bash
# Check DNS resolution
dig grafana.yourdomain.com

# Verify firewall allows HTTP/HTTPS
ufw status | grep -E "80|443"

# Check Caddy logs
docker compose logs caddy

# Common issues:
# - DNS not pointing to droplet (wait up to 24 hours)
# - Firewall blocking port 80 or 443
# - Let's Encrypt rate limit (5 certs/domain/week)
```

### High Memory Usage

```bash
# Check resource usage
docker stats

# Reduce retention periods
# Edit prometheus/prometheus.yml or use env var:
PROMETHEUS_RETENTION=15d

# Reduce Loki retention
# Edit loki/loki.yml:
limits_config:
  retention_period: 168h  # 7 days
```

### Quick Health Check Script

```bash
#!/bin/bash
echo "Health Check"
echo ""

for service in grafana prometheus loki tempo alertmanager autolog-service otel-collector caddy; do
  status=$(docker compose ps $service --format json | jq -r '.[0].State' 2>/dev/null || echo "not found")
  if [ "$status" = "running" ]; then
    echo "OK: $service"
  else
    echo "FAIL: $service ($status)"
  fi
done

echo ""
echo "Resource Usage:"
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"
```

---

## Maintenance

### Daily Checks

- [ ] Verify all services are running: `docker compose ps`
- [ ] Check for alert notifications
- [ ] Review error dashboard for anomalies

### Weekly Tasks

- [ ] Review disk usage: `df -h && docker system df`
- [ ] Check alert frequency and tune thresholds if needed
- [ ] Verify auto-logging triggers are working

### Monthly Tasks

- [ ] Update Docker images: `docker compose pull && docker compose up -d`
- [ ] Review and archive old data if needed
- [ ] Check certificate expiration: `docker compose exec caddy caddy list-certificates`
- [ ] Review and update alert rules

### Backup Strategy

```bash
# Backup Grafana data
docker run --rm -v observability_grafana-storage:/data -v $(pwd):/backup alpine \
  tar czf /backup/grafana-backup.tar.gz -C /data .

# Backup Prometheus data
docker run --rm -v observability_prometheus-storage:/data -v $(pwd):/backup alpine \
  tar czf /backup/prometheus-backup.tar.gz -C /data .

# Backup configuration files
tar czf observability-config-backup.tar.gz \
  docker-compose.yml .env \
  grafana/ prometheus/ loki/ tempo/ alertmanager/ otel-collector/
```

### Cleanup

```bash
# Remove unused Docker resources
docker system prune -a

# Remove old volumes (CAREFUL!)
docker volume prune

# Clear Loki data older than retention
# (Handled automatically by retention policy)
```

---

## API Reference

### Grafana API

```bash
# Health check
curl http://localhost:3000/api/health

# List datasources
curl -u admin:password http://localhost:3000/api/datasources

# Search dashboards
curl -u admin:password http://localhost:3000/api/search
```

### Prometheus API

```bash
# Health check
curl http://localhost:9090/-/healthy

# Query metrics
curl 'http://localhost:9090/api/v1/query?query=up'

# List targets
curl http://localhost:9090/api/v1/targets

# List alert rules
curl http://localhost:9090/api/v1/rules
```

### Loki API

```bash
# Health check
curl http://localhost:3100/ready

# List labels
curl http://localhost:3100/loki/api/v1/labels

# Query logs
curl -G http://localhost:3100/loki/api/v1/query_range \
  --data-urlencode 'query={service_name="jaiye"}' \
  --data-urlencode 'limit=10'
```

### Tempo API

```bash
# Health check
curl http://localhost:3200/ready

# Search traces
curl 'http://localhost:3200/api/search?tags=service.name%3Djaiye'

# Get trace by ID
curl 'http://localhost:3200/api/traces/<trace-id>'
```

### Alertmanager API

```bash
# Health check
curl http://localhost:9093/-/healthy

# List alerts
curl http://localhost:9093/api/v1/alerts

# List silences
curl http://localhost:9093/api/v1/silences

# Create silence
curl -X POST http://localhost:9093/api/v1/silences \
  -H "Content-Type: application/json" \
  -d '{
    "matchers": [{"name": "alertname", "value": "TestAlert"}],
    "startsAt": "2024-01-01T00:00:00Z",
    "endsAt": "2024-01-02T00:00:00Z",
    "createdBy": "admin",
    "comment": "Maintenance window"
  }'
```

### Auto-Log Service API

See [Auto-Logging Service](#auto-logging-service) section for complete API documentation.

---

## Additional Resources

- [Grafana Documentation](https://grafana.com/docs/grafana/latest/)
- [Prometheus Documentation](https://prometheus.io/docs/)
- [Loki Documentation](https://grafana.com/docs/loki/latest/)
- [Tempo Documentation](https://grafana.com/docs/tempo/latest/)
- [OpenTelemetry .NET](https://opentelemetry.io/docs/languages/net/)
- [Caddy Documentation](https://caddyserver.com/docs/)
- [LogQL Reference](https://grafana.com/docs/loki/latest/query/)
- [TraceQL Reference](https://grafana.com/docs/tempo/latest/traceql/)
- [PromQL Reference](https://prometheus.io/docs/prometheus/latest/querying/basics/)

---

## Support

For issues:
1. Check the [Troubleshooting](#troubleshooting) section
2. Review service logs: `docker compose logs <service-name>`
3. Check service health: `docker compose ps`
4. Verify firewall rules: `ufw status numbered`
5. Check network connectivity: `docker network inspect observability_observability`

# Backup and Disaster Recovery Procedures

## What to Back Up

### Critical
1. **Configuration files** - Version controlled in git
2. **`.env` file** - Contains secrets; store securely outside the repo
3. **Grafana storage** (`grafana-storage`) - UI-created dashboards, user preferences
4. **Prometheus storage** (`prometheus-storage`) - Metrics time-series data

### Recommended
5. **Loki storage** (`loki-storage`) - Log data
6. **Tempo storage** (`tempo-storage`) - Trace data
7. **AlertManager storage** (`alertmanager-storage`) - Silences and notification state

### Can Be Rebuilt
8. **Redis** (`redis-autolog`) - Ephemeral autolog sessions; rebuilds automatically
9. **Caddy** (`caddy-data`, `caddy-config`) - TLS certificates; auto-renewed

## Backup Procedures

### Volume Backup

```bash
# Stop services for data consistency (recommended for Prometheus/Loki)
docker compose stop prometheus loki tempo grafana

# Back up each volume
for vol in grafana-storage prometheus-storage loki-storage tempo-storage alertmanager-storage; do
  docker run --rm \
    -v observability_${vol}:/source:ro \
    -v $(pwd)/backups:/backup \
    alpine tar czf /backup/${vol}-$(date +%Y%m%d).tar.gz -C /source .
done

# Restart services
docker compose start prometheus loki tempo grafana
```

### Automated Backup (Cron)

Add to root crontab (`sudo crontab -e`):

```cron
# Daily backup at 3 AM
0 3 * * * cd /opt/observability && ./scripts/backup-volumes.sh >> /var/log/observability-backup.log 2>&1

# Weekly cleanup of backups older than 7 days
0 4 * * 0 find /opt/observability/backups -name "*.tar.gz" -mtime +7 -delete
```

### Configuration Backup

```bash
# .env is in .gitignore - back it up separately
cp .env /secure-backup-location/.env.observability
```

## Restore Procedures

### Restore a Single Volume

```bash
docker compose stop grafana

docker run --rm \
  -v observability_grafana-storage:/target \
  -v $(pwd)/backups:/backup \
  alpine sh -c "rm -rf /target/* && tar xzf /backup/grafana-storage-YYYYMMDD.tar.gz -C /target"

docker compose start grafana
```

### Full Stack Recovery

1. Provision a new droplet
2. Clone the repository
3. Restore `.env` from secure backup
4. Run `./setup-observability-droplet.sh`
5. Restore volume backups (see above)
6. Update DNS records to point to new droplet IP
7. Verify Caddy obtains new TLS certificates

### Partial Recovery (Single Component)

1. `docker compose stop <service>`
2. `docker volume rm observability_<service>-storage` (if data is corrupted)
3. `docker compose up -d <service>`
4. Restore from backup if needed

## Retention Reference

| Component  | Config Location | Default | Env Var |
|------------|----------------|---------|---------|
| Prometheus | CLI flags | 15d and 4GB cap | `PROMETHEUS_RETENTION`, `PROMETHEUS_RETENTION_SIZE` |
| Loki | loki.yml | 168h (7d) | `LOKI_RETENTION` |
| Tempo | tempo.yml | 168h (7d) | `TEMPO_RETENTION` |

Adjust retention to control storage growth before disk space becomes an issue.

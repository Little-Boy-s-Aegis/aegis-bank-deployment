#!/bin/bash
# Aegis Database Backup Script (Linux/Docker)

# Set directories relative to deployment root
DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_DIR="${DEPLOY_DIR}/backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/aegis_backup_${TIMESTAMP}.sql"

# Create backup directory if not exists
mkdir -p "${BACKUP_DIR}"

echo "=================================================="
echo "Starting PostgreSQL backup: $(date)"
echo "Target file: ${BACKUP_FILE}"

# Run pg_dump inside docker container and stream to backup file
docker compose -f "${DEPLOY_DIR}/docker-compose.yml" exec -T postgres pg_dump -U postgres -d aegis > "${BACKUP_FILE}"

# Check backup status
if [ $? -eq 0 ]; then
  echo "Backup completed successfully!"
  # Compress backup file using gzip to save storage space
  gzip -f "${BACKUP_FILE}"
  echo "Compressed file: ${BACKUP_FILE}.gz"
  
  # Retention policy: Deleting backups older than 7 days
  echo "Applying retention policy (deleting backups older than 7 days)..."
  find "${BACKUP_DIR}" -name "aegis_backup_*.sql.gz" -type f -mtime +7 -delete
  echo "Cleanup completed."
else
  echo "ERROR: Backup failed!"
  # Clean up partial failed backup files
  rm -f "${BACKUP_FILE}"
  exit 1
fi
echo "=================================================="

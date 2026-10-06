#!/bin/sh
set -e

# Example script to backup SQLite database while container is running
# Intended to be run periodically via cron

DATA_DIR="/data"
BACKUP_DIR="/backup"
DB_FILE="${DATA_DIR}/access.db"
TIMESTAMP=$(date +%Y%m%d%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/access-${TIMESTAMP}.db"
RETENTION_DAYS=7

if [ ! -f "$DB_FILE" ]; then
    echo "Error: Database file $DB_FILE not found."
    exit 1
fi

echo "Backing up $DB_FILE to $BACKUP_FILE..."
sqlite3 "$DB_FILE" ".backup '${BACKUP_FILE}'"

echo "Pruning backups older than $RETENTION_DAYS days..."
find "$BACKUP_DIR" -name "access-*.db" -type f -mtime +${RETENTION_DAYS} -exec rm -f {} +

echo "Backup complete."

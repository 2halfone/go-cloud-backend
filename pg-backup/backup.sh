#!/bin/bash

BACKUP_DIR=/backups
TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)

mkdir -p $BACKUP_DIR

# AUTH DB
pg_dump -h auth-db -U auth_admin auth_logs_db | gzip > $BACKUP_DIR/auth_logs_db_$TIMESTAMP.sql.gz

# USER DB
pg_dump -h user-db -U user_admin users_db | gzip > $BACKUP_DIR/users_db_$TIMESTAMP.sql.gz

# SOCIAL DB.
pg_dump -h social-log-db -U social_admin social_logs_db | gzip > $BACKUP_DIR/social_logs_db_$TIMESTAMP.sql.gz

# Conserva solo gli ultimi 5 backup per ogni DB, cancella i più vecchi
ls -1t $BACKUP_DIR/auth_logs_db_*.sql.gz | tail -n +6 | xargs -r rm --
ls -1t $BACKUP_DIR/users_db_*.sql.gz | tail -n +6 | xargs -r rm --
ls -1t $BACKUP_DIR/social_logs_db_*.sql.gz | tail -n +6 | xargs -r rm --

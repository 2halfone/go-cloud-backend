# Auth Service Database Documentation

## Overview
This document describes the database configuration and structure for the authentication service in the Go microservices backend.

## Database Configuration,

### Connection Details
- **Database Type**: PostgreSQL 15 (Alpine)
- **Database Name**: `auth_logs_db`
- **Username**: `auth_admin`
- **Password**: `auth_password`
- **Host**: `auth-db` (Docker container)
- **Port**: `5432`

### Docker Configuration
The database is configured in `docker-compose.prod.yml` as:
```yaml
auth-db:
  image: postgres:15-alpine
  environment:
    POSTGRES_DB: auth_logs_db
    POSTGRES_USER: auth_admin
    POSTGRES_PASSWORD: auth_password
  volumes:
    - auth_db_data:/var/lib/postgresql/data
```

## Database Schema

### Tables

#### 1. `users` Table
Stores user account information and authentication data.

**Columns:**
- `id` - Primary key (auto-increment)
- `username` - User's username
- `email` - User's email address
- `password_hash` - Hashed password
- `role` - User role (added in migration 0002)
- `created_at` - Account creation timestamp
- `updated_at` - Last update timestamp

**Current Data:**
- Total users: 22+ registered users (actively growing)
- User synchronization active with user-service

#### 2. `auth_logs` Table
Tracks all authentication events and user actions for audit purposes.

**Columns:**
- `id` - Primary key (auto-increment)
- `user_email` - Email of the user performing the action
- `action` - Type of action performed (e.g., login, logout, registration)
- `timestamp` - When the action occurred

**Purpose:**
- Security auditing
- User activity monitoring
- Login/logout tracking
- System access logs

## Migration History

### Applied Migrations
1. `0001_create_users.sql` - Creates the users table with basic authentication fields
2. `0002_add_role_to_users.sql` - Adds role-based access control to users table
3. `0001_create_auth_logs.sql` - Creates the auth_logs table for activity tracking

## Database Connection

### Go Connection Code
The database connection is handled in `connection.go` using the following configuration:
- Driver: PostgreSQL
- Connection pooling enabled
- Environment-based configuration
- Automatic migration support

### Security Notes
- Database is only accessible within Docker network
- No public port exposure (secure internal communication)
- Strong password authentication
- Connection pooling for performance

## Admin Access

### Planned Features
- `/admin/login-logs` API endpoint to view auth_logs data
- User management interface
- Web-based activity monitoring dashboard
- Log filtering and pagination
- Admin authentication system

### Current Status
- ✅ Database schema established
- ✅ Active logging functionality
- ✅ User registration/authentication working
- ✅ User synchronization with user-service implemented
- ❌ Admin API endpoints (pending implementation)
- ❌ Web dashboard implementation (pending)

## Database Management & Cleanup

### User Management Commands

#### View All Users
```bash
# Lista tutti gli utenti registrati
docker exec go-cloud-backend_auth-db_1 psql -U auth_admin -d auth_logs_db -c "SELECT id, username, email, role, created_at FROM users ORDER BY id;"
```

#### Clean Test Users
```bash
# Visualizza utenti di test
docker exec go-cloud-backend_auth-db_1 psql -U auth_admin -d auth_logs_db -c "SELECT id, username, email FROM users WHERE email LIKE '%test%' OR username LIKE '%test%';"

# Elimina utenti di test (esegui con cautela)
docker exec go-cloud-backend_auth-db_1 psql -U auth_admin -d auth_logs_db -c "DELETE FROM users WHERE email LIKE '%test%' OR username LIKE '%test%';"
```

#### Reset User Sequence
```bash
# Reset sequence ID dopo eliminazioni
docker exec go-cloud-backend_auth-db_1 psql -U auth_admin -d auth_logs_db -c "SELECT setval('users_id_seq', (SELECT MAX(id) FROM users));"
```

### QR Events Management (User-Service Database)

#### View All QR Events
```bash
# Lista tutti gli eventi QR creati
docker exec go-cloud-backend_user-db_1 psql -U user_admin -d users_db -c "SELECT id, event_id, event_name, date, created_at, is_active FROM attendance_events ORDER BY created_at;"
```

#### View Dynamic Attendance Tables
```bash
# Lista tutte le tabelle attendance dinamiche
docker exec go-cloud-backend_user-db_1 psql -U user_admin -d users_db -c "SELECT tablename FROM pg_tables WHERE tablename LIKE 'attendance_%' AND tablename != 'attendance_events';"
```

#### Clean Test Events (Selective)
```bash
# Elimina eventi di test specifici
docker exec go-cloud-backend_user-db_1 psql -U user_admin -d users_db -c "
-- Elimina eventi di test
DELETE FROM attendance_events WHERE event_name LIKE '%test%' OR event_name LIKE '%new%' OR event_name LIKE '%Daily Attendance1%';

-- Droppa le tabelle corrispondenti
DROP TABLE IF EXISTS attendance_new1_2025_06_09;
DROP TABLE IF EXISTS attendance_daily_attendance1_2025_06_09;
DROP TABLE IF EXISTS attendance_daily_attendance2_2025_06_09;
"
```

#### Complete QR Events Reset
```bash
# ⚠️ ATTENZIONE: Reset completo di tutti gli eventi QR
docker exec go-cloud-backend_user-db_1 psql -U user_admin -d users_db -c "
-- Droppa tutte le tabelle attendance dinamiche
DO \$\$
DECLARE 
    r RECORD;
BEGIN
    FOR r IN (SELECT tablename FROM pg_tables WHERE tablename LIKE 'attendance_%' AND tablename != 'attendance_events')
    LOOP
        EXECUTE 'DROP TABLE IF EXISTS ' || r.tablename;
    END LOOP;
END \$\$;

-- Elimina tutti gli eventi
DELETE FROM attendance_events;

-- Reset sequence
ALTER SEQUENCE attendance_events_id_seq RESTART WITH 1;
"
```

### User-Service User Management

#### View User-Service Users
```bash
# Lista utenti nel user-service (dopo sincronizzazione)
docker exec go-cloud-backend_user-db_1 psql -U user_admin -d users_db -c "SELECT id, name, last_name, email, username, status, role, created_at FROM users ORDER BY id;"
```

#### Clean Synchronized Test Users
```bash
# Elimina utenti sincronizzati di test
docker exec go-cloud-backend_user-db_1 psql -U user_admin -d users_db -c "DELETE FROM users WHERE email LIKE '%@local.system' AND id > 4;"
```

### Auth Logs Management

#### View Recent Auth Logs
```bash
# Visualizza log di autenticazione recenti
docker exec go-cloud-backend_auth-db_1 psql -U auth_admin -d auth_logs_db -c "SELECT id, user_email, action, timestamp FROM auth_logs ORDER BY timestamp DESC LIMIT 20;"
```

#### Clean Old Auth Logs
```bash
# Elimina log più vecchi di 30 giorni
docker exec go-cloud-backend_auth-db_1 psql -U auth_admin -d auth_logs_db -c "DELETE FROM auth_logs WHERE timestamp < NOW() - INTERVAL '30 days';"
```

#### Auth Logs Statistics
```bash
# Statistiche sui log di autenticazione
docker exec go-cloud-backend_auth-db_1 psql -U auth_admin -d auth_logs_db -c "
SELECT 
    action,
    COUNT(*) as count,
    DATE(timestamp) as date
FROM auth_logs 
WHERE timestamp >= NOW() - INTERVAL '7 days'
GROUP BY action, DATE(timestamp)
ORDER BY date DESC, action;
"
```

### Database Health Checks

#### Check Database Connections
```bash
# Verifica connessioni attive auth-service
docker exec go-cloud-backend_auth-db_1 psql -U auth_admin -d auth_logs_db -c "SELECT count(*) as active_connections FROM pg_stat_activity WHERE datname = 'auth_logs_db';"

# Verifica connessioni attive user-service
docker exec go-cloud-backend_user-db_1 psql -U user_admin -d users_db -c "SELECT count(*) as active_connections FROM pg_stat_activity WHERE datname = 'users_db';"
```

#### Database Size Monitoring
```bash
# Dimensioni database auth-service
docker exec go-cloud-backend_auth-db_1 psql -U auth_admin -d auth_logs_db -c "SELECT pg_size_pretty(pg_database_size('auth_logs_db')) as auth_db_size;"

# Dimensioni database user-service
docker exec go-cloud-backend_user-db_1 psql -U user_admin -d users_db -c "SELECT pg_size_pretty(pg_database_size('users_db')) as users_db_size;"
```

#### Table Size Analysis
```bash
# Analisi dimensioni tabelle auth-service
docker exec go-cloud-backend_auth-db_1 psql -U auth_admin -d auth_logs_db -c "
SELECT 
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(tablename::text)) as size,
    pg_total_relation_size(tablename::text) as size_bytes
FROM pg_tables 
WHERE schemaname = 'public'
ORDER BY size_bytes DESC;
"
```

### Backup and Restore Commands

#### Create Database Backup
```bash
# Backup auth-service database
docker exec go-cloud-backend_auth-db_1 pg_dump -U auth_admin auth_logs_db > auth_backup_$(date +%Y%m%d_%H%M%S).sql

# Backup user-service database
docker exec go-cloud-backend_user-db_1 pg_dump -U user_admin users_db > users_backup_$(date +%Y%m%d_%H%M%S).sql
```

#### Restore Database
```bash
# Restore auth-service database
cat auth_backup_YYYYMMDD_HHMMSS.sql | docker exec -i go-cloud-backend_auth-db_1 psql -U auth_admin auth_logs_db

# Restore user-service database
cat users_backup_YYYYMMDD_HHMMSS.sql | docker exec -i go-cloud-backend_user-db_1 psql -U user_admin users_db
```

### Production Maintenance

#### User Synchronization Check
```bash
# Verifica sincronizzazione utenti tra auth-service e user-service
echo "=== Auth Service Users ===" && docker exec go-cloud-backend_auth-db_1 psql -U auth_admin -d auth_logs_db -c "SELECT COUNT(*) as auth_users FROM users;" && echo "=== User Service Users ===" && docker exec go-cloud-backend_user-db_1 psql -U user_admin -d users_db -c "SELECT COUNT(*) as user_service_users FROM users;"
```

#### System Status Overview
```bash
# Overview completo del sistema
echo "=== SYSTEM STATUS OVERVIEW ===" && \
echo "Auth Service Users:" && docker exec go-cloud-backend_auth-db_1 psql -U auth_admin -d auth_logs_db -c "SELECT COUNT(*) FROM users;" && \
echo "User Service Users:" && docker exec go-cloud-backend_user-db_1 psql -U user_admin -d users_db -c "SELECT COUNT(*) FROM users;" && \
echo "QR Events:" && docker exec go-cloud-backend_user-db_1 psql -U user_admin -d users_db -c "SELECT COUNT(*) FROM attendance_events;" && \
echo "Auth Logs (last 24h):" && docker exec go-cloud-backend_auth-db_1 psql -U auth_admin -d auth_logs_db -c "SELECT COUNT(*) FROM auth_logs WHERE timestamp >= NOW() - INTERVAL '24 hours';"
```

## Maintenance

### Backup Considerations
- Database data persisted in Docker volume `auth_db_data`
- Regular backup schedule recommended for production
- Migration rollback procedures should be documented
- Use provided backup commands for consistent snapshots

### Performance Monitoring
- Monitor connection pool usage
- Track query performance for auth_logs table
- Consider indexing on frequently queried columns (user_email, timestamp)
- Regular cleanup of old auth_logs recommended (30+ days)

---

**Last Updated:** June 9, 2025  
**Version:** 1.1  
**Status:** Production Ready - User Sync Implemented

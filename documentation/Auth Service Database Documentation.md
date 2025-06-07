# Auth Service Database Documentation

## Overview
This document describes the database configuration and structure for the authentication service in the Go microservices backend.

## Database Configuration

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
- Total users: 22 registered users

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
- ❌ Admin API endpoints (pending implementation)
- ❌ Web dashboard implementation (pending)

## Maintenance

### Backup Considerations
- Database data persisted in Docker volume `auth_db_data`
- Regular backup schedule recommended for production
- Migration rollback procedures should be documented

### Performance Monitoring
- Monitor connection pool usage
- Track query performance for auth_logs table
- Consider indexing on frequently queried columns (user_email, timestamp)

---

**Last Updated:** June 7, 2025  
**Version:** 1.0  
**Status:** Active Development

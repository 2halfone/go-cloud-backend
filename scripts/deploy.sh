#!/bin/bash

# Deployment script for Go microservices on VM
# This script handles deployment, backup, rollback, and health checks

set -euo pipefail

# Configuration
APP_NAME="go-microservices"
DEPLOY_USER="deploy"
DEPLOY_DIR="/opt/$APP_NAME"
BACKUP_DIR="/opt/backups/$APP_NAME"
SYSTEMD_DIR="/etc/systemd/system"
NGINX_DIR="/etc/nginx"
LOG_FILE="/var/log/${APP_NAME}-deploy.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
    exit 1
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        error "This script should not be run as root for security reasons"
    fi
}

# Function to create backup
create_backup() {
    log "Creating backup..."
    
    if [[ -d "$DEPLOY_DIR" ]]; then
        local backup_name="${APP_NAME}-$(date +%Y%m%d-%H%M%S)"
        local backup_path="$BACKUP_DIR/$backup_name"
        
        sudo mkdir -p "$BACKUP_DIR"
        sudo cp -r "$DEPLOY_DIR" "$backup_path"
        sudo chown -R "$DEPLOY_USER:$DEPLOY_USER" "$backup_path"
        
        # Keep only last 5 backups
        sudo find "$BACKUP_DIR" -maxdepth 1 -type d -name "${APP_NAME}-*" | sort -r | tail -n +6 | xargs -r sudo rm -rf
        
        success "Backup created at $backup_path"
        echo "$backup_path" > /tmp/last_backup_path
    else
        warning "No existing deployment found, skipping backup"
    fi
}

# Function to stop services
stop_services() {
    log "Stopping services..."
    
    local services=("${APP_NAME}-gateway" "${APP_NAME}-auth" "${APP_NAME}-user" "nginx")
    
    for service in "${services[@]}"; do
        if sudo systemctl is-active --quiet "$service" 2>/dev/null; then
            sudo systemctl stop "$service"
            log "Stopped $service"
        else
            warning "Service $service is not running"
        fi
    done
}

# Function to start services
start_services() {
    log "Starting services..."
    
    local services=("${APP_NAME}-auth" "${APP_NAME}-user" "${APP_NAME}-gateway" "nginx")
    
    for service in "${services[@]}"; do
        sudo systemctl start "$service"
        sudo systemctl enable "$service"
        
        if sudo systemctl is-active --quiet "$service"; then
            success "Started $service"
        else
            error "Failed to start $service"
        fi
    done
}

# Function to deploy binaries
deploy_binaries() {
    log "Deploying binaries..."
    
    # Create deployment directory
    sudo mkdir -p "$DEPLOY_DIR"/{gateway,auth-service,user-service}
    
    # Copy binaries (assuming they are in current directory)
    if [[ -f "gateway" ]]; then
        sudo cp gateway "$DEPLOY_DIR/gateway/"
        sudo chmod +x "$DEPLOY_DIR/gateway/gateway"
    else
        error "Gateway binary not found"
    fi
    
    if [[ -f "auth-service" ]]; then
        sudo cp auth-service "$DEPLOY_DIR/auth-service/"
        sudo chmod +x "$DEPLOY_DIR/auth-service/auth-service"
    else
        error "Auth service binary not found"
    fi
    
    if [[ -f "user-service" ]]; then
        sudo cp user-service "$DEPLOY_DIR/user-service/"
        sudo chmod +x "$DEPLOY_DIR/user-service/user-service"
    else
        error "User service binary not found"
    fi
    
    # Set ownership
    sudo chown -R "$DEPLOY_USER:$DEPLOY_USER" "$DEPLOY_DIR"
    
    success "Binaries deployed successfully"
}

# Function to update nginx configuration
update_nginx() {
    log "Updating nginx configuration..."
    
    if [[ -f "nginx.conf" ]]; then
        sudo cp nginx.conf "$NGINX_DIR/sites-available/$APP_NAME"
        sudo ln -sf "$NGINX_DIR/sites-available/$APP_NAME" "$NGINX_DIR/sites-enabled/"
        
        # Test nginx configuration
        if sudo nginx -t; then
            success "Nginx configuration updated"
        else
            error "Nginx configuration test failed"
        fi
    else
        warning "nginx.conf not found, skipping nginx update"
    fi
}

# Function to run health checks
health_check() {
    log "Running health checks..."
    
    local max_attempts=30
    local attempt=1
    
    # Wait for services to be ready
    sleep 10
    
    # Check each service
    local services=(
        "http://localhost:3000/health:Gateway"
        "http://localhost:3001/health:Auth Service"
        "http://localhost:3002/health:User Service"
        "http://localhost/health:Nginx"
    )
    
    for service_info in "${services[@]}"; do
        local url="${service_info%:*}"
        local name="${service_info#*:}"
        
        attempt=1
        while [[ $attempt -le $max_attempts ]]; do
            if curl -f -s "$url" > /dev/null 2>&1; then
                success "$name health check passed"
                break
            else
                if [[ $attempt -eq $max_attempts ]]; then
                    error "$name health check failed after $max_attempts attempts"
                fi
                log "Attempt $attempt/$max_attempts: $name not ready, waiting..."
                sleep 5
                ((attempt++))
            fi
        done
    done
    
    success "All health checks passed"
}

# Function to rollback deployment
rollback() {
    log "Rolling back deployment..."
    
    if [[ -f "/tmp/last_backup_path" ]]; then
        local backup_path=$(cat /tmp/last_backup_path)
        
        if [[ -d "$backup_path" ]]; then
            stop_services
            sudo rm -rf "$DEPLOY_DIR"
            sudo cp -r "$backup_path" "$DEPLOY_DIR"
            start_services
            health_check
            success "Rollback completed successfully"
        else
            error "Backup directory not found: $backup_path"
        fi
    else
        error "No backup information found"
    fi
}

# Function to show deployment status
status() {
    log "Checking deployment status..."
    
    local services=("${APP_NAME}-gateway" "${APP_NAME}-auth" "${APP_NAME}-user" "nginx")
    
    echo -e "\n${BLUE}Service Status:${NC}"
    for service in "${services[@]}"; do
        if sudo systemctl is-active --quiet "$service" 2>/dev/null; then
            echo -e "${GREEN}✓${NC} $service: running"
        else
            echo -e "${RED}✗${NC} $service: stopped"
        fi
    done
    
    echo -e "\n${BLUE}Disk Usage:${NC}"
    df -h "$DEPLOY_DIR" 2>/dev/null || echo "Deployment directory not found"
    
    echo -e "\n${BLUE}Recent Logs:${NC}"
    if [[ -f "$LOG_FILE" ]]; then
        tail -10 "$LOG_FILE"
    else
        echo "No log file found"
    fi
}

# Main deployment function
deploy() {
    log "Starting deployment of $APP_NAME"
    
    create_backup
    stop_services
    deploy_binaries
    update_nginx
    start_services
    health_check
    
    success "Deployment completed successfully"
}

# Main script logic
case "${1:-deploy}" in
    deploy)
        check_root
        deploy
        ;;
    rollback)
        check_root
        rollback
        ;;
    status)
        status
        ;;
    start)
        start_services
        ;;
    stop)
        stop_services
        ;;
    restart)
        stop_services
        start_services
        ;;
    health)
        health_check
        ;;
    *)
        echo "Usage: $0 {deploy|rollback|status|start|stop|restart|health}"
        echo ""
        echo "Commands:"
        echo "  deploy   - Deploy the application (default)"
        echo "  rollback - Rollback to previous version"
        echo "  status   - Show deployment status"
        echo "  start    - Start all services"
        echo "  stop     - Stop all services"
        echo "  restart  - Restart all services"
        echo "  health   - Run health checks"
        exit 1
        ;;
esac

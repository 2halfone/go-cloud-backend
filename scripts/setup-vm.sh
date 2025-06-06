#!/bin/bash

# VM Setup and Provisioning Script for Go Microservices
# This script prepares a fresh Ubuntu/Debian VM for deployment

set -euo pipefail

# Configuration
APP_NAME="go-microservices"
DEPLOY_USER="deploy"
DEPLOY_DIR="/opt/$APP_NAME"
BACKUP_DIR="/opt/backups/$APP_NAME"
SYSTEMD_DIR="/etc/systemd/system"
NGINX_DIR="/etc/nginx"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root for initial setup"
    fi
}

# Function to detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    else
        error "Cannot detect operating system"
    fi
    
    log "Detected OS: $OS $VER"
}

# Function to update system packages
update_system() {
    log "Updating system packages..."
    
    if command -v apt-get &> /dev/null; then
        apt-get update
        apt-get upgrade -y
        apt-get install -y curl wget git unzip software-properties-common
    elif command -v yum &> /dev/null; then
        yum update -y
        yum install -y curl wget git unzip
    else
        error "Unsupported package manager"
    fi
    
    success "System packages updated"
}

# Function to install Docker
install_docker() {
    log "Installing Docker..."
    
    if command -v docker &> /dev/null; then
        warning "Docker is already installed"
        return
    fi
    
    # Install Docker
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    rm get-docker.sh
    
    # Install Docker Compose
    curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    
    # Start and enable Docker
    systemctl start docker
    systemctl enable docker
    
    success "Docker installed successfully"
}

# Function to install Nginx
install_nginx() {
    log "Installing Nginx..."
    
    if command -v nginx &> /dev/null; then
        warning "Nginx is already installed"
        return
    fi
    
    if command -v apt-get &> /dev/null; then
        apt-get install -y nginx
    elif command -v yum &> /dev/null; then
        yum install -y nginx
    fi
    
    # Start and enable Nginx
    systemctl start nginx
    systemctl enable nginx
    
    success "Nginx installed successfully"
}

# Function to install monitoring tools
install_monitoring() {
    log "Installing monitoring tools..."
    
    # Install htop, netstat, etc.
    if command -v apt-get &> /dev/null; then
        apt-get install -y htop net-tools iotop tcpdump nmap
    elif command -v yum &> /dev/null; then
        yum install -y htop net-tools iotop tcpdump nmap
    fi
    
    success "Monitoring tools installed"
}

# Function to configure firewall
configure_firewall() {
    log "Configuring firewall..."
    
    if command -v ufw &> /dev/null; then
        # Ubuntu/Debian with UFW
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        
        # Allow SSH
        ufw allow 22/tcp
        
        # Allow HTTP/HTTPS
        ufw allow 80/tcp
        ufw allow 443/tcp
        
        # Allow application ports (for direct access during debugging)
        ufw allow 3000/tcp comment "Gateway Service"
        ufw allow 3001/tcp comment "Auth Service"
        ufw allow 3002/tcp comment "User Service"
        
        ufw --force enable
        success "UFW firewall configured"
        
    elif command -v firewall-cmd &> /dev/null; then
        # CentOS/RHEL with firewalld
        systemctl start firewalld
        systemctl enable firewalld
        
        firewall-cmd --permanent --add-service=ssh
        firewall-cmd --permanent --add-service=http
        firewall-cmd --permanent --add-service=https
        firewall-cmd --permanent --add-port=3000/tcp
        firewall-cmd --permanent --add-port=3001/tcp
        firewall-cmd --permanent --add-port=3002/tcp
        firewall-cmd --reload
        
        success "Firewalld configured"
    else
        warning "No supported firewall found, please configure manually"
    fi
}

# Function to create deploy user
create_deploy_user() {
    log "Creating deploy user..."
    
    if id "$DEPLOY_USER" &>/dev/null; then
        warning "Deploy user already exists"
    else
        useradd -m -s /bin/bash "$DEPLOY_USER"
        success "Deploy user created"
    fi
    
    # Add to docker group
    usermod -aG docker "$DEPLOY_USER"
    
    # Create SSH directory for deploy user
    mkdir -p "/home/$DEPLOY_USER/.ssh"
    chown "$DEPLOY_USER:$DEPLOY_USER" "/home/$DEPLOY_USER/.ssh"
    chmod 700 "/home/$DEPLOY_USER/.ssh"
    
    success "Deploy user configured"
}

# Function to create application directories
create_directories() {
    log "Creating application directories..."
    
    # Create main directories
    mkdir -p "$DEPLOY_DIR"/{gateway,auth-service,user-service}
    mkdir -p "$BACKUP_DIR"
    mkdir -p "/var/log/$APP_NAME"
    
    # Set ownership
    chown -R "$DEPLOY_USER:$DEPLOY_USER" "$DEPLOY_DIR"
    chown -R "$DEPLOY_USER:$DEPLOY_USER" "$BACKUP_DIR"
    chown -R "$DEPLOY_USER:$DEPLOY_USER" "/var/log/$APP_NAME"
    
    success "Application directories created"
}

# Function to configure system limits
configure_limits() {
    log "Configuring system limits..."
    
    # Increase file descriptor limits
    cat >> /etc/security/limits.conf << EOF

# Limits for $APP_NAME
$DEPLOY_USER soft nofile 65536
$DEPLOY_USER hard nofile 65536
$DEPLOY_USER soft nproc 4096
$DEPLOY_USER hard nproc 4096
EOF

    # Configure systemd limits
    mkdir -p /etc/systemd/system.conf.d
    cat > /etc/systemd/system.conf.d/limits.conf << EOF
[Manager]
DefaultLimitNOFILE=65536
DefaultLimitNPROC=4096
EOF

    success "System limits configured"
}

# Function to install SSL certificates (Let's Encrypt)
install_ssl() {
    log "Installing Certbot for SSL certificates..."
    
    if command -v apt-get &> /dev/null; then
        apt-get install -y certbot python3-certbot-nginx
    elif command -v yum &> /dev/null; then
        yum install -y certbot python3-certbot-nginx
    fi
    
    success "Certbot installed (configure SSL manually after domain setup)"
    warning "To get SSL certificate, run: certbot --nginx -d your-domain.com"
}

# Function to configure log rotation
configure_logrotate() {
    log "Configuring log rotation..."
    
    cat > "/etc/logrotate.d/$APP_NAME" << EOF
/var/log/$APP_NAME/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 644 $DEPLOY_USER $DEPLOY_USER
    postrotate
        systemctl reload $APP_NAME-gateway $APP_NAME-auth $APP_NAME-user 2>/dev/null || true
    endscript
}
EOF

    success "Log rotation configured"
}

# Function to install systemd services
install_systemd_services() {
    log "Installing systemd service files..."
    
    # Copy systemd service files (assuming they exist in current directory)
    local services=("gateway" "auth" "user")
    
    for service in "${services[@]}"; do
        local service_file="go-microservices-${service}.service"
        if [[ -f "$service_file" ]]; then
            cp "$service_file" "$SYSTEMD_DIR/"
            success "Installed $service_file"
        else
            warning "Service file $service_file not found"
        fi
    done
    
    # Reload systemd
    systemctl daemon-reload
    
    success "Systemd services installed"
}

# Function to create maintenance scripts
create_maintenance_scripts() {
    log "Creating maintenance scripts..."
    
    mkdir -p "/usr/local/bin"
    
    # Status check script
    cat > "/usr/local/bin/${APP_NAME}-status" << 'EOF'
#!/bin/bash
echo "=== Go Microservices Status ==="
echo ""
echo "Services:"
systemctl status go-microservices-gateway go-microservices-auth go-microservices-user nginx --no-pager -l
echo ""
echo "Health Checks:"
curl -s http://localhost/health && echo " - Nginx: OK" || echo " - Nginx: FAIL"
curl -s http://localhost:3000/health && echo " - Gateway: OK" || echo " - Gateway: FAIL"
curl -s http://localhost:3001/health && echo " - Auth: OK" || echo " - Auth: FAIL"
curl -s http://localhost:3002/health && echo " - User: OK" || echo " - User: FAIL"
echo ""
echo "Disk Usage:"
df -h /opt/go-microservices
echo ""
echo "Memory Usage:"
free -h
echo ""
echo "Recent Logs:"
journalctl -u go-microservices-gateway --no-pager -n 5
EOF

    chmod +x "/usr/local/bin/${APP_NAME}-status"
    
    success "Maintenance scripts created"
}

# Function to run security hardening
security_hardening() {
    log "Applying security hardening..."
    
    # Disable root SSH login
    sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    
    # Disable password authentication (uncomment if using key-based auth)
    # sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    
    # Restart SSH
    systemctl restart sshd
    
    # Set up fail2ban
    if command -v apt-get &> /dev/null; then
        apt-get install -y fail2ban
    elif command -v yum &> /dev/null; then
        yum install -y fail2ban
    fi
    
    systemctl start fail2ban
    systemctl enable fail2ban
    
    success "Security hardening applied"
}

# Function to create deployment script
create_deployment_script() {
    log "Creating deployment script..."
    
    # Copy deployment script if it exists
    if [[ -f "deploy.sh" ]]; then
        cp deploy.sh "/usr/local/bin/${APP_NAME}-deploy"
        chmod +x "/usr/local/bin/${APP_NAME}-deploy"
        chown "$DEPLOY_USER:$DEPLOY_USER" "/usr/local/bin/${APP_NAME}-deploy"
        success "Deployment script installed"
    else
        warning "deploy.sh not found, skipping deployment script installation"
    fi
}

# Function to show completion summary
show_summary() {
    echo ""
    success "=== VM Setup Complete ==="
    echo ""
    echo "Next steps:"
    echo "1. Configure DNS to point to this server"
    echo "2. Set up SSL certificates: certbot --nginx -d your-domain.com"
    echo "3. Copy your deployment artifacts to the server"
    echo "4. Run the deployment: $APP_NAME-deploy"
    echo "5. Check status: $APP_NAME-status"
    echo ""
    echo "Important files:"
    echo "- Application directory: $DEPLOY_DIR"
    echo "- Nginx config: $NGINX_DIR/sites-available/$APP_NAME"
    echo "- Systemd services: $SYSTEMD_DIR/go-microservices-*.service"
    echo "- Deploy script: /usr/local/bin/$APP_NAME-deploy"
    echo "- Status script: /usr/local/bin/$APP_NAME-status"
    echo ""
    echo "Default ports:"
    echo "- HTTP: 80 (Nginx reverse proxy)"
    echo "- HTTPS: 443 (when SSL is configured)"
    echo "- Gateway: 3000 (direct access)"
    echo "- Auth Service: 3001 (direct access)"
    echo "- User Service: 3002 (direct access)"
    echo ""
}

# Main setup function
setup_vm() {
    log "Starting VM setup for $APP_NAME"
    
    detect_os
    update_system
    install_docker
    install_nginx
    install_monitoring
    configure_firewall
    create_deploy_user
    create_directories
    configure_limits
    install_ssl
    configure_logrotate
    install_systemd_services
    create_maintenance_scripts
    security_hardening
    create_deployment_script
    
    show_summary
}

# Main script logic
case "${1:-setup}" in
    setup)
        check_root
        setup_vm
        ;;
    firewall)
        check_root
        configure_firewall
        ;;
    ssl)
        check_root
        install_ssl
        ;;
    security)
        check_root
        security_hardening
        ;;
    *)
        echo "Usage: $0 {setup|firewall|ssl|security}"
        echo ""
        echo "Commands:"
        echo "  setup    - Complete VM setup (default)"
        echo "  firewall - Configure firewall only"
        echo "  ssl      - Install SSL tools only"
        echo "  security - Apply security hardening only"
        exit 1
        ;;
esac

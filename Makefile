.PHONY: deploy-auth deploy-user deploy-gateway deploy-monitoring status health-check clean logs-auth logs-user logs-gateway logs-monitoring full-deploy dev-restart quick-logs help

# =============================================================================
# MODULAR DEPLOYMENT COMMANDS
# =============================================================================

# Deploy single services (NO full restart)
deploy-auth:
	@echo "🔧 Building auth-service..."
	@if [ ! -f docker-compose.yml ]; then echo "❌ docker-compose.yml not found"; exit 1; fi
	docker-compose build auth-service
	@echo "⚡ Restarting ONLY auth-service..."
	docker-compose up -d --no-deps auth-service
	@echo "✅ Auth service deployed successfully"

deploy-user:
	@echo "🔧 Building user-service..."
	@if [ ! -f docker-compose.yml ]; then echo "❌ docker-compose.yml not found"; exit 1; fi
	docker-compose build user-service
	@echo "⚡ Restarting ONLY user-service..."
	docker-compose up -d --no-deps user-service
	@echo "✅ User service deployed successfully"

deploy-gateway:
	@echo "🔧 Building gateway..."
	@if [ ! -f docker-compose.yml ]; then echo "❌ docker-compose.yml not found"; exit 1; fi
	docker-compose build gateway
	@echo "⚡ Restarting ONLY gateway..."
	docker-compose up -d --no-deps gateway
	@echo "✅ Gateway deployed successfully"

deploy-monitoring:
	@echo "🔧 Building monitoring services..."
	@if [ ! -f docker-compose.yml ]; then echo "❌ docker-compose.yml not found"; exit 1; fi
	docker-compose build prometheus-service dashboard-api
	@echo "⚡ Restarting ONLY monitoring services..."
	docker-compose up -d --no-deps prometheus-service dashboard-api
	@echo "✅ Monitoring deployed successfully"

# =============================================================================
# UTILITY COMMANDS
# =============================================================================

status:
	@echo "� Service Status:"
	@if [ ! -f docker-compose.yml ]; then echo "❌ docker-compose.yml not found"; exit 1; fi
	docker-compose ps

health-check:
	@echo "🏥 Health Check:"
	@command -v curl >/dev/null 2>&1 || { echo "❌ curl not installed"; exit 1; }
	@echo "Auth Service:" && (curl -s -f http://localhost:3001/health >/dev/null && echo "✅ UP" || echo "❌ DOWN")
	@echo "User Service:" && (curl -s -f http://localhost:3002/health >/dev/null && echo "✅ UP" || echo "❌ DOWN")
	@echo "Gateway:" && (curl -s -f http://localhost:3000/health >/dev/null && echo "✅ UP" || echo "❌ DOWN")
	@echo "Dashboard:" && (curl -s -f http://localhost:3003/health >/dev/null && echo "✅ UP" || echo "❌ DOWN")

logs-auth:
	@if [ ! -f docker-compose.yml ]; then echo "❌ docker-compose.yml not found"; exit 1; fi
	docker-compose logs -f auth-service

logs-user:
	@if [ ! -f docker-compose.yml ]; then echo "❌ docker-compose.yml not found"; exit 1; fi
	docker-compose logs -f user-service

logs-gateway:
	@if [ ! -f docker-compose.yml ]; then echo "❌ docker-compose.yml not found"; exit 1; fi
	docker-compose logs -f gateway

logs-monitoring:
	@if [ ! -f docker-compose.yml ]; then echo "❌ docker-compose.yml not found"; exit 1; fi
	docker-compose logs -f dashboard-api prometheus-service

# =============================================================================
# EMERGENCY COMMANDS (Use only when necessary)
# =============================================================================

full-deploy:
	@echo "🔥 FULL DEPLOY - This will restart ALL services"
	@echo "⚠️  This should only be used for major changes"
	@if [ ! -f docker-compose.yml ]; then echo "❌ docker-compose.yml not found"; exit 1; fi
	docker-compose down
	docker-compose build
	docker-compose up -d
	@echo "✅ Full deployment complete"

clean:
	@echo "🧹 Cleaning Docker..."
	@if [ ! -f docker-compose.yml ]; then echo "❌ docker-compose.yml not found"; exit 1; fi
	docker-compose down --volumes --remove-orphans
	docker system prune -f

# =============================================================================
# DEVELOPMENT COMMANDS
# =============================================================================

dev-restart:
	@echo "🔄 Quick restart for development"
	@if [ ! -f docker-compose.yml ]; then echo "❌ docker-compose.yml not found"; exit 1; fi
	docker-compose restart

quick-logs:
	@if [ ! -f docker-compose.yml ]; then echo "❌ docker-compose.yml not found"; exit 1; fi
	docker-compose logs --tail=50 -f

# =============================================================================
# HELP
# =============================================================================

help:
	@echo "🚀 Available commands:"
	@echo "  deploy-auth        Deploy only auth-service"
	@echo "  deploy-user        Deploy only user-service"
	@echo "  deploy-gateway     Deploy only gateway"
	@echo "  deploy-monitoring  Deploy only monitoring"
	@echo "  status            Show service status"
	@echo "  health-check      Check service health"
	@echo "  logs-auth         Show auth-service logs"
	@echo "  logs-user         Show user-service logs"
	@echo "  logs-gateway      Show gateway logs"
	@echo "  logs-monitoring   Show monitoring logs"
	@echo "  full-deploy       Deploy all services (emergency)"
	@echo "  clean             Clean Docker (emergency)"
	@echo "  dev-restart       Quick restart all"
	@echo "  quick-logs        Show recent logs"

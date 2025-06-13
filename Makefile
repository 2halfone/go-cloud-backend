# 🚀 Smart Deploy Makefile

.PHONY: help deploy-auth deploy-user deploy-gateway deploy-monitoring deploy-all status

help: ## Show this help
	@echo "🚀 Smart Deploy Commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Deploy singoli servizi
deploy-auth: ## Deploy only auth-service
	@echo "🔧 Deploying Auth Service..."
	docker-compose build auth-service
	docker-compose up -d auth-service
	@echo "✅ Auth Service deployed!"

deploy-user: ## Deploy only user-service
	@echo "🔧 Deploying User Service..."
	docker-compose build user-service
	docker-compose up -d user-service
	@echo "✅ User Service deployed!"

deploy-gateway: ## Deploy only gateway
	@echo "🔧 Deploying Gateway..."
	docker-compose build gateway
	docker-compose up -d gateway
	@echo "✅ Gateway deployed!"

deploy-monitoring: ## Deploy only monitoring services
	@echo "🔧 Deploying Monitoring..."
	docker-compose build dashboard-api prometheus-service
	docker-compose up -d dashboard-api prometheus-service
	@echo "✅ Monitoring deployed!"

deploy-all: ## Deploy all services (full rebuild)
	@echo "🔥 Full deployment..."
	docker-compose down
	docker-compose build
	docker-compose up -d
	@echo "✅ Full stack deployed!"

# Utility commands
status: ## Show services status
	@echo "📊 Services Status:"
	docker-compose ps

logs-auth: ## Show auth-service logs
	docker-compose logs -f auth-service

logs-user: ## Show user-service logs
	docker-compose logs -f user-service

logs-gateway: ## Show gateway logs
	docker-compose logs -f gateway

logs-monitoring: ## Show monitoring logs
	docker-compose logs -f dashboard-api prometheus-service

# Health checks
health-check: ## Check all services health
	@echo "🏥 Health Checking..."
	@curl -f http://localhost:3001/health && echo "✅ Auth Service OK" || echo "❌ Auth Service DOWN"
	@curl -f http://localhost:3002/health && echo "✅ User Service OK" || echo "❌ User Service DOWN"
	@curl -f http://localhost:8080/health && echo "✅ Gateway OK" || echo "❌ Gateway DOWN"
	@curl -f http://localhost:3003/api/health && echo "✅ Monitoring OK" || echo "❌ Monitoring DOWN"

# Quick deploy commands
quick-auth: ## Quick auth deploy (no cache)
	docker-compose build --no-cache auth-service
	docker-compose up -d auth-service

quick-user: ## Quick user deploy (no cache)
	docker-compose build --no-cache user-service
	docker-compose up -d user-service

# Development helpers
dev-up: ## Start all services for development
	docker-compose -f docker-compose.yml up -d

dev-down: ## Stop all development services
	docker-compose -f docker-compose.yml down

# Clean up
clean: ## Clean unused Docker resources
	docker system prune -f
	docker volume prune -f

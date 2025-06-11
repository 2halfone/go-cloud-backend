# Prometheus Monitoring Service

## Overview
Servizio di monitoraggio per il backend modulare Go che raccoglie metriche da tutti i microservizi.

## Features
- 📊 Raccolta metriche HTTP (richieste, durata, status codes)
- 🔐 Monitoraggio autenticazioni e tentativi di login
- 📱 Tracking scansioni QR code
- 👥 Conteggio utenti attivi
- 🔍 Dashboard semplice per visualizzazione metriche
- 🏥 Health check endpoint

## Endpoints

### Health Check
```
GET /health
```

### Metriche Prometheus
```
GET /metrics
```

### Dashboard Semplice
```
GET /dashboard
```

### Statistiche in Tempo Reale
```
GET /stats
```

## Metriche Raccolte

### HTTP Requests
- `http_requests_total` - Totale richieste HTTP per servizio
- `http_request_duration_seconds` - Durata delle richieste HTTP

### Autenticazione
- `auth_attempts_total` - Tentativi di autenticazione (successo/fallimento)

### QR Code
- `qr_scans_total` - Scansioni QR code per evento

### Sistema
- `active_users_total` - Numero utenti attivi
- `system_errors_total` - Errori di sistema per servizio
- `database_connections_active` - Connessioni database attive

## Configurazione

### Variabili d'Ambiente
- `PROMETHEUS_PORT` - Porta del servizio (default: 9090)

### Docker
Il servizio è configurato in `docker-compose.prod.yml` e si avvia automaticamente con:
```bash
docker-compose -f docker-compose.prod.yml up -d
```

## Accesso
- **Servizio**: http://localhost:9090
- **Metriche**: http://localhost:9090/metrics  
- **Dashboard**: http://localhost:9090/dashboard
- **Health**: http://localhost:9090/health

## Integrazione
Il servizio raccoglie automaticamente metriche da:
- Auth Service (porta 3001)
- User Service (porta 3002)  
- Gateway (porta 3000)

## Build Locale
```bash
go mod tidy
go build -o prometheus-service .
./prometheus-service
```

# Metrics & Monitoring

Questa cartella contiene. tutti i servizi e componenti relativi al monitoraggio e alla raccolta di metriche del backend Go.

## 📊 Struttura

```
metrics/
├── README.md                    # Questo file
└── prometheus-service/          # Servizio Prometheus
    ├── main.go                  # Server principale (porta 9090)
    ├── go.mod                   # Dipendenze Go
    ├── go.sum                   # Checksum dipendenze
    ├── Dockerfile               # Containerizzazione
    ├── README.md                # Documentazione specifica
    ├── config/
    │   └── prometheus.yml       # Configurazione Prometheus
    ├── metrics/
    │   └── collectors.go        # Raccoglitori di metriche
    └── middleware/
        └── metrics.go           # Middleware per HTTP metrics
```

## 🚀 Servizi Disponibili

### Prometheus Service (Porto 9090)
- **Scopo**: Raccolta e aggregazione metriche da tutti i microservizi
- **Endpoints**:
  - `/metrics` - Metriche Prometheus in formato standard
  - `/dashboard` - Dashboard semplice per visualizzazione
  - `/health` - Health check del servizio
  - `/stats` - Statistiche in tempo reale

### Metriche Raccolte

#### 📈 HTTP Metrics
- `http_requests_total` - Contatore richieste HTTP per servizio
- `http_request_duration_seconds` - Durata richieste HTTP

#### 🔐 Authentication Metrics
- `auth_attempts_total` - Tentativi di autenticazione (successo/fallimento)

#### 📱 QR Code Metrics
- `qr_scans_total` - Scansioni QR code per evento

#### 👥 System Metrics
- `active_users_total` - Utenti attivi nel sistema
- `system_errors_total` - Errori di sistema per servizio
- `database_connections_active` - Connessioni database attive

## 🔄 Scraping Configuration

Il servizio Prometheus è configurato per raccogliere metriche da:

- **Auth Service** (auth-service:3001/metrics)
- **User Service** (user-service:3002/metrics)
- **Gateway** (gateway:3000/metrics)
- **Prometheus stesso** (localhost:9090/metrics)

## 🐳 Docker Integration

Il servizio è integrato nel `docker-compose.prod.yml`:

```yaml
prometheus-service:
  build: ./metrics/prometheus-service
  ports:
    - "9090:9090"
  networks:
    - microservices-net
```

## 📊 Utilizzo

### Avvio Locale
```bash
cd metrics/prometheus-service
go run main.go
```

### Build Docker
```bash
docker-compose -f docker-compose.prod.yml up prometheus-service
```

### Accesso Dashboard
- **Metriche**: http://localhost:9090/metrics
- **Dashboard**: http://localhost:9090/dashboard
- **Health**: http://localhost:9090/health

## 🔮 Future Extensions

Questa cartella è progettata per ospitare futuri servizi di monitoraggio:
- Grafana per visualizzazioni avanzate
- AlertManager per notifiche
- Jaeger per distributed tracing
- ELK Stack per log analytics

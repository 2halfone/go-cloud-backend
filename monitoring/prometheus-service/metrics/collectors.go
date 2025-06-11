package metrics

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

var (
    // Contatori per richieste HTTP
    HTTPRequestsTotal = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "http_requests_total",
            Help: "Total number of HTTP requests",
        },
        []string{"method", "endpoint", "status_code", "service"},
    )
    
    // Durata delle richieste HTTP
    HTTPRequestDuration = promauto.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "http_request_duration_seconds",
            Help:    "Duration of HTTP requests in seconds",
            Buckets: prometheus.DefBuckets,
        },
        []string{"method", "endpoint", "service"},
    )
    
    // Autenticazioni
    AuthAttemptsTotal = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "auth_attempts_total",
            Help: "Total number of authentication attempts",
        },
        []string{"status", "service"},
    )
    
    // QR scansioni
    QRScansTotal = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "qr_scans_total",
            Help: "Total number of QR code scans",
        },
        []string{"event_id", "status"},
    )
    
    // Utenti attivi
    ActiveUsers = promauto.NewGauge(
        prometheus.GaugeOpts{
            Name: "active_users_total",
            Help: "Number of active users",
        },
    )
    
    // Errori di sistema
    SystemErrorsTotal = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "system_errors_total",
            Help: "Total number of system errors",
        },
        []string{"service", "error_type"},
    )
    
    // Database connections
    DatabaseConnections = promauto.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "database_connections_active",
            Help: "Number of active database connections",
        },
        []string{"service", "database"},
    )
)

func InitPrometheusMetrics() {
    // Registra tutte le metriche personalizzate
    prometheus.MustRegister(HTTPRequestsTotal)
    prometheus.MustRegister(HTTPRequestDuration)
    prometheus.MustRegister(AuthAttemptsTotal)
    prometheus.MustRegister(QRScansTotal)
    prometheus.MustRegister(ActiveUsers)
    prometheus.MustRegister(SystemErrorsTotal)
    prometheus.MustRegister(DatabaseConnections)
}

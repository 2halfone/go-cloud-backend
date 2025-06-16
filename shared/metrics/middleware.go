package metrics

import (
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// HTTP Metrics
	HTTPRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status_code", "service"},
	)

	HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds", 
			Help:    "Duration of HTTP requests in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "endpoint", "service"},
	)

	// Authentication Metrics
	AuthAttemptsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_attempts_total",
			Help: "Total number of authentication attempts",
		},
		[]string{"status", "service"},
	)
	// QR Code Metrics
	QRScansTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "qr_scans_total",
			Help: "Total number of QR code scans",
		},
		[]string{"event_id", "status", "service"},
	)

	QREventsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "qr_events_total",
			Help: "Total number of QR events created",
		},
		[]string{"service"},
	)

	// User Activity Metrics
	ActiveUsers = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "active_users_total",
			Help: "Number of active users",
		},
		[]string{"service"},
	)

	// Database Metrics
	DatabaseConnections = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "database_connections_active",
			Help: "Number of active database connections",
		},
		[]string{"service", "database"},
	)

	// System Error Metrics
	SystemErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "system_errors_total",
			Help: "Total number of system errors",
		},
		[]string{"service", "error_type"},
	)

	// Attendance Events Metrics
	AttendanceEventsActive = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "attendance_events_active",
			Help: "Number of active attendance events",
		},
		[]string{"service"},
	)

	// Gateway-specific metrics
	ProxyRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_proxy_requests_total",
			Help: "Total number of proxy requests through gateway",
		},
		[]string{"target_service", "status_code"},
	)
)

// HTTPMetricsMiddleware collects HTTP request metrics
func HTTPMetricsMiddleware(serviceName string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()

		// Process the request
		err := c.Next()

		duration := time.Since(start)
		statusCode := strconv.Itoa(c.Response().StatusCode())

		// Record metrics
		HTTPRequestsTotal.WithLabelValues(
			c.Method(),
			c.Path(),
			statusCode,
			serviceName,
		).Inc()

		HTTPRequestDuration.WithLabelValues(
			c.Method(),
			c.Path(),
			serviceName,
		).Observe(duration.Seconds())

		return err
	}
}

// RecordAuthAttempt records authentication attempt metrics
func RecordAuthAttempt(success bool, serviceName string) {
	status := "failed"
	if success {
		status = "success"
	}
	AuthAttemptsTotal.WithLabelValues(status, serviceName).Inc()
}

// RecordQRScan records QR code scan metrics
func RecordQRScan(eventID string, success bool, serviceName string) {
	status := "failed"
	if success {
		status = "success"
	}
	QRScansTotal.WithLabelValues(eventID, status, serviceName).Inc()
}

// UpdateActiveUsers updates the active users gauge
func UpdateActiveUsers(count float64, serviceName string) {
	ActiveUsers.WithLabelValues(serviceName).Set(count)
}

// UpdateDatabaseConnections updates database connections gauge
func UpdateDatabaseConnections(count float64, serviceName, database string) {
	DatabaseConnections.WithLabelValues(serviceName, database).Set(count)
}

// RecordSystemError records system error metrics
func RecordSystemError(errorType, serviceName string) {
	SystemErrorsTotal.WithLabelValues(serviceName, errorType).Inc()
}

// RecordProxyRequest records gateway proxy request metrics
func RecordProxyRequest(targetService, statusCode string) {
	ProxyRequestsTotal.WithLabelValues(targetService, statusCode).Inc()
}

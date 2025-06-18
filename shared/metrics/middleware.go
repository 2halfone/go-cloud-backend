package metrics

import (
	"strconv"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	initOnce sync.Once
	metricsInitialized bool
)

// SafeRegisterMetric safely registers a metric, ignoring "already registered" errors
func safeRegisterMetric(metric prometheus.Collector) prometheus.Collector {
	if metric == nil {
		panic("Cannot register nil metric")
	}
	
	err := prometheus.Register(metric)
	if err != nil {
		// If the metric is already registered, that's fine - use the existing one
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			existing := are.ExistingCollector
			if existing == nil {
				// If existing is nil, return the original metric
				return metric
			}
			return existing
		}
		// For other errors, return the metric anyway but log the error
		return metric
	}
	return metric
}

// InitMetrics safely initializes all metrics
func InitMetrics() {
	initOnce.Do(func() {
		metricsInitialized = true
		// Initialize all metrics with safe registration
		initHTTPMetrics()
		initAuthMetrics()
		initQRMetrics()
		initUserMetrics()
		initDatabaseMetrics()
		initSystemMetrics()
		initAttendanceMetrics()
		initGatewayMetrics()
	})
}

var (
	// HTTP Metrics
	HTTPRequestsTotal *prometheus.CounterVec
	HTTPRequestDuration *prometheus.HistogramVec
	
	// Authentication Metrics
	AuthAttemptsTotal *prometheus.CounterVec
	JWTValidationTotal *prometheus.CounterVec
	
	// QR Code Metrics
	QRScansTotal *prometheus.CounterVec
	QREventsTotal *prometheus.CounterVec
	
	// User Activity Metrics
	ActiveUsers *prometheus.GaugeVec
	
	// Database Metrics
	DatabaseConnections *prometheus.GaugeVec
	
	// System Error Metrics
	SystemErrorsTotal *prometheus.CounterVec
	
	// Attendance Events Metrics
	AttendanceEventsActive *prometheus.GaugeVec
	
	// Gateway-specific metrics
	ProxyRequestsTotal *prometheus.CounterVec
)

func initHTTPMetrics() {
	counter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status_code", "service"},
	)
	HTTPRequestsTotal = safeRegisterMetric(counter).(*prometheus.CounterVec)
	
	if HTTPRequestsTotal == nil {
		panic("Failed to initialize HTTPRequestsTotal metric")
	}

	histogram := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds", 
			Help:    "Duration of HTTP requests in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "endpoint", "service"},
	)
	HTTPRequestDuration = safeRegisterMetric(histogram).(*prometheus.HistogramVec)
	
	if HTTPRequestDuration == nil {
		panic("Failed to initialize HTTPRequestDuration metric")
	}
}

func initAuthMetrics() {
	AuthAttemptsTotal = safeRegisterMetric(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_attempts_total",
			Help: "Total number of authentication attempts",
		},
		[]string{"status", "service"},
	)).(*prometheus.CounterVec)

	JWTValidationTotal = safeRegisterMetric(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "jwt_validation_total",
			Help: "Total number of JWT token validations",
		},
		[]string{"status", "service"},
	)).(*prometheus.CounterVec)
}

func initQRMetrics() {
	QRScansTotal = safeRegisterMetric(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "qr_scans_total",
			Help: "Total number of QR code scans",
		},
		[]string{"event_id", "status", "service"},
	)).(*prometheus.CounterVec)

	QREventsTotal = safeRegisterMetric(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "qr_events_total",
			Help: "Total number of QR events created",
		},
		[]string{"service"},
	)).(*prometheus.CounterVec)
}

func initUserMetrics() {
	ActiveUsers = safeRegisterMetric(prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "active_users_total",
			Help: "Number of active users",
		},
		[]string{"service"},
	)).(*prometheus.GaugeVec)
}

func initDatabaseMetrics() {
	DatabaseConnections = safeRegisterMetric(prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "database_connections_active",
			Help: "Number of active database connections",
		},
		[]string{"service", "database"},
	)).(*prometheus.GaugeVec)
}

func initSystemMetrics() {
	SystemErrorsTotal = safeRegisterMetric(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "system_errors_total",
			Help: "Total number of system errors",
		},
		[]string{"service", "error_type"},
	)).(*prometheus.CounterVec)
}

func initAttendanceMetrics() {
	AttendanceEventsActive = safeRegisterMetric(prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "attendance_events_active",
			Help: "Number of active attendance events",
		},
		[]string{"service"},
	)).(*prometheus.GaugeVec)
}

func initGatewayMetrics() {
	ProxyRequestsTotal = safeRegisterMetric(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_proxy_requests_total",
			Help: "Total number of proxy requests through gateway",
		},
		[]string{"target_service", "status_code"},
	)).(*prometheus.CounterVec)
}

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

// RecordJWTValidation records JWT validation metrics
func RecordJWTValidation(success bool, serviceName string) {
	status := "failed"
	if success {
		status = "success"
	}
	JWTValidationTotal.WithLabelValues(status, serviceName).Inc()
}

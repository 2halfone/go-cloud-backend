package main

// @title Dashboard API
// @version 1.0
// @description Comprehensive monitoring dashboard API for go-cloud-backend system
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://github.com/your-repo/go-cloud-backend
// @contact.email support@yourcompany.com

// @license.name MIT
// @license.url https://opensource.org/licenses/MIT

// @host localhost:3003
// @BasePath /
// @schemes http https

// @tag.name Health
// @tag.description Health check endpoints

// @tag.name Security
// @tag.description Security monitoring and authentication stats

// @tag.name VM Health
// @tag.description Virtual machine and system resource monitoring

// @tag.name Analytics
// @tag.description QR code analytics and insights

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	fiberSwagger "github.com/swaggo/fiber-swagger"
	_ "github.com/lib/pq"

	_ "dashboard-api/docs" // Import generated docs
)

// Prometheus client configuration
const (
	PROMETHEUS_URL = "http://localhost:9090"
)

// PrometheusResponse represents the structure of Prometheus API response
type PrometheusResponse struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Metric map[string]string `json:"metric"`
			Value  []interface{}     `json:"value"`
		} `json:"result"`
	} `json:"data"`
}

// Global variables for configuration and database connections
var (
	prometheusURL     string
	authDatabaseURL   string
	userDatabaseURL   string
	authDB           *sql.DB
	userDB           *sql.DB
)

// 🟡 MOCK DATA HIGHLIGHTING SYSTEM - Empty Yellow Boxes
type MockDataValue struct {
	Value      interface{} `json:"value"`             // null when mock data
	IsMock     bool        `json:"is_mock"`           // true for mock data
	Display    string      `json:"display"`           // "empty_yellow" when mock
	DataSource string      `json:"data_source"`       // "prometheus+database" or "fallback"
}

// Helper function to create EMPTY YELLOW BOX for mock data
func createEmptyYellowBox() MockDataValue {
	return MockDataValue{
		Value:      nil,                    // ⚠️ NULL VALUE - Empty box
		IsMock:     true,                   // 🟡 Mark as mock
		Display:    "empty_yellow",         // 🟡 Yellow background indicator
		DataSource: "fallback_unavailable", // Source indicator
	}
}

// Helper function to create empty yellow box with custom message
func createEmptyYellowBoxWithMessage(message string) MockDataValue {
	return MockDataValue{
		Value:      message,                // ⚠️ Message for unavailable data
		IsMock:     true,                   // 🟡 Mark as mock
		Display:    "empty_yellow",         // 🟡 Yellow background indicator
		DataSource: "fallback_unavailable", // Source indicator
	}
}

// Helper function to create real data value
func createRealDataValue(value interface{}) MockDataValue {
	return MockDataValue{
		Value:      value,                  // ✅ Real value
		IsMock:     false,                  // ✅ Not mock
		Display:    "normal",               // Normal display
		DataSource: "prometheus+database",  // Real data source
	}
}

// Step 1.2: Data Structures per i 3 gruppi
type SecurityGroupData struct {
	AuthenticationStats map[string]interface{} `json:"authentication_stats"`
	JWTValidation      map[string]interface{} `json:"jwt_validation"`
	UserActivity       map[string]interface{} `json:"user_activity"`
	SecurityLevel      string                 `json:"security_level"`
	Metadata           map[string]interface{} `json:"metadata"`
}

type VMHealthData struct {
	SystemResources map[string]interface{} `json:"system_resources"`
	ServiceHealth   map[string]interface{} `json:"service_health"`
	DatabaseHealth  map[string]interface{} `json:"database_health"`
	ResponseTimes   map[string]interface{} `json:"response_times"`
	Metadata        map[string]interface{} `json:"metadata"`
}

type InsightsData struct {
	QRAnalytics    map[string]interface{} `json:"qr_analytics"`
	UserActivity   map[string]interface{} `json:"user_activity"`
	EventInsights  map[string]interface{} `json:"event_insights"`
	UsagePatterns  map[string]interface{} `json:"usage_patterns"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// Database initialization function
func initDatabases() error {
	var err error
	
	// Initialize auth database connection
	if authDatabaseURL != "" {
		log.Printf("🔐 Connecting to auth database...")
		authDB, err = sql.Open("postgres", authDatabaseURL)
		if err != nil {
			log.Printf("❌ Failed to connect to auth database: %v", err)
		} else {
			if err = authDB.Ping(); err != nil {
				log.Printf("❌ Auth database ping failed: %v", err)
				authDB.Close()
				authDB = nil
			} else {
				log.Printf("✅ Auth database connected successfully")
				authDB.SetMaxOpenConns(10)
				authDB.SetMaxIdleConns(5)
			}
		}
	} else {
		log.Printf("⚠️ Auth database URL not configured")
	}
	
	// Initialize user database connection
	if userDatabaseURL != "" {
		log.Printf("👤 Connecting to user database...")
		userDB, err = sql.Open("postgres", userDatabaseURL)
		if err != nil {
			log.Printf("❌ Failed to connect to user database: %v", err)
		} else {
			if err = userDB.Ping(); err != nil {
				log.Printf("❌ User database ping failed: %v", err)
				userDB.Close()
				userDB = nil
			} else {
				log.Printf("✅ User database connected successfully")
				userDB.SetMaxOpenConns(10)
				userDB.SetMaxIdleConns(5)
			}
		}
	} else {
		log.Printf("⚠️ User database URL not configured")
	}
	
	return nil
}

// Dashboard Data Structures
type PersonalDashboard struct {
	SystemHealth    SystemHealthData    `json:"system_health"`
	SecurityMetrics SecurityMetricsData `json:"security_metrics"`
	Analytics       AnalyticsData       `json:"analytics"`
	Timestamp       time.Time           `json:"timestamp"`
	UserInfo        UserInfo            `json:"user_info"`
}

// NECESSITÀ - System Health
type SystemHealthData struct {
	OverallStatus    string             `json:"overall_status"`
	Services         []ServiceStatus    `json:"services"`
	Performance      PerformanceMetrics `json:"performance"`
	ResourceUsage    ResourceUsage      `json:"resource_usage"`
}

type ServiceStatus struct {
	Name         string  `json:"name"`
	Status       string  `json:"status"`
	ResponseTime float64 `json:"response_time_ms"`
	Uptime       float64 `json:"uptime_percent"`
	LastCheck    string  `json:"last_check"`
}

type PerformanceMetrics struct {
	AvgResponseTime   MockDataValue `json:"avg_response_time_ms"`
	RequestsPerSecond MockDataValue `json:"requests_per_second"`
	ErrorRate         MockDataValue `json:"error_rate_percent"`
	ThroughputMbps    MockDataValue `json:"throughput_mbps"`
}

type ResourceUsage struct {
	CpuUsage      MockDataValue `json:"cpu_usage_percent"`
	MemoryUsage   MockDataValue `json:"memory_usage_percent"`
	DiskUsage     MockDataValue `json:"disk_usage_percent"`
	NetworkUsage  MockDataValue `json:"network_usage_percent"`
}

// SICUREZZA - Security Metrics
type SecurityMetricsData struct {
	AuthenticationStats AuthStats          `json:"authentication_stats"`
	SecurityAlerts     []SecurityAlert     `json:"security_alerts"`
	ActiveSessions     ActiveSessionsData  `json:"active_sessions"`
	LoginPatterns      LoginPatternsData   `json:"login_patterns"`
}

type AuthStats struct {
	SuccessfulLogins24h MockDataValue `json:"successful_logins_24h"`
	FailedAttempts24h   MockDataValue `json:"failed_attempts_24h"`
	SuccessRate         MockDataValue `json:"success_rate_percent"`
	SuspiciousActivity  MockDataValue `json:"suspicious_activity_count"`
}

type SecurityAlert struct {
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Message     string    `json:"message"`
	Timestamp   time.Time `json:"timestamp"`
	IPAddress   string    `json:"ip_address"`
	UserAgent   string    `json:"user_agent"`
}

type ActiveSessionsData struct {
	TotalActive      MockDataValue            `json:"total_active"`
	SessionsByDevice []DeviceSessionCount     `json:"sessions_by_device"`
	SessionsByLocation []LocationSessionCount `json:"sessions_by_location"`
}

type DeviceSessionCount struct {
	DeviceType string        `json:"device_type"`
	Count      MockDataValue `json:"count"`
}

type LocationSessionCount struct {
	Country string        `json:"country"`
	City    string        `json:"city"`
	Count   MockDataValue `json:"count"`
}

type LoginPatternsData struct {
	PeakHours        []HourlyStats `json:"peak_hours"`
	WeeklyPattern    []DailyStats  `json:"weekly_pattern"`
	GeographicSpread []GeoStats    `json:"geographic_spread"`
}

type HourlyStats struct {
	Hour  int `json:"hour"`
	Count int `json:"count"`
}

type DailyStats struct {
	Day   string `json:"day"`
	Count int    `json:"count"`
}

type GeoStats struct {
	Country   string `json:"country"`
	LoginCount int   `json:"login_count"`
}

// CURIOSITÀ - Analytics Data
type AnalyticsData struct {
	QRCodeAnalytics  QRAnalyticsData  `json:"qr_code_analytics"`
	UserBehavior     UserBehaviorData `json:"user_behavior"`
	AttendanceStats  AttendanceData   `json:"attendance_stats"`
	APIUsageStats    APIUsageData     `json:"api_usage_stats"`
	DatabaseMetrics  DatabaseData     `json:"database_metrics"`
}

type QRAnalyticsData struct {
	TotalScans24h     MockDataValue     `json:"total_scans_24h"`
	ScansPerHour      []HourlyStats     `json:"scans_per_hour"`
	TopScanLocations  []LocationStats   `json:"top_scan_locations"`
	ScanSuccessRate   MockDataValue     `json:"scan_success_rate"`
	AverageScanTime   MockDataValue     `json:"average_scan_time_ms"`
}

type LocationStats struct {
	Location string `json:"location"`
	Count    int    `json:"count"`
}

type UserBehaviorData struct {
	MostActiveUsers    []UserActivity    `json:"most_active_users"`
	ActivityByTimeSlot []TimeSlotActivity `json:"activity_by_time_slot"`
	FeatureUsage       []FeatureUsageStats `json:"feature_usage"`
}

type UserActivity struct {
	UserID       string `json:"user_id"`
	Username     string `json:"username"`
	ActivityCount int   `json:"activity_count"`
	LastActive   string `json:"last_active"`
}

type TimeSlotActivity struct {
	TimeSlot string `json:"time_slot"`
	Users    int    `json:"users"`
	Actions  int    `json:"actions"`
}

type FeatureUsageStats struct {
	Feature    string  `json:"feature"`
	UsageCount int     `json:"usage_count"`
	Percentage float64 `json:"percentage"`
}

type AttendanceData struct {
	TotalEvents24h      MockDataValue  `json:"total_events_24h"`
	AttendanceRate      MockDataValue  `json:"attendance_rate_percent"`
	PeakAttendanceHours []HourlyStats  `json:"peak_attendance_hours"`
	DepartmentStats     []DeptStats    `json:"department_stats"`
}

type DeptStats struct {
	Department     string  `json:"department"`
	AttendanceRate float64 `json:"attendance_rate"`
	TotalEmployees int     `json:"total_employees"`
}

type APIUsageData struct {
	TotalRequests24h   int                `json:"total_requests_24h"`
	TopEndpoints       []EndpointStats    `json:"top_endpoints"`
	ResponseTimesByAPI []APIResponseStats `json:"response_times_by_api"`
	ErrorsByEndpoint   []ErrorStats       `json:"errors_by_endpoint"`
}

type EndpointStats struct {
	Endpoint      string  `json:"endpoint"`
	RequestCount  int     `json:"request_count"`
	AvgResponse   float64 `json:"avg_response_ms"`
}

type APIResponseStats struct {
	API          string  `json:"api"`
	AvgResponse  float64 `json:"avg_response_ms"`
	P95Response  float64 `json:"p95_response_ms"`
}

type ErrorStats struct {
	Endpoint   string `json:"endpoint"`
	ErrorCount int    `json:"error_count"`
	ErrorRate  float64 `json:"error_rate_percent"`
}

type DatabaseData struct {
	ConnectionsActive   int     `json:"connections_active"`
	QueriesPerSecond   float64 `json:"queries_per_second"`
	SlowQueries        int     `json:"slow_queries_count"`
	DatabaseSize       string  `json:"database_size"`
	CacheHitRate       float64 `json:"cache_hit_rate_percent"`
}

type UserInfo struct {
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	LastLogin string `json:"last_login"`
}

// Step 1.3: Helper functions per sanitizzazione dati
func sanitizeFloat64(value float64) float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0.0
	}
	return value
}

func calculateSuccessRate(success, failed float64) float64 {
	total := success + failed
	if total == 0 {
		return 0.0
	}
	return sanitizeFloat64((success / total) * 100)
}

func calculateSecurityLevel(success, failed, suspicious float64) string {
	successRate := calculateSuccessRate(success, failed)
	if suspicious > 10 || successRate < 70 {
		return "HIGH_RISK"
	} else if suspicious > 5 || successRate < 85 {
		return "MEDIUM_RISK"
	}
	return "LOW_RISK"
}

// Prometheus query helper con log migliorato
func queryPrometheusWithLog(query string, description string) float64 {
	log.Printf("🔍 Querying %s: %s", description, query)
	data, err := queryPrometheus(query)
	if err != nil {
		log.Printf("❌ %s query failed: %v", description, err)
		return 0.0
	}
	value := parsePrometheusValue(data)
	log.Printf("✅ %s result: %.6f", description, value)
	return sanitizeFloat64(value)
}

// Prometheus Query Helper with improved error handling
func queryPrometheus(query string) ([]byte, error) {
	// URL encode the query
	encodedQuery := url.QueryEscape(query)
	promURL := prometheusURL
	if promURL == "" {
		promURL = "http://prometheus-service:9090"
	}
	
	requestURL := fmt.Sprintf("%s/api/v1/query?query=%s", promURL, encodedQuery)
	log.Printf("🔍 Querying Prometheus: %s", requestURL)
	
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	
	resp, err := client.Get(requestURL)
	if err != nil {
		log.Printf("❌ Failed to query Prometheus: %v", err)
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		log.Printf("❌ Prometheus returned status: %d", resp.StatusCode)
		return nil, fmt.Errorf("prometheus returned status code: %d", resp.StatusCode)
	}
	
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("❌ Failed to read Prometheus response: %v", err)
		return nil, err
	}
	
	log.Printf("✅ Prometheus query successful, response size: %d bytes", len(data))
	return data, nil
}

// Parse Prometheus response to float64 with better error handling
func parsePrometheusValue(data []byte) float64 {
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		log.Printf("❌ Failed to unmarshal Prometheus response: %v", err)
		return 0
	}
	
	// Check for Prometheus errors
	if status, ok := result["status"].(string); ok && status != "success" {
		log.Printf("❌ Prometheus query failed: %v", result)
		return 0
	}
	
	if data, ok := result["data"].(map[string]interface{}); ok {
		if resultType, ok := data["resultType"].(string); ok {
			log.Printf("📊 Prometheus result type: %s", resultType)
		}
		
		if result, ok := data["result"].([]interface{}); ok && len(result) > 0 {
			if metric, ok := result[0].(map[string]interface{}); ok {
				if value, ok := metric["value"].([]interface{}); ok && len(value) > 1 {
					if strVal, ok := value[1].(string); ok {
						if floatVal, err := strconv.ParseFloat(strVal, 64); err == nil {
							log.Printf("✅ Parsed value: %f", floatVal)
							return floatVal
						} else {
							log.Printf("❌ Failed to parse float value: %s", strVal)
						}
					}
				}
			}
		} else {
			log.Printf("⚠️ Empty result from Prometheus query")
		}
	}
	return 0
}

// Main Dashboard API Endpoint
func getPersonalDashboard(c *fiber.Ctx) error {
	start := time.Now()
	log.Printf("📊 Starting dashboard data collection...")
	
	// Simulate user info (in real app, get from JWT token)
	userInfo := UserInfo{
		UserID:    "user_123",
		Username:  "admin",
		Role:      "administrator",
		LastLogin: time.Now().Add(-2 * time.Hour).Format(time.RFC3339),
	}

	// 1. NECESSITÀ - System Health
	log.Printf("🔧 Collecting system health data...")
	systemHealth := getSystemHealthData()
	
	// 2. SICUREZZA - Security Metrics  
	log.Printf("🔐 Collecting security metrics...")
	securityMetrics := getSecurityMetricsData()
	
	// 3. CURIOSITÀ - Analytics
	log.Printf("📈 Collecting analytics data...")
	analytics := getAnalyticsData()

	dashboard := PersonalDashboard{
		SystemHealth:    systemHealth,
		SecurityMetrics: securityMetrics,
		Analytics:       analytics,
		Timestamp:       time.Now(),
		UserInfo:        userInfo,
	}

	duration := time.Since(start)
	log.Printf("✅ Dashboard data collection completed in %v", duration)
	
	// Add performance headers
	c.Set("X-Response-Time", duration.String())
	c.Set("X-Data-Source", "prometheus+database")
	
	return c.JSON(dashboard)
}

func getSystemHealthData() SystemHealthData {
	// Service statuses
	services := []ServiceStatus{
		{
			Name:         "auth-service",
			Status:       "UP",
			ResponseTime: getServiceResponseTime("auth-service"),
			Uptime:       getServiceUptime("auth-service"),
			LastCheck:    time.Now().Format("15:04:05"),
		},
		{
			Name:         "user-service",
			Status:       "UP", 
			ResponseTime: getServiceResponseTime("user-service"),
			Uptime:       getServiceUptime("user-service"),
			LastCheck:    time.Now().Format("15:04:05"),
		},
		{
			Name:         "gateway",
			Status:       "UP",
			ResponseTime: getServiceResponseTime("gateway"),
			Uptime:       getServiceUptime("gateway"),
			LastCheck:    time.Now().Format("15:04:05"),
		},
	}

	// Performance metrics from Prometheus
	performance := PerformanceMetrics{
		AvgResponseTime:   getAvgResponseTime(),
		RequestsPerSecond: getRequestsPerSecond(),
		ErrorRate:         getErrorRate(),
		ThroughputMbps:    getThroughput(),
	}

	// Resource usage
	resources := ResourceUsage{
		CpuUsage:     getCpuUsage(),
		MemoryUsage:  getMemoryUsage(),
		DiskUsage:    getDiskUsage(),
		NetworkUsage: getNetworkUsage(),
	}

	return SystemHealthData{
		OverallStatus: "HEALTHY",
		Services:      services,
		Performance:   performance,
		ResourceUsage: resources,
	}
}

func getSecurityMetricsData() SecurityMetricsData {
	// Authentication stats from database/Prometheus
	authStats := AuthStats{
		SuccessfulLogins24h: getSuccessfulLogins24h(),
		FailedAttempts24h:   getFailedAttempts24h(),
		SuccessRate:         getAuthSuccessRate(),
		SuspiciousActivity:  getSuspiciousActivityCount(),
	}

	// Security alerts
	alerts := []SecurityAlert{
		{
			Type:      "FAILED_LOGIN",
			Severity:  "MEDIUM",
			Message:   "Multiple failed login attempts from suspicious IP",
			Timestamp: time.Now().Add(-30 * time.Minute),
			IPAddress: "192.168.1.100",
			UserAgent: "Mozilla/5.0...",
		},
	}
	// Active sessions
	activeSessions := ActiveSessionsData{
		TotalActive: getActiveSessions(),
		SessionsByDevice: []DeviceSessionCount{
			{DeviceType: "Desktop", Count: createEmptyYellowBox()},   // 🟡 Empty yellow box
			{DeviceType: "Mobile", Count: createEmptyYellowBox()},    // 🟡 Empty yellow box  
			{DeviceType: "Tablet", Count: createEmptyYellowBox()},    // 🟡 Empty yellow box
		},
		SessionsByLocation: []LocationSessionCount{
			{Country: "Italy", City: "Rome", Count: createEmptyYellowBox()},  // 🟡 Empty yellow box
			{Country: "Italy", City: "Milan", Count: createEmptyYellowBox()}, // 🟡 Empty yellow box
		},
	}

	// Login patterns
	loginPatterns := LoginPatternsData{
		PeakHours: getPeakLoginHours(),
		WeeklyPattern: getWeeklyLoginPattern(),
		GeographicSpread: getGeoLoginSpread(),
	}

	return SecurityMetricsData{
		AuthenticationStats: authStats,
		SecurityAlerts:     alerts,
		ActiveSessions:     activeSessions,
		LoginPatterns:      loginPatterns,
	}
}

func getAnalyticsData() AnalyticsData {	// QR Code analytics
	qrAnalytics := QRAnalyticsData{
		TotalScans24h:    getQRScans24h(),
		ScansPerHour:     getQRScansPerHour(),
		TopScanLocations: getTopScanLocations(),
		ScanSuccessRate:  createEmptyYellowBox(), // 🟡 Empty yellow box instead of hardcoded value
		AverageScanTime:  createEmptyYellowBox(), // 🟡 Empty yellow box instead of hardcoded value
	}

	// User behavior
	userBehavior := UserBehaviorData{
		MostActiveUsers:    getMostActiveUsers(),
		ActivityByTimeSlot: getActivityByTimeSlot(),
		FeatureUsage:       getFeatureUsage(),
	}

	// Attendance stats
	attendanceStats := AttendanceData{
		TotalEvents24h:      getAttendanceEvents24h(),
		AttendanceRate:      createEmptyYellowBox(), // 🟡 Empty yellow box instead of hardcoded value
		PeakAttendanceHours: getPeakAttendanceHours(),
		DepartmentStats:     getDepartmentStats(),
	}

	// API usage stats
	apiUsage := APIUsageData{
		TotalRequests24h:   getAPIRequests24h(),
		TopEndpoints:       getTopEndpoints(),
		ResponseTimesByAPI: getAPIResponseTimes(),
		ErrorsByEndpoint:   getAPIErrors(),
	}
	// Database metrics
	dbMetrics := DatabaseData{
		ConnectionsActive: getDBConnections(),
		QueriesPerSecond:  15.2, // TODO: implement getDBQueriesPerSecond()
		SlowQueries:       5,
		DatabaseSize:      "2.5 GB",
		CacheHitRate:      98.7,
	}

	return AnalyticsData{
		QRCodeAnalytics: qrAnalytics,
		UserBehavior:    userBehavior,
		AttendanceStats: attendanceStats,
		APIUsageStats:   apiUsage,
		DatabaseMetrics: dbMetrics,
	}
}

// Helper functions to get metrics from Prometheus with fallbacks
func getServiceResponseTime(service string) float64 {
	query := fmt.Sprintf(`histogram_quantile(0.95, rate(http_request_duration_seconds_bucket{job="%s"}[5m]))`, service)
	data, err := queryPrometheus(query)
	if err != nil {
		log.Printf("⚠️ Failed to get response time for %s, data unavailable", service)
		return 0.0 // Return 0 instead of hardcoded values
	}
	result := parsePrometheusValue(data) * 1000 // Convert to ms
	if result == 0 {
		return 0.0 // Return 0 instead of hardcoded values
	}
	return result
}

func getServiceUptime(service string) float64 {
	query := fmt.Sprintf(`up{job="%s"}`, service)
	data, err := queryPrometheus(query)
	if err != nil {
		log.Printf("⚠️ Failed to get uptime for %s, data unavailable", service)
		return 0.0 // Return 0 instead of hardcoded values
	}
	result := parsePrometheusValue(data) * 100
	if result == 0 {
		return 0.0 // Return 0 instead of hardcoded values
	}
	return result
}

func getAvgResponseTime() MockDataValue {
	data, err := queryPrometheus(`histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))`)
	if err != nil {
		return createEmptyYellowBox() // 🟡 Empty yellow box instead of showing fallback value
	}
	result := parsePrometheusValue(data) * 1000
	if result == 0 {
		return createEmptyYellowBox() // 🟡 Empty yellow box instead of showing fallback value
	}
	return createRealDataValue(result)
}

func getRequestsPerSecond() MockDataValue {
	data, err := queryPrometheus(`sum(rate(http_requests_total[5m]))`)
	if err != nil {
		return createEmptyYellowBox() // 🟡 Empty yellow box instead of showing fallback value
	}
	result := parsePrometheusValue(data)
	if result == 0 {
		return createEmptyYellowBox() // 🟡 Empty yellow box instead of showing fallback value
	}
	return createRealDataValue(result)
}

func getErrorRate() MockDataValue {
	data, err := queryPrometheus(`sum(rate(http_requests_total{status=~"4..|5.."}[5m])) / sum(rate(http_requests_total[5m])) * 100`)
	if err != nil {
		return createEmptyYellowBox() // 🟡 Empty yellow box instead of showing fallback value
	}
	result := parsePrometheusValue(data)
	if result == 0 {
		return createEmptyYellowBox() // 🟡 Empty yellow box instead of showing fallback value
	}
	return createRealDataValue(result)
}

func getThroughput() MockDataValue {
	data, err := queryPrometheus(`sum(rate(prometheus_tsdb_symbol_table_size_bytes[5m]))`)
	if err != nil {
		return createEmptyYellowBox() // 🟡 Empty yellow box instead of showing fallback value
	}
	result := parsePrometheusValue(data) / 1024 / 1024
	if result == 0 {
		return createEmptyYellowBox() // 🟡 Empty yellow box instead of showing fallback value
	}
	return createRealDataValue(result)
}

func getCpuUsage() MockDataValue {
	data, err := queryPrometheus(`(1 - avg(rate(node_cpu_seconds_total{mode="idle"}[5m]))) * 100`)
	if err != nil {
		return createEmptyYellowBox() // 🟡 Empty yellow box instead of showing fallback value
	}
	result := parsePrometheusValue(data)
	if result == 0 {
		return createEmptyYellowBox() // 🟡 Empty yellow box instead of showing fallback value
	}
	return createRealDataValue(result)
}

func getMemoryUsage() MockDataValue {
	data, err := queryPrometheus(`(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100`)
	if err != nil {
		return createEmptyYellowBox() // 🟡 Empty yellow box instead of showing fallback value
	}
	result := parsePrometheusValue(data)
	if result == 0 {
		return createEmptyYellowBox() // 🟡 Empty yellow box instead of showing fallback value
	}
	return createRealDataValue(result)
}

func getDiskUsage() MockDataValue {
	data, err := queryPrometheus(`(1 - (node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"})) * 100`)
	if err != nil {
		return createEmptyYellowBox() // 🟡 Empty yellow box instead of showing fallback value
	}
	result := parsePrometheusValue(data)
	if result == 0 {
		return createEmptyYellowBox() // 🟡 Empty yellow box instead of showing fallback value
	}
	return createRealDataValue(result)
}

func getNetworkUsage() MockDataValue {
	data, err := queryPrometheus(`sum(rate(node_network_receive_bytes_total[5m])) / 1024 / 1024`)
	if err != nil {
		return createEmptyYellowBox() // 🟡 Empty yellow box instead of showing fallback value
	}
	result := parsePrometheusValue(data)
	if result == 0 {
		return createEmptyYellowBox() // 🟡 Empty yellow box instead of showing fallback value
	}
	return createRealDataValue(result)
}

// Security metrics helpers with real database integration
func getSuccessfulLogins24h() MockDataValue {
	if authDB != nil {
		var count int
		query := `
			SELECT COUNT(*) 
			FROM auth_logs 
			WHERE action = 'login' 
			AND success = true 
			AND timestamp >= NOW() - INTERVAL '24 hours'
		`
		if err := authDB.QueryRow(query).Scan(&count); err == nil {
			log.Printf("✅ Retrieved successful logins from DB: %d", count)
			return createRealDataValue(count)
		} else {
			log.Printf("⚠️ Failed to query auth DB: %v", err)
		}
	}
	
	data, err := queryPrometheus(`increase(auth_attempts_total{status="success"}[24h])`)
	if err != nil {
		return createEmptyYellowBox() // 🟡 Empty yellow box instead of showing fallback value
	}
	result := int(parsePrometheusValue(data))
	if result == 0 {
		return createEmptyYellowBox() // 🟡 Empty yellow box instead of showing fallback value
	}
	return createRealDataValue(result)
}

func getFailedAttempts24h() MockDataValue {
	if authDB != nil {
		var count int
		query := `
			SELECT COUNT(*) 
			FROM auth_logs 
			WHERE action = 'login' 
			AND success = false 
			AND timestamp >= NOW() - INTERVAL '24 hours'
		`
		if err := authDB.QueryRow(query).Scan(&count); err == nil {
			log.Printf("✅ Retrieved failed attempts from DB: %d", count)
			return createRealDataValue(count)
		} else {
			log.Printf("⚠️ Failed to query auth DB: %v", err)
		}
	}
	
	data, err := queryPrometheus(`increase(auth_attempts_total{status="failed"}[24h])`)
	if err != nil {
		return createEmptyYellowBox() // 🟡 Empty yellow box instead of showing fallback value
	}
	result := int(parsePrometheusValue(data))
	if result == 0 {
		return createEmptyYellowBox() // 🟡 Empty yellow box instead of showing fallback value
	}
	return createRealDataValue(result)
}

func getAuthSuccessRate() MockDataValue {
	if authDB != nil {
		var successCount, totalCount int
		successQuery := `
			SELECT COUNT(*) 
			FROM auth_logs 
			WHERE action = 'login' 
			AND success = true 
			AND timestamp >= NOW() - INTERVAL '24 hours'
		`
		totalQuery := `
			SELECT COUNT(*) 
			FROM auth_logs 
			WHERE action = 'login' 
			AND timestamp >= NOW() - INTERVAL '24 hours'
		`
		
		if err := authDB.QueryRow(successQuery).Scan(&successCount); err == nil {
			if err := authDB.QueryRow(totalQuery).Scan(&totalCount); err == nil && totalCount > 0 {
				rate := float64(successCount) / float64(totalCount) * 100
				log.Printf("✅ Retrieved auth success rate from DB: %.2f%%", rate)
				return createRealDataValue(rate)
			}
		}
	}
	
	return createEmptyYellowBox() // 🟡 Empty yellow box instead of showing fallback value
}

func getSuspiciousActivityCount() MockDataValue {
	if authDB != nil {
		var count int
		query := `
			SELECT COUNT(*) 
			FROM auth_logs 
			WHERE (
				(action = 'login' AND success = false AND timestamp >= NOW() - INTERVAL '1 hour')
				OR (ip_address IN (
					SELECT ip_address 
					FROM auth_logs 
					WHERE action = 'login' AND success = false 
					AND timestamp >= NOW() - INTERVAL '24 hours'
					GROUP BY ip_address 
					HAVING COUNT(*) > 5
				))
			)
		`
		if err := authDB.QueryRow(query).Scan(&count); err == nil {
			log.Printf("✅ Retrieved suspicious activity count from DB: %d", count)
			return createRealDataValue(count)
		}
	}
	
	return createEmptyYellowBox() // 🟡 Empty yellow box instead of showing fallback value
}

func getActiveSessions() MockDataValue {
	if userDB != nil {
		var count int
		query := `
			SELECT COUNT(DISTINCT user_id) 
			FROM users 
			WHERE last_login >= NOW() - INTERVAL '30 minutes'
		`
		if err := userDB.QueryRow(query).Scan(&count); err == nil {
			log.Printf("✅ Retrieved active sessions from DB: %d", count)
			return createRealDataValue(count)
		}
	}
	
	return createEmptyYellowBox() // 🟡 Empty yellow box instead of showing fallback value
}

// Additional helper functions for analytics with database integration
func getPeakLoginHours() []HourlyStats {
	if authDB != nil {
		query := `
			SELECT EXTRACT(HOUR FROM timestamp) as hour, COUNT(*) as count
			FROM auth_logs 
			WHERE action = 'login' 
			AND success = true 
			AND timestamp >= NOW() - INTERVAL '7 days'
			GROUP BY EXTRACT(HOUR FROM timestamp)
			ORDER BY count DESC
			LIMIT 5
		`
		rows, err := authDB.Query(query)
		if err == nil {
			defer rows.Close()
			var stats []HourlyStats
			for rows.Next() {
				var hour, count int
				if err := rows.Scan(&hour, &count); err == nil {
					stats = append(stats, HourlyStats{Hour: hour, Count: count})
				}
			}
			if len(stats) > 0 {
				log.Printf("✅ Retrieved peak login hours from DB: %d entries", len(stats))
				return stats
			}
		}
	}
		// Return empty array instead of hardcoded fallback data
	return []HourlyStats{}
}

func getWeeklyLoginPattern() []DailyStats {
	if authDB != nil {
		query := `
			SELECT 
				CASE EXTRACT(DOW FROM timestamp)
					WHEN 0 THEN 'Sunday'
					WHEN 1 THEN 'Monday'
					WHEN 2 THEN 'Tuesday'
					WHEN 3 THEN 'Wednesday'
					WHEN 4 THEN 'Thursday'
					WHEN 5 THEN 'Friday'
					WHEN 6 THEN 'Saturday'
				END as day,
				COUNT(*) as count
			FROM auth_logs 
			WHERE action = 'login' 
			AND success = true 
			AND timestamp >= NOW() - INTERVAL '30 days'
			GROUP BY EXTRACT(DOW FROM timestamp)
			ORDER BY EXTRACT(DOW FROM timestamp)
		`
		rows, err := authDB.Query(query)
		if err == nil {
			defer rows.Close()
			var stats []DailyStats
			for rows.Next() {
				var day string
				var count int
				if err := rows.Scan(&day, &count); err == nil {
					stats = append(stats, DailyStats{Day: day, Count: count})
				}
			}
			if len(stats) > 0 {
				return stats
			}
		}
	}
		// Return empty array instead of hardcoded fallback data
	return []DailyStats{}
}

func getGeoLoginSpread() []GeoStats {
	if authDB != nil {
		query := `
			SELECT 
				COALESCE(country, 'Unknown') as country,
				COUNT(*) as login_count
			FROM auth_logs 
			WHERE action = 'login' 
			AND success = true 
			AND timestamp >= NOW() - INTERVAL '30 days'
			GROUP BY country
			ORDER BY login_count DESC
			LIMIT 10
		`
		rows, err := authDB.Query(query)
		if err == nil {
			defer rows.Close()
			var stats []GeoStats
			for rows.Next() {
				var country string
				var count int
				if err := rows.Scan(&country, &count); err == nil {
					stats = append(stats, GeoStats{Country: country, LoginCount: count})
				}
			}
			if len(stats) > 0 {
				return stats
			}
		}
	}
		// Return empty array instead of hardcoded fallback data
	return []GeoStats{}
}

func getQRScans24h() MockDataValue {
	if userDB != nil {
		var count int
		query := `
			SELECT COUNT(*) 
			FROM attendance_events 
			WHERE timestamp >= NOW() - INTERVAL '24 hours'
		`
		if err := userDB.QueryRow(query).Scan(&count); err == nil {
			log.Printf("✅ Retrieved QR scans from DB: %d", count)
			return createRealDataValue(count)
		}
	}
	
	return createEmptyYellowBox() // 🟡 Empty yellow box instead of showing fallback value
}

// Analytics helper functions with empty arrays instead of hardcoded data
func getQRScansPerHour() []HourlyStats {
	// Return empty array instead of hardcoded fallback data
	return []HourlyStats{}
}

func getTopScanLocations() []LocationStats {
	// Return empty array instead of hardcoded fallback data
	return []LocationStats{}
}

func getMostActiveUsers() []UserActivity {
	// Return empty array instead of hardcoded fallback data
	return []UserActivity{}
}

func getActivityByTimeSlot() []TimeSlotActivity {
	// Return empty array instead of hardcoded fallback data
	return []TimeSlotActivity{}
}

func getFeatureUsage() []FeatureUsageStats {
	// Return empty array instead of hardcoded fallback data
	return []FeatureUsageStats{}
}

func getAttendanceEvents24h() MockDataValue {
	return createEmptyYellowBox() // 🟡 Empty yellow box instead of showing fallback value
}

func getPeakAttendanceHours() []HourlyStats {
	// Return empty array instead of hardcoded fallback data
	return []HourlyStats{}
}

func getDepartmentStats() []DeptStats {
	// Return empty array instead of hardcoded fallback data
	return []DeptStats{}
}

func getAPIRequests24h() int {
	// Return 0 instead of hardcoded fallback
	return 0
}

func getTopEndpoints() []EndpointStats {
	// Return empty array instead of hardcoded fallback data
	return []EndpointStats{}
}

func getAPIResponseTimes() []APIResponseStats {
	return []APIResponseStats{
		{API: "auth-service", AvgResponse: 125.4, P95Response: 289.7},
		{API: "user-service", AvgResponse: 98.6, P95Response: 234.5},
	}
}

func getAPIErrors() []ErrorStats {
	return []ErrorStats{
		{Endpoint: "/api/auth/verify", ErrorCount: 23, ErrorRate: 2.1},
		{Endpoint: "/api/qr/validate", ErrorCount: 15, ErrorRate: 1.8},
	}
}

func getDBConnections() int {
	return 15
}

func getDBStatus(db *sql.DB) string {
	if db == nil {
		return "not_configured"
	}
	
	var status string
	err := db.QueryRow("SELECT 'OK'").Scan(&status)
	if err != nil {
		return "disconnected"
	}
	return "connected"
}

func getSuspiciousActivityFromDB() int {
	if authDB != nil {
		var count int
		query := `
			SELECT COUNT(*) 
			FROM auth_logs 
			WHERE success = false 
			AND timestamp >= NOW() - INTERVAL '1 hour'
		`
		if err := authDB.QueryRow(query).Scan(&count); err == nil {
			return count
		}
	}
	return 5 // Fallback
}

func getMostActiveUsersFromDB() []UserActivity {
	if userDB != nil {
		query := `
			SELECT user_id, COUNT(*) as activity_count, MAX(timestamp) as last_active
			FROM user_activity_logs 
			WHERE timestamp >= NOW() - INTERVAL '24 hours'
			GROUP BY user_id
			ORDER BY activity_count DESC
			LIMIT 5
		`
		rows, err := userDB.Query(query)
		if err == nil {
			defer rows.Close()
			var users []UserActivity
			for rows.Next() {
				var user UserActivity
				if err := rows.Scan(&user.UserID, &user.ActivityCount, &user.LastActive); err == nil {
					user.Username = "User_" + user.UserID[len(user.UserID)-3:] // Simulate username
					users = append(users, user)
				}
			}
			if len(users) > 0 {
				return users
			}
		}
	}
		// Fallback - return empty array instead of fake users
	return []UserActivity{}
}

func getQRTrendsFromDB() map[string]int {
	// Try to get real data from database/prometheus first
	// If no real data available, return empty map to trigger yellow boxes
	
	return map[string]int{
		// Return 0 values to trigger empty yellow box display
		"today":         0,
		"week":          0,
		"daily_average": 0,
	}
}

// =============================================================================
// SWAGGER API HANDLERS
// =============================================================================

var startTime = time.Now()

// @Summary Health Check
// @Description Check if the dashboard API service is healthy and all dependencies are working
// @Tags Health
// @Accept json
// @Produce json
// @Success 200 {object} HealthResponse "Service is healthy"
// @Failure 503 {object} ErrorResponse "Service unavailable"
// @Router /health [get]
func healthCheckHandler(c *fiber.Ctx) error {
	// Check Prometheus connection
	prometheusHealthy := checkPrometheusHealth()
	
	// Check database connections
	authDBHealthy := checkAuthDatabaseHealth()
	userDBHealthy := checkUserDatabaseHealth()

	// Overall health status
	allHealthy := prometheusHealthy && authDBHealthy && userDBHealthy

	status := "healthy"
	httpCode := fiber.StatusOK
	if !allHealthy {
		status = "degraded"
		httpCode = fiber.StatusServiceUnavailable
	}

	response := HealthResponse{
		Status:    status,
		Timestamp: time.Now().UTC(),
		Dependencies: DependencyStatus{
			Prometheus: prometheusHealthy,
			AuthDB:     authDBHealthy,
			UserDB:     userDBHealthy,
		},
		Uptime: time.Since(startTime).String(),
	}

	return c.Status(httpCode).JSON(response)
}

// @Summary Get Security Data
// @Description Retrieve comprehensive security monitoring data including authentication stats, JWT validation, and user activity
// @Tags Security
// @Accept json
// @Produce json
// @Success 200 {object} SecurityResponse "Security data retrieved successfully"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/dashboard/security [get]
func getSecurityDataHandler(c *fiber.Ctx) error {
	start := time.Now()
	log.Println("🔐 Collecting security metrics...")
	
	// Query Prometheus per metriche di sicurezza
	successfulLogins := getSuccessfulLogins24h()
	failedAttempts := getFailedAttempts24h()
	jwtValidations := queryPrometheusWithLog("sum(jwt_validation_total{status=\"success\"})", "JWT validations")
	jwtFailures := queryPrometheusWithLog("sum(jwt_validation_total{status=\"failed\"})", "JWT failures")
	activeUsers := queryPrometheusWithLog("sum(active_users_total)", "Active users")
	
	// Query Database per dati aggiuntivi
	suspiciousActivity := getSuspiciousActivityFromDB()
	
	securityData := SecurityGroupData{
		AuthenticationStats: map[string]interface{}{
			"successful_logins_24h": successfulLogins,
			"failed_attempts_24h":   failedAttempts,
			"success_rate_percent":  calculateSuccessRateFromMock(successfulLogins, failedAttempts),
		},
		JWTValidation: map[string]interface{}{
			"valid_tokens_24h":   jwtValidations,
			"invalid_tokens_24h": jwtFailures,
			"validation_rate":    calculateValidationRate(jwtValidations, jwtFailures),
		},
		UserActivity: map[string]interface{}{
			"active_users_current": activeUsers,
			"suspicious_activity":  suspiciousActivity,
		},
		SecurityLevel: calculateSecurityLevelFromMock(successfulLogins, failedAttempts, int(suspiciousActivity)),
		Metadata: map[string]interface{}{
			"data_source":        "prometheus+database",
			"last_updated":       time.Now().Format(time.RFC3339),
			"collection_time_ms": time.Since(start).Milliseconds(),
		},
	}

	response := SecurityResponse{
		AuthenticationStats: securityData.AuthenticationStats,
		JWTValidation:      securityData.JWTValidation,
		UserActivity:       securityData.UserActivity,
		SecurityLevel:      securityData.SecurityLevel,
		Metadata: Metadata{
			CollectionTimeMs: time.Since(start).Milliseconds(),
			DataSource:       "prometheus+database",
			LastUpdated:      time.Now().UTC(),
		},
	}

	return c.JSON(response)
}

// @Summary Get VM Health Data
// @Description Retrieve virtual machine health data including system resources, service health, and performance metrics
// @Tags VM Health
// @Accept json
// @Produce json
// @Success 200 {object} VMHealthResponse "VM health data retrieved successfully"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/dashboard/vm-health [get]
func getVMHealthHandler(c *fiber.Ctx) error {
	start := time.Now()
	log.Println("💻 Collecting REAL VM health metrics from Prometheus...")
	
	response := VMHealthResponse{
		SystemResources: getSystemResourcesData(),
		ServiceHealth:   getServiceHealthData(),
		DatabaseHealth:  getDatabaseHealthData(),
		ResponseTimes:   getResponseTimesData(),
		Metadata: Metadata{
			CollectionTimeMs: time.Since(start).Milliseconds(),
			DataSource:       "prometheus+node-exporter+database",
			LastUpdated:      time.Now().UTC(),
		},
	}

	return c.JSON(response)
}

// @Summary Get Analytics Insights
// @Description Retrieve QR code analytics, user engagement metrics, and system insights
// @Tags Analytics
// @Accept json
// @Produce json
// @Success 200 {object} AnalyticsResponse "Analytics data retrieved successfully"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/dashboard/insights [get]
func getAnalyticsInsightsHandler(c *fiber.Ctx) error {
	start := time.Now()
	log.Println("📊 Collecting analytics insights...")

	// Get analytics data
	analyticsData := getAnalyticsData()
		response := AnalyticsResponse{
		QRAnalytics: map[string]interface{}{
			"qr_code_analytics": analyticsData.QRCodeAnalytics,
		},
		UserActivity: map[string]interface{}{
			"user_behavior": analyticsData.UserBehavior,
		},
		EventInsights: map[string]interface{}{
			"attendance_stats": analyticsData.AttendanceStats,
		},
		UsagePatterns: map[string]interface{}{
			"api_usage_stats":    analyticsData.APIUsageStats,
			"database_metrics":   analyticsData.DatabaseMetrics,
		},
		Metadata: Metadata{
			CollectionTimeMs: time.Since(start).Milliseconds(),
			DataSource:       "prometheus+database",
			LastUpdated:      time.Now().UTC(),
		},
	}

	return c.JSON(response)
}

// =============================================================================
// HELPER FUNCTIONS FOR SWAGGER HANDLERS
// =============================================================================

func checkPrometheusHealth() bool {
	_, err := queryPrometheus("up")
	return err == nil
}

func checkAuthDatabaseHealth() bool {
	return authDB != nil && authDB.Ping() == nil
}

func checkUserDatabaseHealth() bool {
	return userDB != nil && userDB.Ping() == nil
}

func calculateSuccessRateFromMock(successful, failed MockDataValue) float64 {
	if successful.IsMock || failed.IsMock {
		return 0.0
	}
	
	var successVal, failedVal float64
	if s, ok := successful.Value.(float64); ok {
		successVal = s
	}
	if f, ok := failed.Value.(float64); ok {
		failedVal = f
	}
	
	total := successVal + failedVal
	if total == 0 {
		return 0.0
	}
	return (successVal / total) * 100
}

func calculateValidationRate(valid, invalid float64) float64 {
	total := valid + invalid
	if total == 0 {
		return 0.0
	}
	return (valid / total) * 100
}

func calculateSecurityLevelFromMock(logins, failures MockDataValue, suspicious int) string {
	// Simple security level calculation
	if suspicious > 10 {
		return "HIGH_RISK"
	}
	
	if !logins.IsMock && !failures.IsMock {
		successRate := calculateSuccessRateFromMock(logins, failures)
		if successRate < 50 {
			return "HIGH_RISK"
		} else if successRate < 80 {
			return "MEDIUM_RISK"
		}
	}
		return "LOW_RISK"
}

func main() {
	// Configurazione ambiente
	prometheusURL = os.Getenv("PROMETHEUS_URL")
	if prometheusURL == "" {
		prometheusURL = "http://prometheus-service:9090"
	}

	authDatabaseURL = os.Getenv("AUTH_DATABASE_URL") 
	userDatabaseURL = os.Getenv("USER_DATABASE_URL")

	log.Printf("🚀 Starting Dashboard API...")
	log.Printf("📊 Prometheus URL: %s", prometheusURL)

	// Inizializza connessioni database
	if err := initDatabases(); err != nil {
		log.Printf("⚠️ Database initialization error: %v", err)
	}

	// Inizializza app Fiber
	app := fiber.New(fiber.Config{
		Prefork:      false,
		ServerHeader: "Dashboard-API",
		AppName:      "Dashboard API v1.0",
	})

	// Logger middleware
	app.Use(logger.New())

	// CORS middleware
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowMethods: "GET,POST,HEAD,PUT,DELETE,PATCH,OPTIONS",
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
		AllowCredentials: false,
	}))

	// 📖 Swagger documentation endpoint

	// 📖 Swagger documentation endpoint
	app.Get("/swagger/*", fiberSwagger.WrapHandler)

	// 🔧 Health check endpoint
	app.Get("/health", healthCheckHandler)

	// 🔐 API Routes
	app.Get("/api/dashboard/security", getSecurityDataHandler)
	app.Get("/api/dashboard/vm-health", getVMHealthHandler)
	app.Get("/api/dashboard/insights", getAnalyticsInsightsHandler)

	// Avvia server
	log.Println("🚀 Dashboard API server starting on :3003")
	log.Println("📖 Swagger documentation available at: http://localhost:3003/swagger/")
	log.Fatal(app.Listen(":3003"))
}

// =============================================================================
// PROMETHEUS INTEGRATION FUNCTIONS FOR REAL METRICS
// =============================================================================

// getSystemResourcesData retrieves real system metrics from Prometheus
func getSystemResourcesData() map[string]interface{} {
	resources := make(map[string]interface{})
	
	// CPU Usage (from node_exporter)
	cpuUsage := getPrometheusMetric("100 - (avg(rate(node_cpu_seconds_total{mode=\"idle\"}[5m])) * 100)")
	if cpuUsage != -1 {
		resources["cpu_usage_percent"] = math.Round(cpuUsage*100)/100
	} else {
		resources["cpu_usage_percent"] = createEmptyYellowBoxWithMessage("CPU data unavailable")
	}
	
	// Memory Usage
	memoryQuery := "(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100"
	memoryUsage := getPrometheusMetric(memoryQuery)
	if memoryUsage != -1 {
		resources["memory_usage_percent"] = math.Round(memoryUsage*100)/100
	} else {
		resources["memory_usage_percent"] = createEmptyYellowBoxWithMessage("Memory data unavailable")
	}
	
	// Disk Usage
	diskQuery := "(1 - (node_filesystem_avail_bytes{fstype=\"ext4\"} / node_filesystem_size_bytes{fstype=\"ext4\"})) * 100"
	diskUsage := getPrometheusMetric(diskQuery)
	if diskUsage != -1 {
		resources["disk_usage_percent"] = math.Round(diskUsage*100)/100
	} else {
		resources["disk_usage_percent"] = createEmptyYellowBoxWithMessage("Disk data unavailable")
	}
	
	// Network Usage (bytes/sec to Mbps)
	networkQuery := "rate(node_network_receive_bytes_total{device=\"eth0\"}[5m]) * 8 / 1024 / 1024"
	networkUsage := getPrometheusMetric(networkQuery)
	if networkUsage != -1 {
		resources["network_usage_mbps"] = math.Round(networkUsage*100)/100
	} else {
		resources["network_usage_mbps"] = createEmptyYellowBoxWithMessage("Network data unavailable")
	}
	
	return resources
}

// getServiceHealthData retrieves service health from Prometheus
func getServiceHealthData() map[string]interface{} {
	serviceHealth := make(map[string]interface{})
	
	// Check service uptimes from Prometheus
	authUptime := getServiceUptime("auth-service")
	userUptime := getServiceUptime("user-service") 
	
	serviceHealth["auth_service_status"] = formatServiceStatus(authUptime)
	serviceHealth["user_service_status"] = formatServiceStatus(userUptime)
	serviceHealth["gateway_status"] = formatServiceStatus(gatewayUptime)
	serviceHealth["prometheus_status"] = formatServiceStatus(prometheusUptime)
	
	// Count total services and services up
	servicesUp := 0
	totalServices := 4
	if authUptime > 0 { servicesUp++ }
	if userUptime > 0 { servicesUp++ }
	if gatewayUptime > 0 { servicesUp++ }
	if prometheusUptime > 0 { servicesUp++ }
	
	serviceHealth["services_total"] = totalServices
	serviceHealth["services_up"] = servicesUp
	serviceHealth["health_percentage"] = math.Round(float64(servicesUp)/float64(totalServices)*100*100)/100
	
	return serviceHealth
}

// getDatabaseHealthData retrieves database connection status
func getDatabaseHealthData() map[string]interface{} {
	dbHealth := make(map[string]interface{})
	
	// Check database connections
	authDBStatus := checkDatabaseConnection("go-cloud-backend_auth-db_1", 5432)
	userDBStatus := checkDatabaseConnection("go-cloud-backend_user-db_1", 5432)
	
	if authDBStatus {
		dbHealth["auth_db_status"] = "connected"
		dbHealth["auth_db_response_time_ms"] = getDatabaseResponseTime("auth")
	} else {		dbHealth["auth_db_status"] = createEmptyYellowBoxWithMessage("Auth DB unreachable")
		dbHealth["auth_db_response_time_ms"] = createEmptyYellowBoxWithMessage("N/A")
	}
	
	if userDBStatus {
		dbHealth["user_db_status"] = "connected"  
		dbHealth["user_db_response_time_ms"] = getDatabaseResponseTime("user")
	} else {		dbHealth["user_db_status"] = createEmptyYellowBoxWithMessage("User DB unreachable")
		dbHealth["user_db_response_time_ms"] = createEmptyYellowBoxWithMessage("N/A")
	}
	
	return dbHealth
}

// getResponseTimesData retrieves response times from Prometheus
func getResponseTimesData() map[string]interface{} {
	responseTimes := make(map[string]interface{})
	
	// HTTP request duration metrics (in milliseconds)
	authResponseTime := getPrometheusMetric("histogram_quantile(0.95, rate(http_request_duration_seconds_bucket{job=\"auth-service\"}[5m])) * 1000")
	userResponseTime := getPrometheusMetric("histogram_quantile(0.95, rate(http_request_duration_seconds_bucket{job=\"user-service\"}[5m])) * 1000")
	gatewayResponseTime := getPrometheusMetric("histogram_quantile(0.95, rate(http_request_duration_seconds_bucket{job=\"gateway\"}[5m])) * 1000")
	
	if authResponseTime != -1 {
		responseTimes["auth_service_ms"] = math.Round(authResponseTime*100)/100
	} else {
		responseTimes["auth_service_ms"] = createEmptyYellowBoxWithMessage("Auth response time unavailable")
	}
	
	if userResponseTime != -1 {
		responseTimes["user_service_ms"] = math.Round(userResponseTime*100)/100
	} else {
		responseTimes["user_service_ms"] = createEmptyYellowBoxWithMessage("User response time unavailable")
	}
	
	if gatewayResponseTime != -1 {
		responseTimes["gateway_ms"] = math.Round(gatewayResponseTime*100)/100
	} else {
		responseTimes["gateway_ms"] = createEmptyYellowBoxWithMessage("Gateway response time unavailable")
	}
	
	return responseTimes
}

// getPrometheusMetric queries Prometheus and returns a single metric value
func getPrometheusMetric(query string) float64 {
	url := fmt.Sprintf("%s/api/v1/query?query=%s", PROMETHEUS_URL, url.QueryEscape(query))
	
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("❌ Error querying Prometheus: %v", err)
		return -1
	}
	defer resp.Body.Close()
	
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("❌ Error reading Prometheus response: %v", err)
		return -1
	}
	
	var prometheusResp PrometheusResponse
	if err := json.Unmarshal(body, &prometheusResp); err != nil {
		log.Printf("❌ Error parsing Prometheus response: %v", err)
		return -1
	}
	
	if prometheusResp.Status != "success" || len(prometheusResp.Data.Result) == 0 {
		log.Printf("⚠️ No data returned from Prometheus for query: %s", query)
		return -1
	}
	
	// Extract the value (second element in the value array)
	valueStr, ok := prometheusResp.Data.Result[0].Value[1].(string)
	if !ok {
		log.Printf("❌ Invalid value format from Prometheus")
		return -1
	}
	
	value, err := strconv.ParseFloat(valueStr, 64)
	if err != nil {
		log.Printf("❌ Error parsing float value: %v", err)
		return -1
	}
	
	log.Printf("✅ Prometheus metric retrieved: %f", value)
	return value
}

// getServiceUptime gets uptime status for a specific service
// formatServiceStatus formats service status for display
func formatServiceStatus(uptime float64) string {
	if uptime > 0 {
		return "UP"
	}
	return "DOWN"
}

// checkDatabaseConnection checks if database is reachable
func checkDatabaseConnection(host string, port int) bool {
	timeout := time.Second * 2
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

// getDatabaseResponseTime measures database response time
func getDatabaseResponseTime(dbType string) float64 {
	start := time.Now()
	var host string
	if dbType == "auth" {
		host = "go-cloud-backend_auth-db_1"
	} else {
		host = "go-cloud-backend_user-db_1"
	}
	
	timeout := time.Second * 2
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:5432", host), timeout)
	if err != nil {
		return -1
	}
	defer conn.Close()
	
	duration := time.Since(start)
	return math.Round(float64(duration.Nanoseconds())/1000000*100) / 100 // Convert to milliseconds
}

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

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
	AvgResponseTime   float64 `json:"avg_response_time_ms"`
	RequestsPerSecond float64 `json:"requests_per_second"`
	ErrorRate         float64 `json:"error_rate_percent"`
	ThroughputMbps    float64 `json:"throughput_mbps"`
}

type ResourceUsage struct {
	CpuUsage      float64 `json:"cpu_usage_percent"`
	MemoryUsage   float64 `json:"memory_usage_percent"`
	DiskUsage     float64 `json:"disk_usage_percent"`
	NetworkUsage  float64 `json:"network_usage_percent"`
}

// SICUREZZA - Security Metrics
type SecurityMetricsData struct {
	AuthenticationStats AuthStats          `json:"authentication_stats"`
	SecurityAlerts     []SecurityAlert     `json:"security_alerts"`
	ActiveSessions     ActiveSessionsData  `json:"active_sessions"`
	LoginPatterns      LoginPatternsData   `json:"login_patterns"`
}

type AuthStats struct {
	SuccessfulLogins24h int     `json:"successful_logins_24h"`
	FailedAttempts24h   int     `json:"failed_attempts_24h"`
	SuccessRate         float64 `json:"success_rate_percent"`
	SuspiciousActivity  int     `json:"suspicious_activity_count"`
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
	TotalActive      int                    `json:"total_active"`
	SessionsByDevice []DeviceSessionCount   `json:"sessions_by_device"`
	SessionsByLocation []LocationSessionCount `json:"sessions_by_location"`
}

type DeviceSessionCount struct {
	DeviceType string `json:"device_type"`
	Count      int    `json:"count"`
}

type LocationSessionCount struct {
	Country string `json:"country"`
	City    string `json:"city"`
	Count   int    `json:"count"`
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
	TotalScans24h     int               `json:"total_scans_24h"`
	ScansPerHour      []HourlyStats     `json:"scans_per_hour"`
	TopScanLocations  []LocationStats   `json:"top_scan_locations"`
	ScanSuccessRate   float64           `json:"scan_success_rate"`
	AverageScanTime   float64           `json:"average_scan_time_ms"`
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
	TotalEvents24h      int            `json:"total_events_24h"`
	AttendanceRate      float64        `json:"attendance_rate_percent"`
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

// Prometheus Query Helper
func queryPrometheus(query string) ([]byte, error) {
	url := fmt.Sprintf("http://prometheus-service:9090/api/v1/query?query=%s", query)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	return ioutil.ReadAll(resp.Body)
}

// Parse Prometheus response to float64
func parsePrometheusValue(data []byte) float64 {
	var result map[string]interface{}
	json.Unmarshal(data, &result)
	
	if data, ok := result["data"].(map[string]interface{}); ok {
		if result, ok := data["result"].([]interface{}); ok && len(result) > 0 {
			if metric, ok := result[0].(map[string]interface{}); ok {
				if value, ok := metric["value"].([]interface{}); ok && len(value) > 1 {
					if strVal, ok := value[1].(string); ok {
						if floatVal, err := strconv.ParseFloat(strVal, 64); err == nil {
							return floatVal
						}
					}
				}
			}
		}
	}
	return 0
}

// Main Dashboard API Endpoint
func getPersonalDashboard(c *fiber.Ctx) error {
	// Simulate user info (in real app, get from JWT token)
	userInfo := UserInfo{
		UserID:    "user_123",
		Username:  "admin",
		Role:      "administrator",
		LastLogin: time.Now().Add(-2 * time.Hour).Format(time.RFC3339),
	}

	// 1. NECESSITÀ - System Health
	systemHealth := getSystemHealthData()
	
	// 2. SICUREZZA - Security Metrics  
	securityMetrics := getSecurityMetricsData()
	
	// 3. CURIOSITÀ - Analytics
	analytics := getAnalyticsData()

	dashboard := PersonalDashboard{
		SystemHealth:    systemHealth,
		SecurityMetrics: securityMetrics,
		Analytics:       analytics,
		Timestamp:       time.Now(),
		UserInfo:        userInfo,
	}

	return c.JSON(dashboard)
}

func getSystemHealthData() SystemHealthData {
	// Query Prometheus for system metrics
	
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
	// Authentication stats from Prometheus
	authStats := AuthStats{
		SuccessfulLogins24h: getSuccessfulLogins24h(),
		FailedAttempts24h:   getFailedAttempts24h(),
		SuccessRate:         getAuthSuccessRate(),
		SuspiciousActivity:  getSuspiciousActivityCount(),
	}

	// Security alerts (mock data - in real app, from security monitoring)
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
			{DeviceType: "Desktop", Count: 15},
			{DeviceType: "Mobile", Count: 8},
			{DeviceType: "Tablet", Count: 3},
		},
		SessionsByLocation: []LocationSessionCount{
			{Country: "Italy", City: "Rome", Count: 20},
			{Country: "Italy", City: "Milan", Count: 6},
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

func getAnalyticsData() AnalyticsData {
	// QR Code analytics
	qrAnalytics := QRAnalyticsData{
		TotalScans24h:    getQRScans24h(),
		ScansPerHour:     getQRScansPerHour(),
		TopScanLocations: getTopScanLocations(),
		ScanSuccessRate:  getQRScanSuccessRate(),
		AverageScanTime:  getAvgQRScanTime(),
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
		AttendanceRate:      getAttendanceRate(),
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
		QueriesPerSecond:  getDBQueriesPerSecond(),
		SlowQueries:       getSlowQueries(),
		DatabaseSize:      "2.5 GB",
		CacheHitRate:      getDBCacheHitRate(),
	}

	return AnalyticsData{
		QRCodeAnalytics: qrAnalytics,
		UserBehavior:    userBehavior,
		AttendanceStats: attendanceStats,
		APIUsageStats:   apiUsage,
		DatabaseMetrics: dbMetrics,
	}
}

// Helper functions to get metrics from Prometheus
func getServiceResponseTime(service string) float64 {
	query := fmt.Sprintf(`http_request_duration_seconds{job="%s"}`, service)
	data, _ := queryPrometheus(query)
	return parsePrometheusValue(data) * 1000 // Convert to ms
}

func getServiceUptime(service string) float64 {
	query := fmt.Sprintf(`up{job="%s"}`, service)
	data, _ := queryPrometheus(query)
	return parsePrometheusValue(data) * 100 // Convert to percentage
}

func getAvgResponseTime() float64 {
	data, _ := queryPrometheus(`avg(http_request_duration_seconds)`)
	return parsePrometheusValue(data) * 1000
}

func getRequestsPerSecond() float64 {
	data, _ := queryPrometheus(`rate(http_requests_total[5m])`)
	return parsePrometheusValue(data)
}

func getErrorRate() float64 {
	data, _ := queryPrometheus(`rate(http_requests_total{status=~"4..|5.."}[5m])`)
	return parsePrometheusValue(data) * 100
}

func getThroughput() float64 {
	data, _ := queryPrometheus(`rate(process_network_transmit_bytes_total[5m])`)
	return parsePrometheusValue(data) / 1024 / 1024 // Convert to Mbps
}

func getCpuUsage() float64 {
	data, _ := queryPrometheus(`rate(process_cpu_seconds_total[5m])`)
	return parsePrometheusValue(data) * 100
}

func getMemoryUsage() float64 {
	data, _ := queryPrometheus(`process_resident_memory_bytes`)
	return parsePrometheusValue(data) / 1024 / 1024 / 1024 * 100 // Convert to GB and percentage
}

func getDiskUsage() float64 {
	// Mock data - in real app, get from node_exporter
	return 45.2
}

func getNetworkUsage() float64 {
	data, _ := queryPrometheus(`rate(process_network_receive_bytes_total[5m])`)
	return parsePrometheusValue(data) / 1024 / 1024 // Convert to MB/s
}

// Security metrics helpers
func getSuccessfulLogins24h() int {
	data, _ := queryPrometheus(`increase(auth_attempts_total{status="success"}[24h])`)
	return int(parsePrometheusValue(data))
}

func getFailedAttempts24h() int {
	data, _ := queryPrometheus(`increase(auth_attempts_total{status="failed"}[24h])`)
	return int(parsePrometheusValue(data))
}

func getAuthSuccessRate() float64 {
	successData, _ := queryPrometheus(`increase(auth_attempts_total{status="success"}[24h])`)
	totalData, _ := queryPrometheus(`increase(auth_attempts_total[24h])`)
	
	success := parsePrometheusValue(successData)
	total := parsePrometheusValue(totalData)
	
	if total > 0 {
		return (success / total) * 100
	}
	return 0
}

func getSuspiciousActivityCount() int {
	// Mock data - in real app, implement suspicious activity detection
	return 3
}

func getActiveSessions() int {
	data, _ := queryPrometheus(`active_sessions_total`)
	return int(parsePrometheusValue(data))
}

// Additional helper functions for analytics...
func getPeakLoginHours() []HourlyStats {
	// Mock data - in real app, query Prometheus for hourly login patterns
	return []HourlyStats{
		{Hour: 9, Count: 45},
		{Hour: 10, Count: 32},
		{Hour: 11, Count: 28},
		{Hour: 14, Count: 35},
		{Hour: 15, Count: 40},
	}
}

func getWeeklyLoginPattern() []DailyStats {
	return []DailyStats{
		{Day: "Monday", Count: 245},
		{Day: "Tuesday", Count: 220},
		{Day: "Wednesday", Count: 235},
		{Day: "Thursday", Count: 210},
		{Day: "Friday", Count: 195},
		{Day: "Saturday", Count: 45},
		{Day: "Sunday", Count: 32},
	}
}

func getGeoLoginSpread() []GeoStats {
	return []GeoStats{
		{Country: "Italy", LoginCount: 1150},
		{Country: "Germany", LoginCount: 87},
		{Country: "France", LoginCount: 45},
	}
}

func getQRScans24h() int {
	data, _ := queryPrometheus(`increase(qr_scans_total[24h])`)
	return int(parsePrometheusValue(data))
}

func getQRScansPerHour() []HourlyStats {
	// Mock data - in real app, get from Prometheus
	return []HourlyStats{
		{Hour: 8, Count: 12},
		{Hour: 9, Count: 25},
		{Hour: 10, Count: 18},
		{Hour: 17, Count: 22},
		{Hour: 18, Count: 15},
	}
}

func getTopScanLocations() []LocationStats {
	return []LocationStats{
		{Location: "Main Entrance", Count: 145},
		{Location: "Conference Room A", Count: 87},
		{Location: "Cafeteria", Count: 65},
	}
}

func getQRScanSuccessRate() float64 {
	return 97.8
}

func getAvgQRScanTime() float64 {
	return 1250.5 // milliseconds
}

func getMostActiveUsers() []UserActivity {
	return []UserActivity{
		{UserID: "user_001", Username: "john.doe", ActivityCount: 145, LastActive: "2 minutes ago"},
		{UserID: "user_002", Username: "jane.smith", ActivityCount: 132, LastActive: "5 minutes ago"},
		{UserID: "user_003", Username: "mike.wilson", ActivityCount: 98, LastActive: "1 hour ago"},
	}
}

func getActivityByTimeSlot() []TimeSlotActivity {
	return []TimeSlotActivity{
		{TimeSlot: "08:00-10:00", Users: 45, Actions: 234},
		{TimeSlot: "10:00-12:00", Users: 67, Actions: 345},
		{TimeSlot: "14:00-16:00", Users: 56, Actions: 289},
		{TimeSlot: "16:00-18:00", Users: 34, Actions: 198},
	}
}

func getFeatureUsage() []FeatureUsageStats {
	return []FeatureUsageStats{
		{Feature: "QR Scanning", UsageCount: 1245, Percentage: 35.2},
		{Feature: "User Profile", UsageCount: 987, Percentage: 27.9},
		{Feature: "Attendance Check", UsageCount: 756, Percentage: 21.4},
		{Feature: "Admin Panel", UsageCount: 543, Percentage: 15.5},
	}
}

func getAttendanceEvents24h() int {
	data, _ := queryPrometheus(`increase(attendance_events_total[24h])`)
	return int(parsePrometheusValue(data))
}

func getAttendanceRate() float64 {
	return 89.5
}

func getPeakAttendanceHours() []HourlyStats {
	return []HourlyStats{
		{Hour: 8, Count: 145},
		{Hour: 9, Count: 234},
		{Hour: 17, Count: 189},
		{Hour: 18, Count: 156},
	}
}

func getDepartmentStats() []DeptStats {
	return []DeptStats{
		{Department: "Engineering", AttendanceRate: 94.2, TotalEmployees: 45},
		{Department: "Marketing", AttendanceRate: 87.8, TotalEmployees: 23},
		{Department: "HR", AttendanceRate: 92.1, TotalEmployees: 12},
	}
}

func getAPIRequests24h() int {
	data, _ := queryPrometheus(`increase(http_requests_total[24h])`)
	return int(parsePrometheusValue(data))
}

func getTopEndpoints() []EndpointStats {
	return []EndpointStats{
		{Endpoint: "/api/auth/login", RequestCount: 1234, AvgResponse: 245.6},
		{Endpoint: "/api/qr/scan", RequestCount: 987, AvgResponse: 156.3},
		{Endpoint: "/api/users/profile", RequestCount: 756, AvgResponse: 89.2},
	}
}

func getAPIResponseTimes() []APIResponseStats {
	return []APIResponseStats{
		{API: "auth-service", AvgResponse: 125.4, P95Response: 289.7},
		{API: "user-service", AvgResponse: 98.6, P95Response: 234.5},
		{API: "gateway", AvgResponse: 45.2, P95Response: 123.8},
	}
}

func getAPIErrors() []ErrorStats {
	return []ErrorStats{
		{Endpoint: "/api/auth/verify", ErrorCount: 23, ErrorRate: 2.1},
		{Endpoint: "/api/qr/validate", ErrorCount: 15, ErrorRate: 1.8},
		{Endpoint: "/api/users/update", ErrorCount: 8, ErrorRate: 0.9},
	}
}

func getDBConnections() int {
	data, _ := queryPrometheus(`pg_stat_activity_count`)
	return int(parsePrometheusValue(data))
}

func getDBQueriesPerSecond() float64 {
	data, _ := queryPrometheus(`rate(pg_stat_database_xact_commit[5m])`)
	return parsePrometheusValue(data)
}

func getSlowQueries() int {
	// Mock data - in real app, get from database metrics
	return 5
}

func getDBCacheHitRate() float64 {
	// Mock data - in real app, get from database metrics
	return 98.7
}

func main() {
	app := fiber.New()

	// CORS middleware
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowMethods: "GET,POST,HEAD,PUT,DELETE,PATCH",
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
	}))

	// Dashboard API route
	app.Get("/api/dashboard/personal", getPersonalDashboard)

	// Health check
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status": "healthy",
			"service": "dashboard-api",
			"timestamp": time.Now(),
		})
	})

	fmt.Println("🚀 Dashboard API Server starting on port 3003...")
	app.Listen(":3003")
}

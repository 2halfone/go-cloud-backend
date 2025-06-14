package main

import "time"

// HealthResponse represents the health check response
type HealthResponse struct {
	Status       string           `json:"status" example:"healthy"`
	Timestamp    time.Time        `json:"timestamp"`
	Dependencies DependencyStatus `json:"dependencies"`
	Uptime       string           `json:"uptime" example:"2h30m15s"`
}

// DependencyStatus represents the status of external dependencies
type DependencyStatus struct {
	Prometheus bool `json:"prometheus" example:"true"`
	AuthDB     bool `json:"auth_db" example:"true"`
	UserDB     bool `json:"user_db" example:"true"`
}

// SecurityResponse represents security monitoring data
type SecurityResponse struct {
	AuthenticationStats map[string]interface{} `json:"authentication_stats"`
	JWTValidation      map[string]interface{} `json:"jwt_validation"`
	UserActivity       map[string]interface{} `json:"user_activity"`
	SecurityLevel      string                 `json:"security_level" example:"HIGH_RISK"`
	Metadata           Metadata               `json:"metadata"`
}

// VMHealthResponse represents VM health monitoring data
type VMHealthResponse struct {
	SystemResources map[string]interface{} `json:"system_resources"`
	ServiceHealth   map[string]interface{} `json:"service_health"`
	DatabaseHealth  map[string]interface{} `json:"database_health"`
	ResponseTimes   map[string]interface{} `json:"response_times"`
	Metadata        Metadata               `json:"metadata"`
}

// AnalyticsResponse represents analytics and insights data
type AnalyticsResponse struct {
	QRAnalytics   map[string]interface{} `json:"qr_analytics"`
	UserActivity  map[string]interface{} `json:"user_activity"`
	EventInsights map[string]interface{} `json:"event_insights"`
	UsagePatterns map[string]interface{} `json:"usage_patterns"`
	Metadata      Metadata               `json:"metadata"`
}

// Metadata represents common metadata for all responses
type Metadata struct {
	CollectionTimeMs int64     `json:"collection_time_ms" example:"15"`
	DataSource       string    `json:"data_source" example:"prometheus+database"`
	LastUpdated      time.Time `json:"last_updated"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error" example:"Internal server error"`
	Code    int    `json:"code" example:"500"`
	Message string `json:"message,omitempty" example:"Detailed error message"`
}

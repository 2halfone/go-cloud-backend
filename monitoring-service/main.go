package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

var (
	startTime = time.Now()
	
	// Prometheus metrics
	httpRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status_code"},
	)
	
	httpDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "http_request_duration_seconds",
			Help: "Duration of HTTP requests",
		},
		[]string{"method", "endpoint"},
	)
	
	adminAccess = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "admin_access_total",
			Help: "Total admin access attempts",
		},
		[]string{"user_id", "success"},
	)
)

func init() {
	// Register Prometheus metrics
	prometheus.MustRegister(httpRequests)
	prometheus.MustRegister(httpDuration)
	prometheus.MustRegister(adminAccess)
	
	// Configure logrus
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetLevel(logrus.InfoLevel)
}

type Claims struct {
	UserID int    `json:"user_id"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// JWT Middleware per verificare token e ruolo admin
func adminJWTMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			adminAccess.WithLabelValues("unknown", "false").Inc()
			logrus.WithFields(logrus.Fields{
				"service": "monitoring",
				"action": "admin_access_denied",
				"reason": "missing_token",
			}).Warn("Admin access denied: missing authorization header")
			
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		tokenString := strings.Replace(authHeader, "Bearer ", "", 1)
		
		// Parse token con la secret key
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			jwtSecret := os.Getenv("JWT_SECRET")
			if jwtSecret == "" {
				jwtSecret = "your-secret-key"
			}
			return []byte(jwtSecret), nil
		})

		if err != nil || !token.Valid {
			adminAccess.WithLabelValues("unknown", "false").Inc()
			logrus.WithFields(logrus.Fields{
				"service": "monitoring",
				"action": "admin_access_denied",
				"reason": "invalid_token",
				"error": err.Error(),
			}).Warn("Admin access denied: invalid token")
			
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(*Claims)
		if !ok {
			adminAccess.WithLabelValues("unknown", "false").Inc()
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		// Verifica che l'utente sia admin
		if claims.Role != "admin" {
			adminAccess.WithLabelValues(fmt.Sprintf("%d", claims.UserID), "false").Inc()
			logrus.WithFields(logrus.Fields{
				"service": "monitoring",
				"action": "admin_access_denied",
				"user_id": claims.UserID,
				"role": claims.Role,
				"reason": "insufficient_privileges",
			}).Warn("Admin access denied: insufficient privileges")
			
			c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
			c.Abort()
			return
		}

		// Success logging
		adminAccess.WithLabelValues(fmt.Sprintf("%d", claims.UserID), "true").Inc()
		logrus.WithFields(logrus.Fields{
			"service": "monitoring",
			"action": "admin_access_granted",
			"user_id": claims.UserID,
			"role": claims.Role,
			"duration": time.Since(start).String(),
		}).Info("Admin access granted")

		c.Set("user_id", claims.UserID)
		c.Set("role", claims.Role)
		c.Next()
	}
}

// Metrics middleware
func metricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		
		duration := time.Since(start)
		status := fmt.Sprintf("%d", c.Writer.Status())
		
		httpRequests.WithLabelValues(c.Request.Method, c.FullPath(), status).Inc()
		httpDuration.WithLabelValues(c.Request.Method, c.FullPath()).Observe(duration.Seconds())
	}
}

// Health check con dependency checks
func healthCheck(c *gin.Context) {
	health := gin.H{
		"status": "healthy",
		"service": "monitoring",
		"version": "1.0.0",
		"uptime": time.Since(startTime).String(),
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	
	// Check Grafana connectivity
	grafanaURL := os.Getenv("GRAFANA_URL")
	if grafanaURL == "" {
		grafanaURL = "http://grafana:3000"
	}
	
	grafanaStatus := "unknown"
	if resp, err := http.Get(grafanaURL + "/api/health"); err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			grafanaStatus = "healthy"
		} else {
			grafanaStatus = "unhealthy"
		}
	} else {
		grafanaStatus = "unreachable"
	}
	
	health["dependencies"] = gin.H{
		"grafana": grafanaStatus,
	}
	
	c.JSON(http.StatusOK, health)
}

// Proxy per Grafana
func grafanaProxy(c *gin.Context) {
	grafanaURL := os.Getenv("GRAFANA_URL")
	if grafanaURL == "" {
		grafanaURL = "http://grafana:3000"
	}

	target, err := url.Parse(grafanaURL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid Grafana URL"})
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	
	// Modifica la request per rimuovere il prefisso /monitoring
	originalPath := c.Request.URL.Path
	c.Request.URL.Path = strings.TrimPrefix(originalPath, "/monitoring")
	if c.Request.URL.Path == "" {
		c.Request.URL.Path = "/"
	}

	proxy.ServeHTTP(c.Writer, c.Request)
}

func main() {
	r := gin.Default()

	// Metrics middleware per tutte le richieste
	r.Use(metricsMiddleware())

	// CORS middleware
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
		
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		
		c.Next()
	})

	// Public endpoints (no auth required)
	r.GET("/health", healthCheck)
	r.GET("/metrics", promhttp.Handler())

	// Protected monitoring routes (admin only)
	protected := r.Group("/")
	protected.Use(adminJWTMiddleware())
	{
		// Info endpoint
		protected.GET("/info", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"message": "Monitoring Service - Admin Dashboard",
				"user_id": c.GetInt("user_id"),
				"role":    c.GetString("role"),
				"grafana": "Available at /monitoring/*",
				"endpoints": gin.H{
					"health": "/health",
					"metrics": "/metrics (public)",
					"grafana": "/monitoring/*",
					"info": "/info",
				},
			})
		})

		// Proxy to Grafana
		protected.Any("/monitoring/*path", grafanaProxy)
		protected.Any("/monitoring", grafanaProxy)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8085"
	}

	logrus.WithFields(logrus.Fields{
		"service": "monitoring",
		"port": port,
		"uptime": time.Since(startTime).String(),
	}).Info("🔍 Monitoring Service starting")
	
	fmt.Printf("🔍 Monitoring Service starting on port %s\n", port)
	fmt.Println("📊 Admin-only Grafana access available at /monitoring")
	fmt.Println("📈 Metrics endpoint available at /metrics")
	fmt.Println("🏥 Health check available at /health")
	
	r.Run(":" + port)
}

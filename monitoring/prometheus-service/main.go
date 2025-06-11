package main

import (
    "log"
    "os"
    "time"
    
    "prometheus-service/metrics"
    "prometheus-service/middleware"
    
    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/fiber/v2/middleware/cors"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "github.com/valyala/fasthttp/fasthttpadaptor"
)

func main() {
    // Inizializza Prometheus registry
    metrics.InitPrometheusMetrics()
    
    app := fiber.New(fiber.Config{
        Prefork:      false,
        IdleTimeout:  30 * time.Second,
        ReadTimeout:  30 * time.Second,
        WriteTimeout: 30 * time.Second,
    })
    
    // CORS per permettere accesso al frontend
    app.Use(cors.New(cors.Config{
        AllowOrigins: "*",
        AllowMethods: "GET,POST,PUT,DELETE,OPTIONS",
        AllowHeaders: "Origin,Content-Type,Accept,Authorization",
    }))
    
    // Middleware per raccogliere metriche
    app.Use(middleware.PrometheusMiddleware())
    
    // Health check
    app.Get("/health", func(c *fiber.Ctx) error {
        return c.JSON(fiber.Map{
            "status":    "healthy",
            "service":   "prometheus-service",
            "timestamp": time.Now(),
        })
    })
    
    // Endpoint per esporre metriche Prometheus
    app.Get("/metrics", func(c *fiber.Ctx) error {
        handler := fasthttpadaptor.NewFastHTTPHandler(promhttp.Handler())
        handler(c.Context())
        return nil
    })
    
    // Endpoint per dashboard semplice
    app.Get("/dashboard", func(c *fiber.Ctx) error {
        return c.JSON(fiber.Map{
            "message": "Prometheus Dashboard",
            "metrics_endpoint": "/metrics",
            "services": []string{
                "auth-service",
                "user-service",
                "gateway",
            },
        })
    })
    
    // Endpoint per statistiche in tempo reale
    app.Get("/stats", func(c *fiber.Ctx) error {
        return c.JSON(fiber.Map{
            "total_requests": "Check /metrics endpoint",
            "active_users": "Check /metrics endpoint",
            "qr_scans": "Check /metrics endpoint",
            "auth_attempts": "Check /metrics endpoint",
            "uptime": time.Now().Format(time.RFC3339),
        })
    })
    
    port := os.Getenv("PROMETHEUS_PORT")
    if port == "" {
        port = "9090"
    }
    
    log.Printf("🚀 Prometheus service starting on port %s", port)
    log.Printf("📊 Metrics available at: http://localhost:%s/metrics", port)
    log.Printf("📈 Dashboard available at: http://localhost:%s/dashboard", port)
    log.Fatal(app.Listen(":" + port))
}

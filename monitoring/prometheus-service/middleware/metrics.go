package middleware

import (
    "strconv"
    "time"
    
    "prometheus-service/metrics"
    
    "github.com/gofiber/fiber/v2"
)

func PrometheusMiddleware() fiber.Handler {
    return func(c *fiber.Ctx) error {
        start := time.Now()
        
        // Processa la richiesta
        err := c.Next()
        
        duration := time.Since(start)
        statusCode := strconv.Itoa(c.Response().StatusCode())
        
        // Registra le metriche
        metrics.HTTPRequestsTotal.WithLabelValues(
            c.Method(),
            c.Path(),
            statusCode,
            "prometheus-service",
        ).Inc()
        
        metrics.HTTPRequestDuration.WithLabelValues(
            c.Method(),
            c.Path(),
            "prometheus-service",
        ).Observe(duration.Seconds())
        
        return err
    }
}

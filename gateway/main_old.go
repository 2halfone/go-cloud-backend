package main

import (
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "os"
    "strconv"
    "strings"
    "time"

    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/fiber/v2/middleware/cors"
    "github.com/gofiber/fiber/v2/middleware/helmet"
    "github.com/gofiber/fiber/v2/middleware/limiter"
    "github.com/gofiber/fiber/v2/middleware/proxy"
    "github.com/gofiber/fiber/v2/middleware/recover"
    jwtware "github.com/gofiber/jwt/v3"
    "github.com/golang-jwt/jwt/v4"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "github.com/valyala/fasthttp/fasthttpadaptor"
    
    "go-cloud-backend/shared/metrics"
)

// JWT secret - loaded from environment variable JWT_SECRET
var jwtSecret []byte

// Helper function to determine target service from path
func getTargetService(path string) string {
    if strings.HasPrefix(path, "/auth/") {
        return "auth-service"
    } else if strings.HasPrefix(path, "/user/") {
        return "user-service"
    } else if strings.HasPrefix(path, "/admin/") {
        return "auth-service"
    } else if strings.HasPrefix(path, "/dashboard/") {
        return "dashboard-api"
    } else if strings.HasPrefix(path, "/monitoring/") {
        return "prometheus-service"
    }
    return "gateway"
}

// LogEntry rappresenta una voce di log strutturata
type LogEntry struct {
    Timestamp    string            `json:"timestamp"`
    Method       string            `json:"method"`
    Path         string            `json:"path"`
    StatusCode   int               `json:"status_code"`
    Duration     string            `json:"duration"`
    IP           string            `json:"ip"`
    UserAgent    string            `json:"user_agent"`
    RequestID    string            `json:"request_id"`
    UserID       string            `json:"user_id,omitempty"`
    Headers      map[string]string `json:"headers"`
    RequestBody  string            `json:"request_body,omitempty"`
    ResponseBody string            `json:"response_body,omitempty"`
    Error        string            `json:"error,omitempty"`
    Service      string            `json:"service,omitempty"`
}

// RequestResponseLogger middleware per il logging completo delle richieste/risposte
func RequestResponseLogger() fiber.Handler {
    return func(c *fiber.Ctx) error {
        start := time.Now()
        requestID := c.Get("X-Request-ID")
        if requestID == "" {
            requestID = fmt.Sprintf("%d-%s", time.Now().UnixNano(), c.IP())
        }
        
        // Leggi il body della richiesta (limitato per sicurezza)
        var requestBody string
        if c.Body() != nil && len(c.Body()) < 1024 { // Max 1KB per log
            requestBody = string(c.Body())
        }
        
        // Cattura headers importanti (nascondendo token sensibili)
        headers := make(map[string]string)
        headers["Content-Type"] = c.Get("Content-Type")
        if auth := c.Get("Authorization"); auth != "" {
            if strings.HasPrefix(auth, "Bearer ") {
                headers["Authorization"] = "Bearer [REDACTED]"
            } else {
                headers["Authorization"] = "[REDACTED]"
            }
        }
        headers["User-Agent"] = c.Get("User-Agent")
        
        // Estrai user ID dal JWT se presente
        var userID string
        if user := c.Locals("user"); user != nil {
            if token, ok := user.(*jwt.Token); ok {
                if claims, ok := token.Claims.(jwt.MapClaims); ok {
                    if id, exists := claims["user_id"]; exists {
                        userID = fmt.Sprintf("%v", id)
                    }
                }
            }
        }          // Determina il servizio di destinazione
        var service string
        path := c.Path()
        switch {
        case strings.HasPrefix(path, "/auth/"):
            service = "auth-service"
        case strings.HasPrefix(path, "/user/"):
            service = "user-service"
        default:
            service = "gateway"
        }
        
        // Processa la richiesta
        err := c.Next()
        
        duration := time.Since(start)
        
        // Cattura il body della risposta se è JSON (limitato per sicurezza)
        var responseBody string
        if strings.Contains(c.Get("Content-Type"), "application/json") {
            respBody := c.Response().Body()
            if len(respBody) < 1024 { // Max 1KB per log
                responseBody = string(respBody)
            }
        }
        
        // Crea la voce di log
        logEntry := LogEntry{
            Timestamp:    start.Format(time.RFC3339),
            Method:       c.Method(),
            Path:         c.Path(),
            StatusCode:   c.Response().StatusCode(),
            Duration:     duration.String(),
            IP:           c.IP(),
            UserAgent:    c.Get("User-Agent"),
            RequestID:    requestID,
            UserID:       userID,
            Headers:      headers,
            RequestBody:  requestBody,
            ResponseBody: responseBody,
            Service:      service,
        }
        
        if err != nil {
            logEntry.Error = err.Error()
        }
        
        // Log in formato JSON
        logJSON, _ := json.Marshal(logEntry)
        log.Printf("REQUEST_LOG: %s", string(logJSON))
        
        return err
    }
}

// SecurityHeaders middleware per aggiungere header di sicurezza.
func SecurityHeaders() fiber.Handler {
    return func(c *fiber.Ctx) error {
        c.Set("X-Content-Type-Options", "nosniff")
        c.Set("X-Frame-Options", "DENY")
        c.Set("X-XSS-Protection", "1; mode=block")
        c.Set("Referrer-Policy", "strict-origin-when-cross-origin")
        c.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        c.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'")
        c.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return c.Next()
    }
}

func main() {
    // Initialize metrics system
    metrics.InitMetrics()
    
    // Load JWT secret from environment variable
    jwtSecretEnv := os.Getenv("JWT_SECRET")
    if jwtSecretEnv == "" {
        log.Fatal("JWT_SECRET environment variable not set")
    }
    jwtSecret = []byte(jwtSecretEnv)

    app := fiber.New(fiber.Config{
        ErrorHandler: func(c *fiber.Ctx, err error) error {
            code := fiber.StatusInternalServerError
            if e, ok := err.(*fiber.Error); ok {
                code = e.Code
            }
            
            // Log dettagliato dell'errore
            log.Printf("ERROR: %s - Path: %s - Method: %s - IP: %s - UserAgent: %s", 
                err.Error(), c.Path(), c.Method(), c.IP(), c.Get("User-Agent"))
            
            return c.Status(code).JSON(fiber.Map{
                "error":     "Internal server error",
                "code":      code,
                "timestamp": time.Now().Format(time.RFC3339),
            })
        },        ReadTimeout:  30 * time.Second,
        WriteTimeout: 30 * time.Second,
        BodyLimit:    2 * 1024 * 1024, // 2MB limit
    })

    // -------------------------------------------------------
    // 1) Middleware di sicurezza globale
    // -------------------------------------------------------
    
    // Recover da panic
    app.Use(recover.New(recover.Config{
        EnableStackTrace: true,
    }))
    
    // Security headers personalizzati
    app.Use(SecurityHeaders())
    
    // Helmet per sicurezza aggiuntiva
    app.Use(helmet.New(helmet.Config{
        XSSProtection:             "1; mode=block",
        ContentTypeNosniff:        "nosniff",
        XFrameOptions:             "DENY",
        ReferrerPolicy:            "strict-origin-when-cross-origin",
        CrossOriginEmbedderPolicy: "require-corp",
        CrossOriginOpenerPolicy:   "same-origin",
        CrossOriginResourcePolicy: "cross-origin",
        OriginAgentCluster:        "?1",
        XDNSPrefetchControl:       "off",
        XDownloadOptions:          "noopen",
        XPermittedCrossDomain:     "none",
    }))
      // CORS configuration sicura
    app.Use(cors.New(cors.Config{
        AllowOrigins:     "http://localhost:5500,http://localhost:8080,http://127.0.0.1:5500,http://127.0.0.1:8080,http://localhost:3000,https://localhost:3000,https://localhost:8080",
        AllowMethods:     "GET,POST,PUT,DELETE,OPTIONS",
        AllowHeaders:     "Origin,Content-Type,Accept,Authorization,X-Request-ID,X-Forwarded-For",
        AllowCredentials: true,
        MaxAge:           86400, // 24 ore
    }))
      // Rate limiting globale con diversi limiti per endpoint
    app.Use(limiter.New(limiter.Config{
        Max:        100, // 100 richieste per minuto per endpoint generale
        Expiration: 1 * time.Minute,
        KeyGenerator: func(c *fiber.Ctx) string {
            return c.Get("X-Forwarded-For", c.IP())
        },
        LimitReached: func(c *fiber.Ctx) error {
            log.Printf("RATE_LIMIT_EXCEEDED: IP=%s Path=%s Method=%s UserAgent=%s", 
                c.IP(), c.Path(), c.Method(), c.Get("User-Agent"))
            return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
                "error":     "Rate limit exceeded",
                "message":   "Too many requests, please try again later",
                "retry_after": 60,
                "timestamp": time.Now().Format(time.RFC3339),
            })
        },
    }))
    
    // Rate limiting più severo per auth endpoints
    app.Use("/auth/*", limiter.New(limiter.Config{
        Max:        20, // 20 richieste per minuto per auth
        Expiration: 1 * time.Minute,
        KeyGenerator: func(c *fiber.Ctx) string {
            return "auth:" + c.Get("X-Forwarded-For", c.IP())
        },
        LimitReached: func(c *fiber.Ctx) error {
            log.Printf("AUTH_RATE_LIMIT_EXCEEDED: IP=%s Path=%s Method=%s", 
                c.IP(), c.Path(), c.Method())
            return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
                "error":     "Authentication rate limit exceeded",
                "message":   "Too many authentication attempts, please try again later",
                "retry_after": 60,
                "timestamp": time.Now().Format(time.RFC3339),
            })
        },
    }))
      // Logger completo per richieste/risposte    app.Use(RequestResponseLogger())    
    
    // Metrics middleware per HTTP requests e proxy - TEMPORANEAMENTE DISABILITATO per duplicati
    // app.Use(metrics.HTTPMetricsMiddleware("gateway"))
    
    // Middleware per proxy metrics
    app.Use(func(c *fiber.Ctx) error {
        err := c.Next()
        
        // Record proxy metrics based on path
        targetService := getTargetService(c.Path())
        if targetService != "gateway" {
            statusCode := strconv.Itoa(c.Response().StatusCode())
            metrics.RecordProxyRequest(targetService, statusCode)
        }
        
        return err
    })
    
    // -------------------------------------------------------    // Rotte pubbliche (senza JWT)
    // -------------------------------------------------------    // Rotte di autenticazione - non richiedono JWT
    app.All("/auth/*", func(c *fiber.Ctx) error {
        // Strip /auth prefix and forward to auth-service
        newPath := strings.TrimPrefix(c.OriginalURL(), "/auth")
        if newPath == "" {
            newPath = "/"
        }
        target := "http://auth-service:3001" + newPath
        
        // Aggiungi header personalizzato per identificare richieste dal Gateway
        c.Set("X-Gateway-Request", "gateway-v1.0")
        
        log.Printf("AUTH_PROXY: %s %s -> %s [IP: %s]", c.Method(), c.OriginalURL(), target, c.IP())
        return proxy.Do(c, target)    })

    // QR Attendance System - Public QR scanning
    app.Post("/user/scan-qr", func(c *fiber.Ctx) error {
        target := "http://user-service:3002/qr/scan"
        
        // Aggiungi header personalizzato per identificare richieste dal Gateway
        c.Set("X-Gateway-Request", "gateway-v1.0")
        
        log.Printf("QR_SCAN_PROXY: %s %s -> %s [IP: %s]", c.Method(), c.OriginalURL(), target, c.IP())
        return proxy.Do(c, target)
    })    // Health checks pubblici
    app.Get("/health", func(c *fiber.Ctx) error {
        return c.JSON(fiber.Map{
            "status":    "healthy",
            "service":   "gateway",
            "timestamp": time.Now().Format(time.RFC3339),
            "version":   "1.0.0",
        })
    })

    // Prometheus metrics endpoint (local service metrics)
    app.Get("/metrics", func(c *fiber.Ctx) error {
        handler := fasthttpadaptor.NewFastHTTPHandler(promhttp.Handler())
        handler(c.Context())
        return nil
    })

    // Prometheus monitoring access (proxy to internal Prometheus)
    app.Get("/monitoring/*", func(c *fiber.Ctx) error {
        // Remove /monitoring prefix and proxy to prometheus-service
        path := strings.TrimPrefix(c.Path(), "/monitoring")
        if path == "" {
            path = "/"
        }
        
        return proxy.Do(c, "http://prometheus-service:9090"+path)
    })
    
    // -------------------------------------------------------    // Rotte pubbliche (senza JWT)
    // -------------------------------------------------------    // Rotte di autenticazione - non richiedono JWT
    app.All("/auth/*", func(c *fiber.Ctx) error {
        // Strip /auth prefix and forward to auth-service
        newPath := strings.TrimPrefix(c.OriginalURL(), "/auth")
        if newPath == "" {
            newPath = "/"
        }
        target := "http://auth-service:3001" + newPath
        
        // Aggiungi header personalizzato per identificare richieste dal Gateway
        c.Set("X-Gateway-Request", "gateway-v1.0")
        
        log.Printf("AUTH_PROXY: %s %s -> %s [IP: %s]", c.Method(), c.OriginalURL(), target, c.IP())
        return proxy.Do(c, target)    })

    // QR Attendance System - Public QR scanning
    app.Post("/user/scan-qr", func(c *fiber.Ctx) error {
        target := "http://user-service:3002/qr/scan"
        
        // Aggiungi header personalizzato per identificare richieste dal Gateway
        c.Set("X-Gateway-Request", "gateway-v1.0")
        
        log.Printf("QR_SCAN_PROXY: %s %s -> %s [IP: %s]", c.Method(), c.OriginalURL(), target, c.IP())
        return proxy.Do(c, target)
    })    // Health checks pubblici
    app.Get("/health", func(c *fiber.Ctx) error {
        return c.JSON(fiber.Map{
            "status":    "healthy",
            "service":   "gateway",
            "timestamp": time.Now().Format(time.RFC3339),
            "version":   "1.0.0",
        })
    })

    // Prometheus metrics endpoint (local service metrics)
    app.Get("/metrics", func(c *fiber.Ctx) error {
        handler := fasthttpadaptor.NewFastHTTPHandler(promhttp.Handler())
        handler(c.Context())
        return nil
    })

    // Prometheus monitoring access (proxy to internal Prometheus)
    app.Get("/monitoring/*", func(c *fiber.Ctx) error {
        // Remove /monitoring prefix and proxy to prometheus-service
        path := strings.TrimPrefix(c.Path(), "/monitoring")
        if path == "" {
            path = "/"
        }
        
        return proxy.Do(c, "http://prometheus-service:9090"+path)
    })
    
    // -------------------------------------------------------    // Rotte pubbliche (senza JWT)
    // -------------------------------------------------------    // Rotte di autenticazione - non richiedono JWT
    app.All("/auth/*", func(c *fiber.Ctx) error {
        // Strip /auth prefix and forward to auth-service
        newPath := strings.TrimPrefix(c.OriginalURL(), "/auth")
        if newPath == "" {
            newPath = "/"
        }
        target := "http://auth-service:3001" + newPath
        
        // Aggiungi header personalizzato per identificare richieste dal Gateway
        c.Set("X-Gateway-Request", "gateway-v1.0")
        
        log.Printf("AUTH_PROXY: %s %s -> %s [IP: %s]", c.Method(), c.OriginalURL(), target, c.IP())
        return proxy.Do(c, target)    })

    // QR Attendance System - Public QR scanning
    app.Post("/user/scan-qr", func(c *fiber.Ctx) error {
        target := "http://user-service:3002/qr/scan"
        
        // Aggiungi header personalizzato per identificare richieste dal Gateway
        c.Set("X-Gateway-Request", "gateway-v1.0")
        
        log.Printf("QR_SCAN_PROXY: %s %s -> %s [IP: %s]", c.Method(), c.OriginalURL(), target, c.IP())
        return proxy.Do(c, target)
    })    // Health checks pubblici
    app.Get("/health", func(c *fiber.Ctx) error {
        return c.JSON(fiber.Map{
            "status":    "healthy",
            "service":   "gateway",
            "timestamp": time.Now().Format(time.RFC3339),
            "version":   "1.0.0",
        })
    })

    // Prometheus metrics endpoint (local service metrics)
    app.Get("/metrics", func(c *fiber.Ctx) error {
        handler := fasthttpadaptor.NewFastHTTPHandler(promhttp.Handler())
        handler(c.Context())
        return nil
    })

    // Prometheus monitoring access (proxy to internal Prometheus)
    app.Get("/monitoring/*", func(c *fiber.Ctx) error {
        // Remove /monitoring prefix and proxy to prometheus-service
        path := strings.TrimPrefix(c.Path(), "/monitoring")
        if path == "" {
            path = "/"
        }
        
        return proxy.Do(c, "http://prometheus-service:9090"+path)
    })
    
    // -------------------------------------------------------    // Rotte pubbliche (senza JWT)
    // -------------------------------------------------------    // Rotte di autenticazione - non richiedono JWT
    app.All("/auth/*", func(c *fiber.Ctx) error {
        // Strip /auth prefix and forward to auth-service
        newPath := strings.TrimPrefix(c.OriginalURL(), "/auth")
        if newPath == "" {
            newPath = "/"
        }
        target := "http://auth-service:3001" + newPath
        
        // Aggiungi header personalizzato per identificare richieste dal Gateway
        c.Set("X-Gateway-Request", "gateway-v1.0")
        
        log.Printf("AUTH_PROXY: %s %s -> %s [IP: %s]", c.Method(), c.OriginalURL(), target, c.IP())
        return proxy.Do(c, target)    })

    // QR Attendance System - Public QR scanning
    app.Post("/user/scan-qr", func(c *fiber.Ctx) error {
        target := "http://user-service:3002/qr/scan"
        
        // Aggiungi header personalizzato per identificare richieste dal Gateway
        c.Set("X-Gateway-Request", "gateway-v1.0")
        
        log.Printf("QR_SCAN_PROXY: %s %s -> %s [IP: %s]", c.Method(), c.OriginalURL(), target, c.IP())
        return proxy.Do(c, target)
    })    // Health checks pubblici
    app.Get("/health", func(c *fiber.Ctx) error {
        return c.JSON(fiber.Map{
            "status":    "healthy",
            "service":   "gateway",
            "timestamp": time.Now().Format(time.RFC3339),
            "version":   "1.0.0",
        })
    })

    // Prometheus metrics endpoint (local service metrics)
    app.Get("/metrics", func(c *fiber.Ctx) error {
        handler := fasthttpadaptor.NewFastHTTPHandler(promhttp.Handler())
        handler(c.Context())
        return nil
    })

    // Prometheus monitoring access (proxy to internal Prometheus)
    app.Get("/monitoring/*", func(c *fiber.Ctx) error {
        // Remove /monitoring prefix and proxy to prometheus-service
        path := strings.TrimPrefix(c.Path(), "/monitoring")
        if path == "" {
            path = "/"
        }
        
        return proxy.Do(c, "http://prometheus-service:9090"+path)
    })
    
    // -------------------------------------------------------
    // 3) Middleware JWT per rotte protette
    // -------------------------------------------------------
      // Tutte le altre rotte richiedono JWT valido
    app.Use(jwtware.New(jwtware.Config{
        SigningKey:   jwtSecret,
        ErrorHandler: jwtError,
    }))    // Middleware per tracciare validazioni JWT riuscite
    app.Use(func(c *fiber.Ctx) error {
        // Se arriviamo qui, la validazione JWT è andata a buon fine
        metrics.RecordJWTValidation(true, "gateway")
        return c.Next()
    })

    // -------------------------------------------------------
    // 4) Rotte protette con JWT obbligatorio
    // -------------------------------------------------------

// User service protetto - forward con path stripping
app.All("/user/*", func(c *fiber.Ctx) error {
    // Rimuovi /user dal path e forward al user-service
    path := strings.TrimPrefix(c.Path(), "/user")
    if path == "" {
        path = "/"
    }
    target := "http://user-service:3002" + path
    if c.OriginalURL() != c.Path() {
        // Mantieni query parameters
        if strings.Contains(c.OriginalURL(), "?") {
            target += "?" + strings.Split(c.OriginalURL(), "?")[1]
        }
    }
    
    // Aggiungi header personalizzato per identificare richieste dal Gateway
    c.Set("X-Gateway-Request", "gateway-v1.0")
      log.Printf("USER_PROXY: %s %s -> %s [IP: %s, User: %s]", 
        c.Method(), c.OriginalURL(), target, c.IP(), getUserID(c))
    return proxy.Do(c, target)
})

// -------------------------------------------------------
// QR Attendance System Routes (JWT Protected)
// -------------------------------------------------------

// QR User routes (JWT protected)
app.Post("/user/qr/scan", func(c *fiber.Ctx) error {
    target := "http://user-service:3002/qr/scan"
    c.Set("X-Gateway-Request", "gateway-v1.0")
    log.Printf("QR_SCAN_AUTH_PROXY: %s %s -> %s [IP: %s, User: %s]", 
        c.Method(), c.OriginalURL(), target, c.IP(), getUserID(c))
    return proxy.Do(c, target)
})

app.Get("/user/qr/attendance/history", func(c *fiber.Ctx) error {
    target := "http://user-service:3002/qr/attendance/history"
    if c.OriginalURL() != c.Path() && strings.Contains(c.OriginalURL(), "?") {
        target += "?" + strings.Split(c.OriginalURL(), "?")[1]
    }
    c.Set("X-Gateway-Request", "gateway-v1.0")
    log.Printf("QR_HISTORY_PROXY: %s %s -> %s [IP: %s, User: %s]", 
        c.Method(), c.OriginalURL(), target, c.IP(), getUserID(c))
    return proxy.Do(c, target)
})

app.Get("/user/qr/attendance/today", func(c *fiber.Ctx) error {
    target := "http://user-service:3002/qr/attendance/today"
    c.Set("X-Gateway-Request", "gateway-v1.0")
    log.Printf("QR_TODAY_PROXY: %s %s -> %s [IP: %s, User: %s]", 
        c.Method(), c.OriginalURL(), target, c.IP(), getUserID(c))
    return proxy.Do(c, target)
})

// QR Admin routes (JWT + Admin role required)
app.Post("/user/qr/admin/generate", adminOnly, func(c *fiber.Ctx) error {
    target := "http://user-service:3002/qr/admin/generate"
    c.Set("X-Gateway-Request", "gateway-v1.0")
    log.Printf("QR_GENERATE_PROXY: %s %s -> %s [IP: %s, User: %s]", 
        c.Method(), c.OriginalURL(), target, c.IP(), getUserID(c))
    return proxy.Do(c, target)
})

app.Get("/user/qr/admin/events", adminOnly, func(c *fiber.Ctx) error {
    target := "http://user-service:3002/qr/admin/events"
    if c.OriginalURL() != c.Path() && strings.Contains(c.OriginalURL(), "?") {
        target += "?" + strings.Split(c.OriginalURL(), "?")[1]
    }
    c.Set("X-Gateway-Request", "gateway-v1.0")
    log.Printf("QR_EVENTS_PROXY: %s %s -> %s [IP: %s, User: %s]", 
        c.Method(), c.OriginalURL(), target, c.IP(), getUserID(c))
    return proxy.Do(c, target)
})

app.Get("/user/qr/admin/events/:event_id/attendance", adminOnly, func(c *fiber.Ctx) error {
    eventID := c.Params("event_id")
    target := fmt.Sprintf("http://user-service:3002/qr/admin/events/%s/attendance", eventID)
    if c.OriginalURL() != c.Path() && strings.Contains(c.OriginalURL(), "?") {
        target += "?" + strings.Split(c.OriginalURL(), "?")[1]
    }
    c.Set("X-Gateway-Request", "gateway-v1.0")
    log.Printf("QR_EVENT_ATTENDANCE_PROXY: %s %s -> %s [IP: %s, User: %s]", 
        c.Method(), c.OriginalURL(), target, c.IP(), getUserID(c))
    return proxy.Do(c, target)
})

app.Get("/user/qr/admin/events/:event_id/users", adminOnly, func(c *fiber.Ctx) error {
    eventID := c.Params("event_id")
    target := fmt.Sprintf("http://user-service:3002/qr/admin/events/%s/users", eventID)
    if c.OriginalURL() != c.Path() && strings.Contains(c.OriginalURL(), "?") {
        target += "?" + strings.Split(c.OriginalURL(), "?")[1]
    }
    c.Set("X-Gateway-Request", "gateway-v1.0")
    log.Printf("QR_EVENT_USERS_PROXY: %s %s -> %s [IP: %s, User: %s]", 
        c.Method(), c.OriginalURL(), target, c.IP(), getUserID(c))
    return proxy.Do(c, target)
})

// -------------------------------------------------------
// 5) Rotte amministrative (solo admin)
// -------------------------------------------------------

// Auth Admin routes - forward to auth-service
app.Get("/admin/users", adminOnly, func(c *fiber.Ctx) error {
    target := "http://auth-service:3001/admin/users"
    if c.OriginalURL() != c.Path() && strings.Contains(c.OriginalURL(), "?") {
        target += "?" + strings.Split(c.OriginalURL(), "?")[1]
    }
    c.Set("X-Gateway-Request", "gateway-v1.0")
    log.Printf("ADMIN_USERS_PROXY: %s %s -> %s [IP: %s, Admin: %s]", 
        c.Method(), c.OriginalURL(), target, c.IP(), getUserID(c))
    return proxy.Do(c, target)
})

app.Get("/admin/auth-logs", adminOnly, func(c *fiber.Ctx) error {
    target := "http://auth-service:3001/admin/auth-logs"
    if c.OriginalURL() != c.Path() && strings.Contains(c.OriginalURL(), "?") {
        target += "?" + strings.Split(c.OriginalURL(), "?")[1]
    }
    c.Set("X-Gateway-Request", "gateway-v1.0")
    log.Printf("ADMIN_AUTH_LOGS_PROXY: %s %s -> %s [IP: %s, Admin: %s]", 
        c.Method(), c.OriginalURL(), target, c.IP(), getUserID(c))
    return proxy.Do(c, target)
})

app.Put("/admin/users/:id/role", adminOnly, func(c *fiber.Ctx) error {
    userID := c.Params("id")
    target := fmt.Sprintf("http://auth-service:3001/admin/users/%s/role", userID)
    c.Set("X-Gateway-Request", "gateway-v1.0")
    log.Printf("ADMIN_UPDATE_ROLE_PROXY: %s %s -> %s [IP: %s, Admin: %s]", 
        c.Method(), c.OriginalURL(), target, c.IP(), getUserID(c))
    return proxy.Do(c, target)
})

app.Delete("/admin/users/:id", adminOnly, func(c *fiber.Ctx) error {
    userID := c.Params("id")
    target := fmt.Sprintf("http://auth-service:3001/admin/users/%s", userID)
    c.Set("X-Gateway-Request", "gateway-v1.0")
    log.Printf("ADMIN_DELETE_USER_PROXY: %s %s -> %s [IP: %s, Admin: %s]", 
        c.Method(), c.OriginalURL(), target, c.IP(), getUserID(c))
    return proxy.Do(c, target)
})

// QR Admin routes - forward to user-service with DNS fallback
app.All("/admin/qr/*", adminOnly, func(c *fiber.Ctx) error {
    // Map /admin/qr/* to /qr/admin/* in user-service
    qrPath := strings.TrimPrefix(c.Path(), "/admin/qr")
    if qrPath == "" {
        qrPath = "/"
    }
    
    // Try DNS first, fallback to IP if DNS fails
    targets := []string{
        "http://user-service:3002/qr/admin" + qrPath,
        "http://172.18.0.4:3002/qr/admin" + qrPath, // Fallback IP
    }
    
    // Preserve query parameters
    queryParams := ""
    if c.OriginalURL() != c.Path() && strings.Contains(c.OriginalURL(), "?") {
        queryParams = "?" + strings.Split(c.OriginalURL(), "?")[1]
    }
    
    // Aggiungi header personalizzato per identificare richieste dal Gateway
    c.Set("X-Gateway-Request", "gateway-v1.0")
    
    var lastErr error
    for i, baseTarget := range targets {
        target := baseTarget + queryParams
        log.Printf("QR_ADMIN_PROXY_ATTEMPT_%d: %s %s -> %s [IP: %s, User: %s, Role: %s]", 
            i+1, c.Method(), c.OriginalURL(), target, c.IP(), getUserID(c), getUserRole(c))
        
        err := proxy.Do(c, target)
        if err == nil {
            log.Printf("QR_ADMIN_PROXY_SUCCESS: %s %s -> %s", 
                c.Method(), c.OriginalURL(), target)
            return nil
        }
        
        lastErr = err
        log.Printf("QR_ADMIN_PROXY_FAILED_%d: %s %s -> %s [Error: %v]", 
            i+1, c.Method(), c.OriginalURL(), target, err)
    }
    
    // If all targets fail, return the last error
    log.Printf("QR_ADMIN_PROXY_ALL_FAILED: %s %s [Final Error: %v]", 
        c.Method(), c.OriginalURL(), lastErr)
    return lastErr
})

// Admin routes - richiedono ruolo admin (altri endpoint)
app.All("/admin/*", adminOnly, func(c *fiber.Ctx) error {
    // Strip /admin prefix and forward to auth-service
    newPath := strings.TrimPrefix(c.OriginalURL(), "/admin")
    if newPath == "" {
        newPath = "/"
    }
    target := "http://auth-service:3001/admin" + newPath
    
    // Aggiungi header personalizzato per identificare richieste dal Gateway
    c.Set("X-Gateway-Request", "gateway-v1.0")
    
    log.Printf("ADMIN_PROXY: %s %s -> %s [IP: %s, User: %s, Role: %s]", 
        c.Method(), c.OriginalURL(), target, c.IP(), getUserID(c), getUserRole(c))
    return proxy.Do(c, target)
})

// -------------------------------------------------------
// 6) Avvio del server
// -------------------------------------------------------      log.Println("🚀 Secure API Gateway v1.0.0 starting...")
    log.Println("📊 Security features enabled:")
    log.Println("   ✅ JWT Authentication")
    log.Println("   ✅ Rate Limiting (100/min global, 20/min auth)")
    log.Println("   ✅ Security Headers (HSTS, CSP, XSS)")
    log.Println("   ✅ CORS Protection")
    log.Println("   ✅ Request/Response Logging")
    log.Println("   ✅ Error Handling & Recovery")
      log.Println("🔒 Protected routes: /user/*, /admin/*")
    log.Println("🌐 Public routes: /auth/*, /user/scan-qr, /health, /")
    log.Println("📱 QR User routes: /user/qr/scan, /user/qr/attendance/* (JWT protected)")
    log.Println("👑 QR Admin routes: /user/qr/admin/* (admin role required)")
    log.Println("👑 Admin routes: /admin/* (admin role required)")
    log.Println("🎯 Gateway listening on port 3000")
    
    if err := app.Listen(":3000"); err != nil {
        log.Fatal("❌ Failed to start gateway:", err)
    }
}

// jwtError gestisce gli errori di autenticazione JWT
func jwtError(c *fiber.Ctx, err error) error {
    log.Printf("JWT_AUTH_FAILED: %s - Path: %s - Method: %s - IP: %s - UserAgent: %s",        err.Error(), c.Path(), c.Method(), c.IP(), c.Get("User-Agent"))
    
    // Record failed JWT validation metric
    metrics.RecordJWTValidation(false, "gateway")
    
    return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
        "error":       "Authentication failed",
        "message":     "Invalid or missing JWT token. Please provide a valid Authorization header with Bearer token.",
        "code":        fiber.StatusUnauthorized,
        "timestamp":   time.Now().Format(time.RFC3339),
        "request_id":  c.Get("X-Request-ID", "unknown"),
    })
}

// getUserID estrae l'ID utente dal JWT token
func getUserID(c *fiber.Ctx) string {
    if user := c.Locals("user"); user != nil {
        if token, ok := user.(*jwt.Token); ok {
            if claims, ok := token.Claims.(jwt.MapClaims); ok {
                if id, exists := claims["user_id"]; exists {
                    return fmt.Sprintf("%v", id)
                }
            }
        }
    }
    return "anonymous"
}

// getUserRole estrae il ruolo utente dal JWT token
func getUserRole(c *fiber.Ctx) string {
    if user := c.Locals("user"); user != nil {
        if token, ok := user.(*jwt.Token); ok {
            if claims, ok := token.Claims.(jwt.MapClaims); ok {
                if role, exists := claims["role"]; exists {
                    return fmt.Sprintf("%v", role)
                }
            }
        }
    }
    return "user"
}

// adminOnly middleware per verificare che l'utente sia admin
func adminOnly(c *fiber.Ctx) error {
    role := getUserRole(c)
    if role != "admin" {
        log.Printf("ADMIN_ACCESS_DENIED: user_id=%s role=%s path=%s", getUserID(c), role, c.Path())
        return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
            "error":     "Access denied",
            "message":   "Administrator privileges required to access this resource",
            "code":      fiber.StatusForbidden,
            "timestamp": time.Now().Format(time.RFC3339),
        })
    }
    return c.Next()
}

// Dashboard API protetto - forward con path stripping
app.All("/dashboard/*", func(c *fiber.Ctx) error {
    // Rimuovi /dashboard dal path e forward al dashboard-api
    path := strings.TrimPrefix(c.Path(), "/dashboard")
    if path == "" {
        path = "/"
    }
    target := "http://dashboard-api:3003" + path
    if c.OriginalURL() != c.Path() {
        // Mantieni query parameters
        if strings.Contains(c.OriginalURL(), "?") {
            target += "?" + strings.Split(c.OriginalURL(), "?")[1]
        }
    }
    
    // Aggiungi header personalizzato per identificare richieste dal Gateway
    c.Set("X-Gateway-Request", "gateway-v1.0")
    log.Printf("DASHBOARD_PROXY: %s %s -> %s [IP: %s, User: %s]", 
        c.Method(), c.OriginalURL(), target, c.IP(), getUserID(c))
    return proxy.Do(c, target)
})

// -------------------------------------------------------

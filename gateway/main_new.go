package main

import (
    "encoding/json"
    "fmt"
    "log"
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
)

// JWT secret - deve corrispondere esattamente alla chiave segreta di auth-service
var jwtSecret = []byte("la-tua-chiave-segreta-qui")

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
        }
        
        // Determina il servizio di destinazione
        var service string
        path := c.Path()
        switch {
        case strings.HasPrefix(path, "/auth/"):
            service = "auth-service"
        case strings.HasPrefix(path, "/user/"):
            service = "user-service"
        case strings.HasPrefix(path, "/shop/"):
            service = "shop-service"
        case strings.HasPrefix(path, "/chat/"):
            service = "chat-service"
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

// SecurityHeaders middleware per aggiungere header di sicurezza
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
        },
        ReadTimeout:  10 * time.Second,
        WriteTimeout: 10 * time.Second,
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
        AllowOrigins:     "http://localhost:3000,http://localhost:8080,https://localhost:3000,https://localhost:8080",
        AllowMethods:     "GET,POST,PUT,DELETE,OPTIONS",
        AllowHeaders:     "Origin,Content-Type,Accept,Authorization,X-Request-ID,X-Forwarded-For",
        AllowCredentials: true,
        MaxAge:           86400, // 24 ore
    }))
    
    // Rate limiting globale con diversi limiti per endpoint
    app.Use(limiter.New(limiter.Config{
        Max:        100, // 100 richieste per minuto
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
    
    // Logger completo per richieste/risposte
    app.Use(RequestResponseLogger())

    // -------------------------------------------------------
    // 2) Rotte pubbliche (senza JWT)
    // -------------------------------------------------------
    
    // Rotte di autenticazione - non richiedono JWT
    app.All("/auth/*", func(c *fiber.Ctx) error {
        target := "http://localhost:3001" + c.OriginalURL()
        log.Printf("AUTH_PROXY: %s %s -> %s [IP: %s]", c.Method(), c.OriginalURL(), target, c.IP())
        return proxy.Do(c, target)
    })
    
    // QR code scanning - pubblico (ma potrebbe essere limitato in futuro)
    app.Post("/user/scan-qr", func(c *fiber.Ctx) error {
        target := "http://localhost:3002" + c.OriginalURL()
        log.Printf("QR_SCAN_PROXY: %s %s -> %s [IP: %s]", c.Method(), c.OriginalURL(), target, c.IP())
        return proxy.Do(c, target)
    })
    
    // Health checks pubblici
    app.Get("/health", func(c *fiber.Ctx) error {
        return c.JSON(fiber.Map{
            "status":      "healthy",
            "timestamp":   time.Now().Format(time.RFC3339),
            "gateway":     "v1.0.0",
            "uptime":      time.Since(time.Now()).String(),
            "environment": "development",
            "features": []string{
                "JWT Authentication",
                "Rate Limiting", 
                "Security Headers",
                "Request/Response Logging",
                "CORS Protection",
                "Error Handling",
            },
        })
    })

    // -------------------------------------------------------
    // 3) Middleware JWT per rotte protette
    // -------------------------------------------------------
    
    // Tutte le altre rotte richiedono JWT valido
    app.Use(jwtware.New(jwtware.Config{
        SigningKey:   jwtSecret,
        ErrorHandler: jwtError,
        Filter: func(c *fiber.Ctx) bool {
            // Salta la validazione JWT per rotte pubbliche
            path := c.Path()
            return strings.HasPrefix(path, "/auth/") || 
                   path == "/user/scan-qr" ||
                   path == "/health" ||
                   path == "/"
        },
    }))

    // -------------------------------------------------------
    // 4) Rotte protette con JWT obbligatorio
    // -------------------------------------------------------
    
    // User service protetto
    app.All("/user/*", func(c *fiber.Ctx) error {
        target := "http://localhost:3002" + c.OriginalURL()
        log.Printf("USER_PROXY: %s %s -> %s [IP: %s, User: %s]", 
            c.Method(), c.OriginalURL(), target, c.IP(), getUserID(c))
        return proxy.Do(c, target)
    })

    // Shop service protetto
    app.All("/shop/*", func(c *fiber.Ctx) error {
        target := "http://localhost:3003" + c.OriginalURL()
        log.Printf("SHOP_PROXY: %s %s -> %s [IP: %s, User: %s]", 
            c.Method(), c.OriginalURL(), target, c.IP(), getUserID(c))
        return proxy.Do(c, target)
    })

    // Chat service protetto
    app.All("/chat/*", func(c *fiber.Ctx) error {
        target := "http://localhost:3004" + c.OriginalURL()
        log.Printf("CHAT_PROXY: %s %s -> %s [IP: %s, User: %s]", 
            c.Method(), c.OriginalURL(), target, c.IP(), getUserID(c))
        return proxy.Do(c, target)
    })

    // Rotta di default informativa
    app.Get("/", func(c *fiber.Ctx) error {
        return c.JSON(fiber.Map{
            "message": "🚀 Secure API Gateway v1.0.0",
            "description": "Centralized security and request routing for microservices",
            "routes": map[string]interface{}{
                "public": map[string]string{
                    "/auth/*":        "Authentication service (registration, login)",
                    "/user/scan-qr":  "QR code scanning endpoint",
                    "/health":        "Gateway health check",
                },
                "protected": map[string]string{
                    "/user/*":  "User service (requires JWT)",
                    "/shop/*":  "Shop service (requires JWT)",
                    "/chat/*":  "Chat service (requires JWT)",
                },
            },
            "security_features": []string{
                "JWT Authentication",
                "Rate Limiting (100/min global, 20/min auth)",
                "Security Headers (HSTS, CSP, XSS Protection)",
                "CORS Protection",
                "Request/Response Logging",
                "Error Handling & Recovery",
            },
            "timestamp": time.Now().Format(time.RFC3339),
        })
    })

    // -------------------------------------------------------
    // 5) Avvio del server
    // -------------------------------------------------------
    
    log.Println("🚀 Secure API Gateway v1.0.0 starting...")
    log.Println("📊 Security features enabled:")
    log.Println("   ✅ JWT Authentication")
    log.Println("   ✅ Rate Limiting (100/min global, 20/min auth)")
    log.Println("   ✅ Security Headers (HSTS, CSP, XSS)")
    log.Println("   ✅ CORS Protection")
    log.Println("   ✅ Request/Response Logging")
    log.Println("   ✅ Error Handling & Recovery")
    log.Println("🔒 Protected routes: /user/*, /shop/*, /chat/*")
    log.Println("🌐 Public routes: /auth/*, /user/scan-qr, /health, /")
    log.Println("🎯 Gateway listening on port 3000")
    
    if err := app.Listen(":3000"); err != nil {
        log.Fatal("❌ Failed to start gateway:", err)
    }
}

// jwtError gestisce gli errori di autenticazione JWT
func jwtError(c *fiber.Ctx, err error) error {
    log.Printf("JWT_AUTH_FAILED: %s - Path: %s - Method: %s - IP: %s - UserAgent: %s", 
        err.Error(), c.Path(), c.Method(), c.IP(), c.Get("User-Agent"))
    
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

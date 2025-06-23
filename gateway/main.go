package main

import (
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
    "runtime/debug"
    "strconv"
    "strings"
    "time"

    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/fiber/v2/middleware/cors"
    "github.com/gofiber/fiber/v2/middleware/helmet"
    "github.com/gofiber/fiber/v2/middleware/limiter"
    "github.com/gofiber/fiber/v2/middleware/proxy"
    jwtware "github.com/gofiber/jwt/v3"
    "github.com/golang-jwt/jwt/v4"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "github.com/valyala/fasthttp/fasthttpadaptor"
    
    "go-cloud-backend/shared/metrics"
)

//. JWT secret - loaded from environment variable JWT_SECRET
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

// .LogEntry rappresentaa una voce di log strutturata
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
                    if id, exists := claims["user_id"]; exists && id != nil {
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

// Get user ID from JWT token
func getUserID(c *fiber.Ctx) string {
    user := c.Locals("user")
    if user == nil {
        log.Printf("WARNING: getUserID called but c.Locals('user') is nil for path %s", c.Path())
        return "unknown"
    }
    
    token, ok := user.(*jwt.Token)
    if !ok {
        log.Printf("WARNING: getUserID called but user is not a JWT token for path %s", c.Path())
        return "unknown"
    }
    
    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
        log.Printf("WARNING: getUserID called but claims are not MapClaims for path %s", c.Path())
        return "unknown"
    }
    
    if userID, exists := claims["user_id"]; exists && userID != nil {
        return fmt.Sprintf("%v", userID)
    }
    
    log.Printf("WARNING: getUserID called but user_id claim not found for path %s", c.Path())
    return "unknown"
}

// Get user role from JWT token
func getUserRole(c *fiber.Ctx) string {
    user := c.Locals("user")
    if user == nil {
        log.Printf("WARNING: getUserRole called but c.Locals('user') is nil for path %s", c.Path())
        return "user"
    }
    
    token, ok := user.(*jwt.Token)
    if !ok {
        log.Printf("WARNING: getUserRole called but user is not a JWT token for path %s", c.Path())
        return "user"
    }
    
    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
        log.Printf("WARNING: getUserRole called but claims are not MapClaims for path %s", c.Path())
        return "user"
    }
    
    if role, exists := claims["role"]; exists && role != nil {
        return fmt.Sprintf("%v", role)
    }
    
    return "user"
}

// Middleware per controllare ruolo admin
func adminOnly(c *fiber.Ctx) error {
    role := getUserRole(c)
    userID := getUserID(c)
    
    if role != "admin" {
        log.Printf("ADMIN_ACCESS_DENIED: User %s with role '%s' tried to access admin endpoint %s", 
            userID, role, c.Path())
        
        return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
            "error": "Access denied. Admin role required.",
            "code":  "ADMIN_REQUIRED",
        })
    }
    
    log.Printf("ADMIN_ACCESS_GRANTED: Admin %s accessing %s", userID, c.Path())
    return c.Next()
}

// jwtError handles JWT authentication errors
func jwtError(c *fiber.Ctx, err error) error {
    defer func() {
        if r := recover(); r != nil {
            log.Printf("PANIC in jwtError: %v\n%s", r, debug.Stack())
        }
    }()
    
    // Safe logging with nil checks
    method := "UNKNOWN"
    path := "UNKNOWN"
    ip := "UNKNOWN"
    if c != nil {
        method = c.Method()
        path = c.Path()
        ip = c.IP()
    }
    
    errorMsg := "Unknown JWT error"
    if err != nil {
        errorMsg = err.Error()
    }
    
    log.Printf("JWT_ERROR: %s on %s %s from IP %s", errorMsg, method, path, ip)
    
    // Safe headers logging
    if c != nil {
        headers := make(map[string]string)
        reqHeaders := c.GetReqHeaders()
        if reqHeaders != nil {
            for k, v := range reqHeaders {
                if k == "Authorization" && len(v) > 0 {
                    headers[k] = "[REDACTED]"
                } else if len(v) > 0 {
                    headers[k] = strings.Join(v, ",")
                }
            }
        }
        log.Printf("JWT_ERROR_DETAILS: Method=%s, Path=%s, Headers=%v", method, path, headers)
    }
    
    // Record metrics safely
    metrics.RecordJWTValidation(false, "gateway")
    
    // Return a proper JSON error response
    if c != nil {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
            "error": "Token non valido o mancante",
            "code":  "JWT_INVALID",
            "details": errorMsg,
        })
    }
    
    return fmt.Errorf("JWT error: %s", errorMsg)
}

func main() {
    log.Printf("GATEWAY STARTUP: Starting gateway with nil pointer fix - Build Time: %s", time.Now().Format(time.RFC3339))
      // Load JWT secret from environment
    jwtSecretStr := os.Getenv("JWT_SECRET")
    if jwtSecretStr == "" {
        log.Fatal("JWT_SECRET environment variable is required")
    }
    jwtSecret = []byte(jwtSecretStr)
    
    // Initialize Prometheus metrics
    metrics.InitMetrics()
    
    app := fiber.New(fiber.Config{
        EnableTrustedProxyCheck: true,
        TrustedProxies:          []string{"127.0.0.1", "::1"},
        ProxyHeader:             fiber.HeaderXForwardedFor,
    })

    // PANIC RECOVERY MIDDLEWARE - MUST BE FIRST
    app.Use(func(c *fiber.Ctx) error {
        defer func() {
            if r := recover(); r != nil {
                log.Printf("[PANIC_HANDLER] PANIC RECOVERED: %v\n%s\n[REQUEST] Method=%s Path=%s IP=%s Body=%s Headers=%v", r, debug.Stack(), c.Method(), c.Path(), c.IP(), string(c.Body()), c.GetReqHeaders())
                // Risposta JSON coerente per panic
                _ = c.Status(500).JSON(fiber.Map{
                    "error":   "Errore interno del gateway (panic)",
                    "code":    "GATEWAY_PANIC",
                    "details": fmt.Sprintf("%v", r),
                })
            }
        }()
        return c.Next()
    })

    // CORS middleware
    app.Use(cors.New(cors.Config{
        AllowOrigins:     "*",
        AllowMethods:     "GET,POST,HEAD,PUT,DELETE,PATCH,OPTIONS",
        AllowHeaders:     "Origin, Content-Type, Accept, Authorization, X-Requested-With",
        AllowCredentials: false,
    }))    // Security middleware
    app.Use(helmet.New())

    // Rate limiter globale (per tutte le route)
    app.Use(limiter.New(limiter.Config{
        Max:        100,
        Expiration: 1 * time.Minute,
        KeyGenerator: func(c *fiber.Ctx) string {
            return c.IP()
        },
        LimitReached: func(c *fiber.Ctx) error {
            return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
                "error": "Rate limit exceeded",
            })
        },
    }))

    // Rate limiter più restrittivo solo per /login
    app.Post("/login",
        limiter.New(limiter.Config{
            Max:        5, // Limite molto più basso per login
            Expiration: 1 * time.Minute,
            KeyGenerator: func(c *fiber.Ctx) string {
                return c.IP()
            },
            LimitReached: func(c *fiber.Ctx) error {
                return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
                    "error": "Too many login attempts, try again later",
                })
            },
        }),
        func(c *fiber.Ctx) error {
            // Proxy la richiesta al servizio di autenticazione
            target := "http://auth-service:8080/login"
            return proxy.Do(c, target)
        },
    )

    // Request/Response logging
    app.Use(RequestResponseLogger())

    // Metrics middleware
    app.Use(func(c *fiber.Ctx) error {
        start := time.Now()
        
        err := c.Next()
        
        // Record proxy metrics based on path
        targetService := getTargetService(c.Path())
        if targetService != "gateway" {
            statusCode := strconv.Itoa(c.Response().StatusCode())
            metrics.RecordProxyRequest(targetService, statusCode)
        }        // Record request duration  
        _ = time.Since(start) // Use start to avoid "declared and not used" error
        // metrics.RecordRequestDuration(c.Method(), c.Route().Path, c.Response().StatusCode(), duration)
        
        return err
    })

    // --------------------------------------------------------
    // 1) Public routes (no JWT required)
    // -------------------------------------------------------

    // Health check
    app.Get("/health", func(c *fiber.Ctx) error {
        return c.JSON(fiber.Map{
            "status":    "healthy",
            "service":   "gateway",
            "timestamp": time.Now().Format(time.RFC3339),
            "version":   "1.0.0",
        })
    })

    // Gateway metrics endpoint
    app.Get("/metrics", func(c *fiber.Ctx) error {
        // Wrap Prometheus handler for Fiber
        handler := fasthttpadaptor.NewFastHTTPHandler(promhttp.Handler())
        handler(c.Context())
        return nil
    })

    // Auth routes (no JWT required)
    app.All("/auth/*", func(c *fiber.Ctx) error {
        log.Printf("TRACE: INIZIO handler /auth/*")
        defer func() {
            if r := recover(); r != nil {
                log.Printf("[PANIC_HANDLER] PANIC in /auth/*: %v\n%s\n[REQUEST] Method=%s Path=%s IP=%s Body=%s Headers=%v", r, debug.Stack(), c.Method(), c.Path(), c.IP(), string(c.Body()), c.GetReqHeaders())
                _ = c.Status(500).JSON(fiber.Map{
                    "error":   "Errore interno del gateway (panic)",
                    "code":    "GATEWAY_PANIC_AUTH",
                    "details": fmt.Sprintf("%v", r),
                })
            }
        }()
        log.Printf("TRACE: dopo defer recover, prima strip prefix")
        newPath := strings.TrimPrefix(c.OriginalURL(), "/auth")
        if newPath == "" {
            newPath = "/"
        }
        log.Printf("TRACE: dopo strip prefix, newPath=%s", newPath)
        target := "http://auth-service:3001" + newPath
        c.Set("X-Gateway-Request", "gateway-v1.0")
        log.Printf("TRACE: prima HTTP NewRequest, target=%s", target)
        reqBody := c.Body()
        req, err := http.NewRequest(c.Method(), target, strings.NewReader(string(reqBody)))
        if err != nil {
            log.Printf("[ERROR_500] AUTH_PROXY NewRequest error: %v", err)
            return c.Status(502).SendString("Gateway error: " + err.Error())
        }
        log.Printf("TRACE: dopo HTTP NewRequest")
        c.Request().Header.VisitAll(func(k, v []byte) {
            req.Header.Set(string(k), string(v))
        })
        log.Printf("TRACE: dopo copia headers")
        client := &http.Client{}
        resp, err := client.Do(req)
        if err != nil {
            log.Printf("[ERROR_500] AUTH_PROXY client.Do error: %v", err)
            return c.Status(502).SendString("Gateway error: " + err.Error())
        }
        log.Printf("TRACE: dopo client.Do, status=%d", resp.StatusCode)
        defer resp.Body.Close()
        respBody, readErr := io.ReadAll(resp.Body)
        if readErr != nil {
            log.Printf("[ERROR_500] AUTH_PROXY io.ReadAll error: %v", readErr)
        }
        log.Printf("TRACE: dopo io.ReadAll, body=%s", string(respBody))
        log.Printf("[AUTH_PROXY] Response from auth-service: status=%d, body=%s", resp.StatusCode, string(respBody))
        // Copy headers from upstream BEFORE sending the body
        for k, vals := range resp.Header {
            for _, v := range vals {
                c.Set(k, v)
            }
        }
        log.Printf("TRACE: dopo copia headers da upstream")
        // Send the response body and return (NO SetBodyRaw!)
        log.Printf("TRACE: prima di return c.Status(resp.StatusCode).Send(respBody)")
        log.Printf("TRACE: fine handler /auth/*")
        return c.Status(resp.StatusCode).Send(respBody)
    })    // -------------------------------------------------------
    // 2) JWT middleware for protected routes
    // -------------------------------------------------------
    
    // Add debugging middleware before JWT
    app.Use(func(c *fiber.Ctx) error {
        path := c.Path()
        authHeader := c.Get("Authorization")
        log.Printf("DEBUG_REQUEST: Method=%s, Path=%s, HasAuth=%v", c.Method(), path, authHeader != "")
        
        // Check if this should be a protected route
        isPublic := strings.HasPrefix(path, "/auth/") || path == "/health" || path == "/metrics"
        log.Printf("DEBUG_ROUTE: Path=%s, IsPublic=%v", path, isPublic)
        
        return c.Next()
    })
    
    app.Use(jwtware.New(jwtware.Config{
        SigningKey:   jwtSecret,
        ErrorHandler: jwtError,
        Filter: func(c *fiber.Ctx) bool {
            // Skip JWT validation for public routes
            path := c.Path()
            shouldSkip := strings.HasPrefix(path, "/auth/") ||
                         path == "/health" ||
                         path == "/metrics"
            log.Printf("DEBUG_JWT_FILTER: Path=%s, ShouldSkip=%v", path, shouldSkip)
            return shouldSkip
        },
        SuccessHandler: func(c *fiber.Ctx) error {
            // Record successful JWT validation
            log.Printf("DEBUG_JWT_SUCCESS: Path=%s", c.Path())
            metrics.RecordJWTValidation(true, "gateway")
            return c.Next()
        },
    }))

    // -------------------------------------------------------
    // 3) Protected user routes (JWT required)
    // -------------------------------------------------------    // Specific user routes BEFORE the general /user/* catch-all
    app.Get("/user/profile", func(c *fiber.Ctx) error {
        log.Printf("DEBUG_PROFILE_START: Entering /user/profile handler")
        
        // SAFETY CHECK: Ensure JWT validation succeeded
        user := c.Locals("user")
        if user == nil {
            log.Printf("DEBUG_PROFILE_ERROR: No JWT user in locals - unauthorized access attempt")
            return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
                "error": "Token non valido o mancante",
                "code":  "JWT_REQUIRED",
            })
        }
        
        log.Printf("DEBUG_PROFILE_JWT_VALID: JWT user found in locals, proceeding")
        
        target := "http://user-service:3002/profile"
        log.Printf("DEBUG_PROFILE_TARGET: Target set to %s", target)
        
        c.Set("X-Gateway-Request", "gateway-v1.0")
        log.Printf("DEBUG_PROFILE_HEADER: Set X-Gateway-Request header")
          // Pass JWT claims as headers to user-service
        log.Printf("DEBUG_PROFILE_JWT_START: Starting JWT processing")
        // We already validated user is not nil above
        token, ok := user.(*jwt.Token)
        if !ok {
            log.Printf("DEBUG_PROFILE_JWT_ERROR: Token cast failed")
            return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
                "error": "Token invalido",
                "code":  "JWT_INVALID_FORMAT",
            })
        }
        
        log.Printf("DEBUG_PROFILE_JWT_TOKEN: Token cast successful")
        claims, ok := token.Claims.(jwt.MapClaims)
        if !ok {
            log.Printf("DEBUG_PROFILE_JWT_ERROR: Claims cast failed")
            return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
                "error": "Token claims invalidi",
                "code":  "JWT_INVALID_CLAIMS",
            })
        }
        
        log.Printf("DEBUG_PROFILE_JWT_CLAIMS: Claims cast successful")
        if userID, exists := claims["user_id"]; exists {
            c.Set("X-User-ID", fmt.Sprintf("%v", userID))
            log.Printf("DEBUG_PROFILE_USERID: Set X-User-ID = %v", userID)
        }
        if email, exists := claims["email"]; exists {
            c.Set("X-User-Email", fmt.Sprintf("%v", email))
            log.Printf("DEBUG_PROFILE_EMAIL: Set X-User-Email = %v", email)
        }
        if role, exists := claims["role"]; exists {
            c.Set("X-User-Role", fmt.Sprintf("%v", role))
            log.Printf("DEBUG_PROFILE_ROLE: Set X-User-Role = %v", role)
        }
        if name, exists := claims["name"]; exists {
            c.Set("X-User-Name", fmt.Sprintf("%v", name))
            log.Printf("DEBUG_PROFILE_NAME: Set X-User-Name = %v", name)
        }
        log.Printf("DEBUG_PROFILE_JWT_END: JWT processing completed")
        
        log.Printf("DEBUG_PROFILE_PROXY_START: About to call proxy")
        log.Printf("USER_PROFILE_PROXY: %s %s -> %s [IP: %s, User: %s]", 
            c.Method(), c.OriginalURL(), target, c.IP(), getUserID(c))
        
        log.Printf("DEBUG_PROFILE_PROXY_CALL: Calling proxy.Do")
        err := proxy.Do(c, target)
        log.Printf("DEBUG_PROFILE_PROXY_RESULT: proxy.Do returned, err = %v", err)
        return err
    })    // QR User routes (JWT protected)
    app.Post("/user/qr/scan", func(c *fiber.Ctx) error {
        // Safety check for JWT validation
        if c.Locals("user") == nil {
            return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
                "error": "Token non valido o mancante",
                "code":  "JWT_REQUIRED",
            })
        }
        
        target := "http://user-service:3002/qr/scan"
        c.Set("X-Gateway-Request", "gateway-v1.0")
        log.Printf("QR_SCAN_AUTH_PROXY: %s %s -> %s [IP: %s, User: %s]", 
            c.Method(), c.OriginalURL(), target, c.IP(), getUserID(c))
        return proxy.Do(c, target)
    })

    app.Get("/user/qr/attendance/history", func(c *fiber.Ctx) error {
        // Safety check for JWT validation
        if c.Locals("user") == nil {
            return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
                "error": "Token non valido o mancante",
                "code":  "JWT_REQUIRED",
            })
        }
        
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
        // Safety check for JWT validation
        if c.Locals("user") == nil {
            return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
                "error": "Token non valido o mancante",
                "code":  "JWT_REQUIRED",
            })
        }
        
        target := "http://user-service:3002/qr/attendance/today"
        c.Set("X-Gateway-Request", "gateway-v1.0")
        log.Printf("QR_TODAY_PROXY: %s %s -> %s [IP: %s, User: %s]", 
            c.Method(), c.OriginalURL(), target, c.IP(), getUserID(c))
        return proxy.Do(c, target)
    })

    // General user routes (catch-all for other /user/* routes)
    app.All("/user/*", func(c *fiber.Ctx) error {
        defer func() {
            if r := recover(); r != nil {
                log.Printf("[PANIC_HANDLER] PANIC in /user/*: %v\n%s\n[REQUEST] Method=%s Path=%s IP=%s Body=%s Headers=%v", r, debug.Stack(), c.Method(), c.Path(), c.IP(), string(c.Body()), c.GetReqHeaders())
                c.Status(500).SendString(fmt.Sprintf("Panic recovered: %v", r))
            }
        }()
        // Safety check for JWT validation
        if c.Locals("user") == nil {
            log.Printf("[ERROR_500] /user/* unauthorized: JWT missing [REQUEST] Method=%s Path=%s IP=%s Body=%s Headers=%v", c.Method(), c.Path(), c.IP(), string(c.Body()), c.GetReqHeaders())
            return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
                "error": "Token non valido o mancante",
                "code":  "JWT_REQUIRED",
            })
        }
        
        // Strip /user prefix and forward to user-service
        path := strings.TrimPrefix(c.Path(), "/user")
        if path == "" {
            path = "/"
        }
        target := "http://user-service:3002" + path
        if c.OriginalURL() != c.Path() {
            // Preserve query parameters
            if strings.Contains(c.OriginalURL(), "?") {
                target += "?" + strings.Split(c.OriginalURL(), "?")[1]
            }
        }
        c.Set("X-Gateway-Request", "gateway-v1.0")
        log.Printf("USER_PROXY: %s %s -> %s [IP: %s, User: %s]", c.Method(), c.OriginalURL(), target, c.IP(), getUserID(c))
        err := proxy.Do(c, target)
        if err != nil {
            log.Printf("[ERROR_500] USER_PROXY error: %v [REQUEST] Method=%s Path=%s IP=%s Body=%s Headers=%v", err, c.Method(), c.Path(), c.IP(), string(c.Body()), c.GetReqHeaders())
        }
        return err
    })

    // -------------------------------------------------------
    // 4) Admin routes (JWT + admin role required)
    // -------------------------------------------------------

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

    // -------------------------------------------------------
    // 5) Analytics/Monitoring routes (JWT + admin role required)
    // -------------------------------------------------------

    // Dashboard API proxy
    app.All("/dashboard/*", adminOnly, func(c *fiber.Ctx) error {
        // Strip /dashboard prefix and forward to dashboard-api
        path := strings.TrimPrefix(c.Path(), "/dashboard")
        if path == "" {
            path = "/"
        }
        target := "http://dashboard-api:3003" + path
        if c.OriginalURL() != c.Path() && strings.Contains(c.OriginalURL(), "?") {
            target += "?" + strings.Split(c.OriginalURL(), "?")[1]
        }
        
        c.Set("X-Gateway-Request", "gateway-v1.0")
        log.Printf("DASHBOARD_PROXY: %s %s -> %s [IP: %s, Admin: %s]", 
            c.Method(), c.OriginalURL(), target, c.IP(), getUserID(c))
        return proxy.Do(c, target)
    })

    // Prometheus monitoring proxy
    app.All("/monitoring/*", adminOnly, func(c *fiber.Ctx) error {
        // Strip /monitoring prefix and forward to prometheus-service
        path := strings.TrimPrefix(c.Path(), "/monitoring")
        if path == "" {
            path = "/"
        }
        target := "http://prometheus-service:9090" + path
        if c.OriginalURL() != c.Path() && strings.Contains(c.OriginalURL(), "?") {
            target += "?" + strings.Split(c.OriginalURL(), "?")[1]
        }
        
        c.Set("X-Gateway-Request", "gateway-v1.0")
        log.Printf("MONITORING_PROXY: %s %s -> %s [IP: %s, Admin: %s]", 
            c.Method(), c.OriginalURL(), target, c.IP(), getUserID(c))
        return proxy.Do(c, target)
    })

    // Proxy per /api/dashboard/vm-health
    app.All("/api/dashboard/vm-health", func(c *fiber.Ctx) error {
        target := "http://dashboard-api:3003/api/dashboard/vm-health"
        log.Printf("DASHBOARD_VM_HEALTH_PROXY: %s %s -> %s [IP: %s]", c.Method(), c.OriginalURL(), target, c.IP())
        return proxy.Do(c, target)
    })

    // Proxy per /api/dashboard/security
    app.All("/api/dashboard/security", func(c *fiber.Ctx) error {
        target := "http://dashboard-api:3003/api/dashboard/security"
        log.Printf("DASHBOARD_SECURITY_PROXY: %s %s -> %s [IP: %s]", c.Method(), c.OriginalURL(), target, c.IP())
        return proxy.Do(c, target)
    })

    // Proxy for /api/social/log to social-log-service
    app.All("/api/social/log", func(c *fiber.Ctx) error {
        target := "http://social-log-service:8080/api/social/log"
        log.Printf("SOCIAL_LOG_PROXY: %s %s -> %s [IP: %s]", c.Method(), c.OriginalURL(), target, c.IP())
        return proxy.Do(c, target)
    })

    // -------------------------------------------------------
    // Start server
    // -------------------------------------------------------

    log.Println("🚀 Gateway Service avviato sulla porta 3000")
    log.Println("🔓 Public routes: /auth/*, /health, /metrics")
    log.Println("🔒 Protected routes: /user/*, /admin/*")
    log.Println("📱 QR User routes: /user/qr/scan, /user/qr/attendance/* (JWT protected)")
    log.Println("👑 QR Admin routes: /user/qr/admin/* (admin role required)")
    log.Println("📊 Analytics routes: /dashboard/*, /monitoring/* (admin role required)")
    log.Fatal(app.Listen(":3000"))
}

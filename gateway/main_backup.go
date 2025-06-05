package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "os"
    "strings"
    "time"

    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/fiber/v2/middleware/cors"
    "github.com/gofiber/fiber/v2/middleware/helmet"
    "github.com/gofiber/fiber/v2/middleware/limiter"
    "github.com/gofiber/fiber/v2/middleware/logger"
    "github.com/gofiber/fiber/v2/middleware/proxy"
    "github.com/gofiber/fiber/v2/middleware/recover"
    jwtware "github.com/gofiber/jwt/v3"
    "github.com/golang-jwt/jwt/v4"
)

// Deve corrispondere esattamente alla chiave segreta di auth-service
var jwtSecret = []byte("la-tua-chiave-segreta-qui")

// LogEntry rappresenta una voce di log strutturata
type LogEntry struct {
    Timestamp   string            `json:"timestamp"`
    Method      string            `json:"method"`
    Path        string            `json:"path"`
    StatusCode  int               `json:"status_code"`
    Duration    string            `json:"duration"`
    IP          string            `json:"ip"`
    UserAgent   string            `json:"user_agent"`
    RequestID   string            `json:"request_id"`
    UserID      string            `json:"user_id,omitempty"`
    Headers     map[string]string `json:"headers"`
    RequestBody string            `json:"request_body,omitempty"`
    ResponseBody string           `json:"response_body,omitempty"`
    Error       string            `json:"error,omitempty"`
}

// RequestResponseLogger middleware per il logging completo
func RequestResponseLogger() fiber.Handler {
    return func(c *fiber.Ctx) error {
        start := time.Now()
        requestID := c.Get("X-Request-ID")
        if requestID == "" {
            requestID = fmt.Sprintf("%d-%s", time.Now().UnixNano(), c.IP())
        }
        
        // Leggi il body della richiesta
        var requestBody string
        if c.Body() != nil {
            requestBody = string(c.Body())
        }
        
        // Cattura headers importanti
        headers := make(map[string]string)
        headers["Content-Type"] = c.Get("Content-Type")
        headers["Authorization"] = c.Get("Authorization")
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
        
        // Processa la richiesta
        err := c.Next()
        
        duration := time.Since(start)
        
        // Cattura il body della risposta se è JSON
        var responseBody string
        if strings.Contains(c.Get("Content-Type"), "application/json") {
            responseBody = string(c.Response().Body())
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
        c.Set("Content-Security-Policy", "default-src 'self'")
        return c.Next()
    }
}

func main() {
    app := fiber.New()

    // -------------------------------------------------------
    // 1) Middleware globale per validare il JWT in ingresso
    // -------------------------------------------------------
    // Tutte le rotte “protette” passeranno da qui: controlla che il token sia valido,
    // che non sia scaduto e che la firma corrisponda.
    app.Use(jwtware.New(jwtware.Config{
        SigningKey:   jwtSecret,
        ErrorHandler: jwtError, // funzione personalizzata per gestire errori JWT
    }))

    // -------------------------------------------------------
    // 2) Configurazione delle rotte proxy
    // -------------------------------------------------------
    // Inoltra tutto ciò che arriva su /user/* verso user-service (porta 3002)
    app.All("/user/*", func(c *fiber.Ctx) error {
        // Costruisci l’URL di destinazione: mantieni il path completo (/user/…)
        target := "http://localhost:3002" + c.OriginalURL()
        // Inoltra la richiesta con tutti gli header (incluso Authorization)
        return proxy.Do(c, target)
    })

    // Inoltra tutto ciò che arriva su /shop/* verso shop-service (porta 3003)
    app.All("/shop/*", func(c *fiber.Ctx) error {
        target := "http://localhost:3003" + c.OriginalURL()
        return proxy.Do(c, target)
    })

    // Inoltra tutto ciò che arriva su /chat/* verso chat-service (porta 3004)
    app.All("/chat/*", func(c *fiber.Ctx) error {
        target := "http://localhost:3004" + c.OriginalURL()
        return proxy.Do(c, target)
    })

    // Rotta di default (opzionale): se qualcuno chiama la root, possiamo rispondere con un messaggio informativo
    app.Get("/", func(c *fiber.Ctx) error {
        return c.JSON(fiber.Map{
            "message": "Gateway attivo. Rotte: /user/*, /shop/*, /chat/* (richiede JWT)",
        })
    })

    log.Println("Gateway in ascolto sulla porta 3000")
    if err := app.Listen(":3000"); err != nil {
        log.Fatal(err)
    }
}

// jwtError viene invocata se il token non è valido o è assente.
// Possiamo restituire un JSON con errore 401.
func jwtError(c *fiber.Ctx, err error) error {
    return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
        "error": "Accesso negato: token non valido o mancante",
    })
}

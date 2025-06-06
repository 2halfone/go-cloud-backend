package main

import (
    "log"
    "net/mail"
    "os"
    "strings"
    "time"

    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/fiber/v2/middleware/cors"
    jwtware "github.com/gofiber/jwt/v3"
    "github.com/golang-jwt/jwt/v4"
    "golang.org/x/crypto/bcrypt"
)

// JWT secret - loaded from environment variable JWT_SECRET
var jwtSecret []byte

// User rappresenta un utente registrato (per semplicità, memorizzato in memoria)
type User struct {
    Email    string
    Password string // hashed
}

// In-memory store molto semplice (map da email → User)
var users = map[string]User{}

// Helper function per debug logging
func getMapKeys(m map[string]User) []string {
    keys := make([]string, 0, len(m))
    for k := range m {
        keys = append(keys, k)
    }
    return keys
}

// request payload per /register
type registerRequest struct {
    Email    string `json:"email"`
    Username string `json:"username"` // supporta anche username
    Password string `json:"password"`
}

func registerHandler(c *fiber.Ctx) error {
    var req registerRequest
    if err := c.BodyParser(&req); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Payload non valido",
        })    }    // TrimSpace su email, username e password
    req.Email = strings.TrimSpace(req.Email)
    req.Username = strings.TrimSpace(req.Username)
    req.Password = strings.TrimSpace(req.Password)

    // Supporta sia email che username come identificatore
    // Priorità: username se fornito, altrimenti email
    var identifier string
    if req.Username != "" {
        identifier = req.Username
    } else if req.Email != "" {
        identifier = req.Email
    } else {
        return c.Status(400).JSON(fiber.Map{
            "error": "Email o username richiesti",
        })
    }

    // Validazione formato email se email è fornita
    if req.Email != "" {
        if _, err := mail.ParseAddress(req.Email); err != nil {
            return c.Status(400).JSON(fiber.Map{
                "error": "Formato email non valido",
            })
        }
    }

    // Validazione password vuota
    if req.Password == "" {
        return c.Status(400).JSON(fiber.Map{
            "error": "Password non può essere vuota",
        })
    }    // Controlla se l'utente esiste già (usa identifier che può essere email o username)
    if _, exists := users[identifier]; exists {
        return c.Status(fiber.StatusConflict).JSON(fiber.Map{
            "error": "Utente già registrato",
        })
    }

    // Hash della password
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Errore server nel processare la password",
        })    }

    // Salva l'utente in memoria (usa identifier come chiave)
    users[identifier] = User{
        Email:    identifier, // identifier può essere email o username
        Password: string(hashedPassword),
    }

    log.Printf("REGISTER_SUCCESS: identifier='%s', users_count=%d", identifier, len(users))

    return c.Status(fiber.StatusCreated).JSON(fiber.Map{
        "message": "Registrazione avvenuta con successo",
    })
}

// request payload per /login
type loginRequest struct {
    Email    string `json:"email"`
    Username string `json:"username"` // supporta anche username
    Password string `json:"password"`
}

func loginHandler(c *fiber.Ctx) error {
    var req loginRequest
    if err := c.BodyParser(&req); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Payload non valido",
        })
    }    // Supporta sia email che username come identificatore per login
    // Priorità: username se fornito, altrimenti email
    var identifier string
    if req.Username != "" {
        identifier = req.Username
    } else if req.Email != "" {
        identifier = req.Email
    } else {
        return c.Status(400).JSON(fiber.Map{
            "error": "Email o username richiesti",
        })
    }

    log.Printf("LOGIN_DEBUG: identifier='%s', users_keys=%v", identifier, getMapKeys(users))

    // Controlla se l'utente esiste
    user, exists := users[identifier]
    if !exists {
        log.Printf("LOGIN_FAILED: identifier '%s' not found in users map", identifier)
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
            "error": "Credenziali errate",
        })
    }

    // Verifica password
    if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
            "error": "Credenziali errate",
        })
    }    // Genera JWT
    token := jwt.New(jwt.SigningMethodHS256)
    claims := token.Claims.(jwt.MapClaims)
    claims["email"] = user.Email // mantiene email per compatibilità
    claims["user_id"] = identifier // aggiunge user_id che può essere email o username
    claims["identifier"] = identifier // campo esplicito per l'identificatore usato
    claims["exp"] = time.Now().Add(24 * time.Hour).Unix() // scade dopo 24h

    tokenString, err := token.SignedString(jwtSecret)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Impossibile generare il token",
        })
    }

    return c.JSON(fiber.Map{
        "token": tokenString,
    })
}

// gatewayOnly middleware per accettare solo richieste dal Gateway
func gatewayOnly(c *fiber.Ctx) error {
    // Verifica che la richiesta provenga dal Gateway
    xForwardedFor := c.Get("X-Forwarded-For")
    userAgent := c.Get("User-Agent")
    
    // Il Gateway dovrebbe aggiungere un header personalizzato
    gatewayHeader := c.Get("X-Gateway-Request")
    
    // Accetta se ha l'header del Gateway o se è una richiesta localhost (per sviluppo)
    if gatewayHeader == "gateway-v1.0" || 
       strings.Contains(c.Get("Origin"), "localhost:3000") ||
       c.IP() == "127.0.0.1" || c.IP() == "::1" {
        return c.Next()
    }
    
    log.Printf("UNAUTHORIZED_DIRECT_ACCESS: IP=%s UserAgent=%s XForwardedFor=%s Origin=%s", 
        c.IP(), userAgent, xForwardedFor, c.Get("Origin"))
    
    return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
        "error": "Accesso diretto non consentito. Utilizzare il Gateway.",
        "code":  "DIRECT_ACCESS_FORBIDDEN",
    })
}

func main() {
    // Load JWT secret from environment variable
    jwtSecretEnv := os.Getenv("JWT_SECRET")
    if jwtSecretEnv == "" {
        log.Fatal("JWT_SECRET environment variable not set")    }
    jwtSecret = []byte(jwtSecretEnv)

    app := fiber.New()

    // CORS restrittivo - accetta solo richieste dal Gateway
    app.Use(cors.New(cors.Config{
        AllowOrigins:     "http://localhost:3000", // Solo dal Gateway
        AllowMethods:     "GET,POST,PUT,DELETE,OPTIONS",
        AllowHeaders:     "Origin,Content-Type,Accept,Authorization,X-Request-ID,X-Forwarded-For,X-Gateway-Request",
        AllowCredentials: true,
        MaxAge:           300, // 5 minuti
    }))

    // Middleware per bloccare accessi diretti (opzionale in sviluppo)
    // app.Use(gatewayOnly)

    // Health endpoint (pubblico)
    app.Get("/health", func(c *fiber.Ctx) error {
        return c.JSON(fiber.Map{
            "status":    "healthy",
            "service":   "auth-service",
            "timestamp": time.Now(),
        })
    })

    // Endpoint per registrare un nuovo utente
    app.Post("/register", registerHandler)

    // Endpoint per autenticare e ricevere token
    app.Post("/login", loginHandler)

    // Middleware JWT per proteggere le rotte successive
    app.Use("/protected", jwtware.New(jwtware.Config{
        SigningKey: jwtSecret,
    }))

    // Endpoint protetto che richiede autenticazione
    app.Get("/protected/profile", func(c *fiber.Ctx) error {
        user := c.Locals("user").(*jwt.Token)
        claims := user.Claims.(jwt.MapClaims)
        email := claims["email"].(string)

        return c.JSON(fiber.Map{
            "message": "Accesso autorizzato",
            "email":   email,
        })
    })

    log.Println("Auth-service in ascolto sulla porta 3001")
    if err := app.Listen(":3001"); err != nil {
        log.Fatal(err)
    }
}

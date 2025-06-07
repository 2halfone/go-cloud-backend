package main

import (
    "auth-service/database"
    "database/sql"
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

// User rappresenta un utente registrato nel database PostgreSQL
type User struct {
    ID        int       `json:"id"`
    Email     string    `json:"email"`
    Username  string    `json:"username,omitempty"`
    Password  string    `json:"-"` // hashed, non esposto nel JSON
    CreatedAt time.Time `json:"created_at"`
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

    // Validazione formato email se email è fornita
    if req.Email != "" {
        if _, err := mail.ParseAddress(req.Email); err != nil {
            return c.Status(400).JSON(fiber.Map{
                "error": "Formato email non valido",
            })
        }
    }    // Validazione password (minimo 6 caratteri per Flutter)
    if len(req.Password) < 6 {
        return c.Status(400).JSON(fiber.Map{
            "error": "Password deve essere di almeno 6 caratteri",
            "code":  "PASSWORD_TOO_SHORT",
        })
    }

    // Controlla se l'utente esiste già nel database PostgreSQL
    var existingID int
    checkQuery := "SELECT id FROM users WHERE email = $1 OR username = $2"
    err := database.DB.QueryRow(checkQuery, req.Email, req.Username).Scan(&existingID)
    if err != sql.ErrNoRows {
        log.Printf("REGISTER_ERROR: User already exists - email=%s, username=%s", req.Email, req.Username)
        return c.Status(fiber.StatusConflict).JSON(fiber.Map{
            "error": "Utente già registrato",
            "code":  "USER_EXISTS",
        })
    }

    // Hash della password
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
    if err != nil {
        log.Printf("REGISTER_ERROR: Password hashing failed - %v", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Errore server nel processare la password",
            "code":  "HASH_ERROR",
        })
    }

    // Salva l'utente nel database PostgreSQL
    insertQuery := `
        INSERT INTO users (email, username, password, created_at) 
        VALUES ($1, $2, $3, $4) 
        RETURNING id, created_at`

    var userID int
    var createdAt time.Time
    err = database.DB.QueryRow(insertQuery, req.Email, req.Username, string(hashedPassword), time.Now()).
        Scan(&userID, &createdAt)

    if err != nil {
        log.Printf("REGISTER_ERROR: Database insert failed - %v", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Errore nel salvare l'utente",
            "code":  "DATABASE_ERROR",
        })
    }

    log.Printf("REGISTER_SUCCESS: user_id=%d, email=%s, username=%s", userID, req.Email, req.Username)

    return c.Status(fiber.StatusCreated).JSON(fiber.Map{
        "message": "Registrazione avvenuta con successo",
        "user": fiber.Map{
            "id":         userID,
            "email":      req.Email,
            "username":   req.Username,
            "created_at": createdAt,
        },
        "code": "REGISTER_SUCCESS",
    })
}

// request payload per /login
type loginRequest struct {
    Email    string `json:"email"`
    Username string `json:"username"` // supporta anche username
    Password string `json:"password"`
}

func loginHandler(c *fiber.Ctx) error {    var req loginRequest
    if err := c.BodyParser(&req); err != nil {
        log.Printf("LOGIN_ERROR: Invalid payload - %v", err)
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Payload non valido",
            "code":  "INVALID_PAYLOAD",
        })
    }

    // Supporta sia email che username come identificatore per login
    // Priorità: username se fornito, altrimenti email
    var identifier string
    if req.Username != "" {
        identifier = req.Username
    } else if req.Email != "" {
        identifier = req.Email
    } else {
        return c.Status(400).JSON(fiber.Map{
            "error": "Email o username richiesti",
            "code":  "MISSING_IDENTIFIER",
        })
    }

    log.Printf("LOGIN_ATTEMPT: identifier='%s'", identifier)

    // Cerca l'utente nel database PostgreSQL
    var user User
    selectQuery := `SELECT id, email, username, password, created_at FROM users WHERE email = $1 OR username = $1`
    err := database.DB.QueryRow(selectQuery, identifier).Scan(
        &user.ID, &user.Email, &user.Username, &user.Password, &user.CreatedAt)

    if err == sql.ErrNoRows {
        log.Printf("LOGIN_FAILED: identifier '%s' not found in database", identifier)
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
            "error": "Credenziali errate",
            "code":  "INVALID_CREDENTIALS",
        })
    } else if err != nil {
        log.Printf("LOGIN_ERROR: Database query failed - %v", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Errore interno del server",
            "code":  "DATABASE_ERROR",
        })
    }

    // Verifica password
    if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
        log.Printf("LOGIN_FAILED: Invalid password for identifier '%s'", identifier)
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
            "error": "Credenziali errate",
            "code":  "INVALID_CREDENTIALS",
        })
    }

    // Genera JWT
    token := jwt.New(jwt.SigningMethodHS256)
    claims := token.Claims.(jwt.MapClaims)
    claims["email"] = user.Email     // mantiene email per compatibilità
    claims["user_id"] = user.ID      // ID numerico dal database
    claims["identifier"] = identifier // campo esplicito per l'identificatore usato
    claims["exp"] = time.Now().Add(24 * time.Hour).Unix() // scade dopo 24h

    tokenString, err := token.SignedString(jwtSecret)
    if err != nil {
        log.Printf("LOGIN_ERROR: JWT signing failed - %v", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Impossibile generare il token",
            "code":  "JWT_ERROR",
        })
    }

    log.Printf("LOGIN_SUCCESS: user_id=%d, email=%s", user.ID, user.Email)

    return c.JSON(fiber.Map{
        "token":        tokenString,
        "access_token": tokenString, // Per compatibilità Flutter
        "expires_in":   86400,       // 24 ore in secondi
        "user": fiber.Map{
            "id":       user.ID,
            "email":    user.Email,
            "username": user.Username,
        },
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

    // Connetti al database
    database.Connect()
    
    app := fiber.New()    // CORS per Flutter - configurazione sicura per sviluppo
    app.Use(cors.New(cors.Config{
        AllowOrigins:     "http://localhost:3000,http://localhost:8080,http://127.0.0.1:3000,http://10.0.2.2:3000", // Origins specifici invece di wildcard
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

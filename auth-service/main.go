package main

/ SECRET FIX TEST: Testing corrected SSH secret names in workflow
// This change should trigger only auth-service deployment with proper secrets

import (
    "auth-service/database"
    "auth-service/models"
    "database/sql"
    "fmt"
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
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "github.com/valyala/fasthttp/fasthttpadaptor"
    recovermw "github.com/gofiber/fiber/v2/middleware/recover"
    
    "go-cloud-backend/shared/metrics"
)

// JWT secret - loaded from environment variable JWT_SECRET
var jwtSecret []byte

// User rappresenta un utente registrato nel database PostgreSQL
type User struct {
    ID        int       `json:"id"`
    Email     string    `json:"email"`
    Username  string    `json:"username,omitempty"`
    Name      string    `json:"name,omitempty"`
    Surname   string    `json:"surname,omitempty"`
    Password  string    `json:"-"` // hashed, non esposto nel JSON
    Role      string    `json:"role"`
    CreatedAt time.Time `json:"created_at"`
}

// request payload per /register
type registerRequest struct {
    Email    string `json:"email"`
    Username string `json:"username"` // supporta anche username
    Name     string `json:"name"`     // nome utente
    Surname  string `json:"surname"`  // cognome utente
    Password string `json:"password"`
}

func registerHandler(c *fiber.Ctx) error {
    var req registerRequest
    if err := c.BodyParser(&req); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Payload non valido",
        })
    }    // TrimSpace su tutti i campi
    req.Email = strings.TrimSpace(req.Email)
    req.Username = strings.TrimSpace(req.Username)
    req.Name = strings.TrimSpace(req.Name)
    req.Surname = strings.TrimSpace(req.Surname)
    req.Password = strings.TrimSpace(req.Password)

    // Validazione formato email se email è fornita
    if req.Email != "" {
        if _, err := mail.ParseAddress(req.Email); err != nil {
            return c.Status(400).JSON(fiber.Map{
                "error": "Formato email non valido",
            })
        }    }    // Validazione password (minimo 6 caratteri per Flutter)
    if len(req.Password) < 6 {
        return c.Status(400).JSON(fiber.Map{
            "error": "Password deve essere di almeno 6 caratteri",
            "code":  "PASSWORD_TOO_SHORT",
        })
    }

    // Validazione campi obbligatori
    if req.Name == "" || req.Surname == "" {
        return c.Status(400).JSON(fiber.Map{
            "error": "Nome e cognome sono obbligatori",
            "code":  "MISSING_NAMES",
        })
    }// Controlla se l'utente esiste già nel database PostgreSQL
    var existingID int
    var checkQuery string
    var args []interface{}
    
    // Costruisci la query dinamicamente per evitare falsi positivi con stringhe vuote
    if req.Username != "" && req.Email != "" {
        checkQuery = "SELECT id FROM users WHERE email = $1 OR username = $2"
        args = []interface{}{req.Email, req.Username}
    } else if req.Email != "" {
        checkQuery = "SELECT id FROM users WHERE email = $1"
        args = []interface{}{req.Email}
    } else if req.Username != "" {
        checkQuery = "SELECT id FROM users WHERE username = $1"
        args = []interface{}{req.Username}
    } else {
        return c.Status(400).JSON(fiber.Map{
            "error": "Email o username richiesti per la registrazione",
            "code":  "MISSING_IDENTIFIER",
        })
    }
    
    err := database.DB.QueryRow(checkQuery, args...).Scan(&existingID)
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
    }    // Salva l'utente nel database PostgreSQL
    insertQuery := `
        INSERT INTO users (email, username, name, surname, password, role, created_at) 
        VALUES ($1, $2, $3, $4, $5, $6, $7) 
        RETURNING id, created_at`

    var userID int
    var createdAt time.Time
    
    // Se username è vuoto, genera automaticamente dalla email
    var finalUsername string
    if req.Username == "" {
        // Estrae la parte prima di @ dall'email
        emailParts := strings.Split(req.Email, "@")
        baseUsername := emailParts[0]
        
        // Verifica se username esiste già e genera versione unica
        finalUsername = baseUsername
        counter := 1
        for {
            var existingUsernameID int
            err := database.DB.QueryRow("SELECT id FROM users WHERE username = $1", finalUsername).Scan(&existingUsernameID)
            if err == sql.ErrNoRows {
                // Username disponibile
                break
            }
            // Username occupato, prova con numero
            finalUsername = fmt.Sprintf("%s%d", baseUsername, counter)
            counter++
        }
    } else {
        finalUsername = req.Username
    }
      err = database.DB.QueryRow(insertQuery, req.Email, finalUsername, req.Name, req.Surname, string(hashedPassword), "user", time.Now()).
        Scan(&userID, &createdAt)

    if err != nil {
        log.Printf("REGISTER_ERROR: Database insert failed - %v", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Errore nel salvare l'utente",
            "code":  "DATABASE_ERROR",
        })
    }
    
    log.Printf("REGISTER_SUCCESS: user_id=%d, email=%s, username=%s", userID, req.Email, finalUsername)
    
    // Record successful registration metric
    metrics.RecordAuthAttempt(true, "auth-service")

    return c.Status(fiber.StatusCreated).JSON(fiber.Map{
        "message": "Registrazione avvenuta con successo",
        "user": fiber.Map{
            "id":         userID,
            "email":      req.Email,
            "username":   finalUsername,  // Restituisce l'username generato
            "name":       req.Name,
            "surname":    req.Surname,
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

func loginHandler(c *fiber.Ctx) error {
    log.Printf("LOGIN_TRACE: INIZIO loginHandler")
    defer func() {
        if r := recover(); r != nil {
            log.Printf("LOGIN_PANIC: %v", r)
            _ = c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
                "error":   "Errore interno del server (panic)",
                "code":    "INTERNAL_PANIC",
                "details": fmt.Sprintf("%v", r),
            })
        }
    }()

    log.Printf("LOGIN_TRACE: dopo defer recover, prima controllo DB")
    // Controllo robusto su database.DB
    if database.DB == nil {
        log.Printf("LOGIN_ERROR: database.DB is nil")
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Database non disponibile",
            "code":  "DB_NOT_AVAILABLE",
        })
    }

    log.Printf("LOGIN_TRACE: dopo controllo DB, prima BodyParser")
    var req loginRequest
    if err := c.BodyParser(&req); err != nil {
        log.Printf("LOGIN_ERROR: Invalid payload - %v", err)
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Payload non valido",
            "code":  "INVALID_PAYLOAD",
        })
    }

    log.Printf("LOGIN_TRACE: dopo BodyParser, req.Email='%s', req.Username='%s'", req.Email, req.Username)

    // Determina l'identificatore (email o username)
    identifier := ""
    if req.Email != "" {
        identifier = req.Email
    } else if req.Username != "" {
        identifier = req.Username
    } else {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Email o username richiesti",
            "code":  "MISSING_IDENTIFIER",
        })
    }

    log.Printf("LOGIN_ATTEMPT: identifier='%s'", identifier)
    var user User
    selectQuery := `SELECT id, email, username, name, surname, password, role, created_at FROM users WHERE email = $1 OR username = $1`
    err := database.DB.QueryRow(selectQuery, identifier).Scan(
        &user.ID, &user.Email, &user.Username, &user.Name, &user.Surname, &user.Password, &user.Role, &user.CreatedAt)

    if err == sql.ErrNoRows {
        log.Printf("LOGIN_FAILED: identifier '%s' not found in database", identifier)
        metrics.RecordAuthAttempt(false, "auth-service")
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

    log.Printf("LOGIN_DEBUG: user.ID=%d, user.Email=%s, user.Password.len=%d", user.ID, user.Email, len(user.Password))

    if user.Password == "" {
        log.Printf("LOGIN_ERROR: Password hash vuoto per user.ID=%d, identifier='%s'", user.ID, identifier)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Password non impostata per l'utente",
            "code":  "PASSWORD_NOT_SET",
        })
    }

    if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
        log.Printf("LOGIN_FAILED: Invalid password for identifier '%s' (user.ID=%d)", identifier, user.ID)
        // Log fallimento autenticazione con gestione errori logging
        if database.DB != nil {
            if logErr := models.LogAuthActionDetailed(user.Email, user.Username, "login_failed_wrong_password", c.IP(), c.Get("User-Agent"), false); logErr != nil {
                log.Printf("LOGIN_LOG_ERROR: %v", logErr)
            }
        }
        metrics.RecordAuthAttempt(false, "auth-service")
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
            "error": "Credenziali errate",
            "code":  "INVALID_CREDENTIALS",
        })
    }

    // Genera JWT
    token := jwt.New(jwt.SigningMethodHS256)
    claims := token.Claims.(jwt.MapClaims)
    claims["email"] = user.Email
    claims["user_id"] = user.ID
    claims["role"] = user.Role
    claims["name"] = user.Name
    claims["surname"] = user.Surname
    claims["identifier"] = identifier
    claims["exp"] = time.Now().Add(24 * time.Hour).Unix()

    tokenString, err := token.SignedString(jwtSecret)
    if err != nil {
        log.Printf("LOGIN_ERROR: JWT signing failed - %v", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Impossibile generare il token",
            "code":  "JWT_ERROR",
        })
    }

    // Log the successful authentication con gestione errori logging
    if database.DB != nil {
        if logErr := models.LogAuthActionDetailed(user.Email, user.Username, "login_success", c.IP(), c.Get("User-Agent"), true); logErr != nil {
            log.Printf("LOGIN_LOG_ERROR: %v", logErr)
        }
    }
    log.Printf("LOGIN_SUCCESS: user_id=%d, email=%s", user.ID, user.Email)
    metrics.RecordAuthAttempt(true, "auth-service")

    return c.JSON(fiber.Map{
        "token":        tokenString,
        "access_token": tokenString,
        "expires_in":   86400,
        "user": fiber.Map{
            "id":       user.ID,
            "email":    user.Email,
            "username": user.Username,
            "name":     user.Name,
            "surname":  user.Surname,
            "role":     user.Role,
        },
    })
}

// adminOnly middleware per verificare che l'utente sia admin
func adminOnly(c *fiber.Ctx) error {
    user := c.Locals("user").(*jwt.Token)
    claims := user.Claims.(jwt.MapClaims)
    role, ok := claims["role"].(string)
    
    if !ok || role != "admin" {
        log.Printf("ADMIN_ACCESS_DENIED: user_id=%v role=%v", claims["user_id"], role)
        return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
            "error": "Accesso negato. Privilegi amministratore richiesti.",
            "code":  "ADMIN_REQUIRED",
        })
    }
    return c.Next()
}

// getAllUsersHandler restituisce tutti gli utenti (solo admin)
func getAllUsersHandler(c *fiber.Ctx) error {
    query := `SELECT id, email, username, name, surname, role, created_at FROM users ORDER BY created_at DESC`
    rows, err := database.DB.Query(query)
    if err != nil {
        log.Printf("ADMIN_ERROR: Failed to query users - %v", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Errore nel recuperare gli utenti",
            "code":  "DATABASE_ERROR",
        })
    }
    defer rows.Close()
      var users []User
    for rows.Next() {
        var user User
        err := rows.Scan(&user.ID, &user.Email, &user.Username, &user.Name, &user.Surname, &user.Role, &user.CreatedAt)
        if err != nil {
            log.Printf("ADMIN_ERROR: Failed to scan user - %v", err)
            continue
        }
        users = append(users, user)
    }
    
    return c.JSON(fiber.Map{
        "users": users,
        "total": len(users),
    })
}

// updateUserRoleHandler aggiorna il ruolo di un utente (solo admin)
func updateUserRoleHandler(c *fiber.Ctx) error {
    userID := c.Params("id")
    
    var req struct {
        Role string `json:"role"`
    }
    if err := c.BodyParser(&req); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Payload non valido",
            "code":  "INVALID_PAYLOAD",
        })
    }
    
    // Valida il ruolo
    if req.Role != "user" && req.Role != "admin" {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Ruolo non valido. Deve essere 'user' o 'admin'",
            "code":  "INVALID_ROLE",
        })
    }
    
    query := `UPDATE users SET role = $1 WHERE id = $2`
    result, err := database.DB.Exec(query, req.Role, userID)
    if err != nil {
        log.Printf("ADMIN_ERROR: Failed to update user role - %v", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Errore nell'aggiornamento del ruolo",
            "code":  "DATABASE_ERROR",
        })
    }
    
    rowsAffected, _ := result.RowsAffected()
    if rowsAffected == 0 {
        return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
            "error": "Utente non trovato",
            "code":  "USER_NOT_FOUND",
        })
    }
    
    log.Printf("ADMIN_ACTION: User %s role updated to %s", userID, req.Role)
    
    return c.JSON(fiber.Map{
        "message": "Ruolo aggiornato con successo",
        "user_id": userID,
        "new_role": req.Role,
    })
}

// deleteUserHandler elimina un utente (solo admin)
func deleteUserHandler(c *fiber.Ctx) error {
    userID := c.Params("id")
    
    // Verifica che l'admin non stia eliminando se stesso
    user := c.Locals("user").(*jwt.Token)
    claims := user.Claims.(jwt.MapClaims)
    currentUserID := claims["user_id"]
    
    if fmt.Sprintf("%v", currentUserID) == userID {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Non puoi eliminare il tuo stesso account",
            "code":  "SELF_DELETE_FORBIDDEN",
        })
    }
    
    query := `DELETE FROM users WHERE id = $1`
    result, err := database.DB.Exec(query, userID)
    if err != nil {
        log.Printf("ADMIN_ERROR: Failed to delete user - %v", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Errore nell'eliminazione dell'utente",
            "code":  "DATABASE_ERROR",
        })
    }
    
    rowsAffected, _ := result.RowsAffected()
    if rowsAffected == 0 {
        return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
            "error": "Utente non trovato",
            "code":  "USER_NOT_FOUND",
        })
    }
    
    log.Printf("ADMIN_ACTION: User %s deleted", userID)
    
    return c.JSON(fiber.Map{
        "message": "Utente eliminato con successo",
        "user_id": userID,
    })
}

// getAuthLogsHandler restituisce tutti i log di autenticazione (solo admin)
func getAuthLogsHandler(c *fiber.Ctx) error {
    // Parametri di paginazione opzionali
    page := c.QueryInt("page", 1)
    limit := c.QueryInt("limit", 50)
    
    if page < 1 {
        page = 1
    }
    if limit < 1 || limit > 500 {
        limit = 50
    }
    
    logs, err := models.GetAuthLogs()
    if err != nil {
        log.Printf("ADMIN_ERROR: Failed to get auth logs - %v", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Errore nel recuperare i log di autenticazione",
            "code":  "DATABASE_ERROR",
        })
    }
    
    // Paginazione semplice
    total := len(logs)
    start := (page - 1) * limit
    end := start + limit
    
    if start >= total {
        logs = []models.AuthLog{}
    } else {
        if end > total {
            end = total
        }
        logs = logs[start:end]
    }
    
    log.Printf("ADMIN_ACTION: Auth logs requested - page=%d, limit=%d, total=%d", page, limit, total)
    
    return c.JSON(fiber.Map{
        "logs":  logs,
        "total": total,
        "page":  page,
        "limit": limit,
        "stats": fiber.Map{
            "total_logs": total,
            "current_page": page,
            "pages_total": (total + limit - 1) / limit,
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

func getUserFromJWT(c *fiber.Ctx) (int, string, string, string, error) {
    log.Println("getUserFromJWT: Starting...")
    
    user := c.Locals("user")
    if user == nil {
        log.Println("getUserFromJWT: No user in context")
        return 0, "", "", "", fmt.Errorf("utente non autenticato")
    }

    token, ok := user.(*jwt.Token)
    if !ok {
        log.Println("getUserFromJWT: Invalid token type")
        return 0, "", "", "", fmt.Errorf("token non valido")
    }

    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
        log.Println("getUserFromJWT: Invalid claims type")
        return 0, "", "", "", fmt.Errorf("claims non validi")
    }

    log.Printf("getUserFromJWT: JWT claims: %v", claims)

    userID, ok := claims["user_id"].(float64)
    if !ok {
        log.Println("getUserFromJWT: user_id not found in claims")
        return 0, "", "", "", fmt.Errorf("user_id non trovato nel token")
    }

    email, _ := claims["email"].(string)
    role, ok := claims["role"].(string)
    if !ok {
        role = "user" // default role
    }

    log.Printf("getUserFromJWT: Success - UserID: %d, Email: %s, Role: %s", int(userID), email, role)
    
    // Microservizi puri: usa solo dati dal JWT, no database query
    name := email
    surname := ""
    
    return int(userID), name, surname, role, nil
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

    // Connetti al database
    database.Connect()
    app := fiber.New()

    // PRIMO middleware: recover di Fiber
    app.Use(recovermw.New(recovermw.Config{
        EnableStackTrace: true,
        StackTraceHandler: func(c *fiber.Ctx, e interface{}) {
            log.Printf("PANIC: %v", e)
            log.Printf("REQUEST: %s %s", c.Method(), c.OriginalURL())
            log.Printf("HEADERS: %v", c.GetReqHeaders())
        },
    }))

    // Middleware recover globale personalizzato per loggare stacktrace e request
    app.Use(func(c *fiber.Ctx) error {
        defer func() {
            if r := recover(); r != nil {
                log.Printf("GLOBAL_PANIC: %v", r)
                log.Printf("REQUEST: %s %s", c.Method(), c.OriginalURL())
                log.Printf("HEADERS: %v", c.GetReqHeaders())
                // Risposta JSON coerente
                _ = c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
                    "error":   "Errore interno del server (panic)",
                    "code":    "INTERNAL_PANIC_GLOBAL",
                    "details": fmt.Sprintf("%v", r),
                })
            }
        }()
        return c.Next()
    })

    // Add metrics middleware to track HTTP requests
    app.Use(metrics.HTTPMetricsMiddleware("auth-service"))

    // CORS per Flutter - configurazione sicura per sviluppo
    app.Use(cors.New(cors.Config{
        AllowOrigins:     "http://localhost:3000,http://localhost:8080,http://127.0.0.1:3000,http://10.0.2.2:3000", // Origins specifici invece di wildcard
        AllowMethods:     "GET,POST,PUT,DELETE,OPTIONS",
        AllowHeaders:     "Origin,Content-Type,Accept,Authorization,X-Request-ID,X-Forwarded-For,X-Gateway-Request",
        AllowCredentials: true,
        MaxAge:           300, // 5 minuti
    }))    // Start periodic metrics updates - removed for simplicity
    // Auth service focuses on authentication metrics only

    // Middleware per bloccare accessi diretti (opzionale in sviluppo)
    // app.Use(gatewayOnly)// Health endpoint (pubblico)
    app.Get("/health", func(c *fiber.Ctx) error {
        return c.JSON(fiber.Map{
            "status":    "healthy",
            "service":   "auth-service",
            "timestamp": time.Now(),
        })
    })

    // Prometheus metrics endpoint
    app.Get("/metrics", func(c *fiber.Ctx) error {
        handler := fasthttpadaptor.NewFastHTTPHandler(promhttp.Handler())
        handler(c.Context())
        return nil
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

    // Rotte amministrative - richiedono autenticazione admin
    admin := app.Group("/admin", jwtware.New(jwtware.Config{
        SigningKey: jwtSecret,
    }), adminOnly)    // Endpoint per ottenere tutti gli utenti (admin)
    admin.Get("/users", getAllUsersHandler)

    // Endpoint per ottenere i log di autenticazione (admin)
    admin.Get("/auth-logs", getAuthLogsHandler)

    // Endpoint per aggiornare il ruolo di un utente (admin)
    admin.Put("/users/:id/role", updateUserRoleHandler)

    // Endpoint per eliminare un utente (admin)
    admin.Delete("/users/:id", deleteUserHandler)

    log.Println("Auth-service in ascolto sulla porta 3001")
    if err := app.Listen(":3001"); err != nil {
        log.Fatal(err)
    }
}

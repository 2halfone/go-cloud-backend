package main

import (
    "log"
    "os"
    "strconv"
    "strings"
    "time"
    "user-service/database"

    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/fiber/v2/middleware/cors"
    jwtware "github.com/gofiber/jwt/v3"
    "github.com/golang-jwt/jwt/v4"
)

// JWT secret - loaded from environment variable JWT_SECRET
var jwtSecret []byte

// User rappresenta un utente nella tabella users
type User struct {
    ID        int       `json:"id" db:"id"`
    Name      string    `json:"name" db:"name"`
    LastName  string    `json:"last_name" db:"last_name"`
    Status    string    `json:"status" db:"status"`
    Timestamp time.Time `json:"timestamp" db:"timestamp"`
}

// Request payload per creare/aggiornare utente
type UserRequest struct {
    Name     string `json:"name"`
    LastName string `json:"last_name"`
    Status   string `json:"status"`
}

// QR scan request structure
type QRScanRequest struct {
    QRCode   string `json:"qr_code"`
    Location string `json:"location"`
}

// QR scan data structure
type QRScan struct {
    QRCode    string    `json:"qr_code"`
    Location  string    `json:"location"`
    Timestamp time.Time `json:"timestamp"`
}

// User choice request structure
type UserChoiceRequest struct {
    Choice   string                 `json:"choice"`
    QRCode   string                 `json:"qr_code"`
    Location string                 `json:"location"`
    Metadata map[string]interface{} `json:"metadata"`
}

// User choice data structure
type UserChoice struct {
    ID        string                 `json:"id"`
    UserEmail string                 `json:"user_email"`
    QRCode    string                 `json:"qr_code"`
    Choice    string                 `json:"choice"`
    Location  string                 `json:"location"`
    Metadata  map[string]interface{} `json:"metadata"`
    Timestamp time.Time              `json:"timestamp"`
}

// In-memory storage for QR scans and user choices (for demo purposes)
var qrScans []QRScan
var userChoices []UserChoice

// Response per lista utenti con paginazione
type UsersResponse struct {
    Users []User `json:"users"`
    Total int    `json:"total"`
    Page  int    `json:"page"`
    Limit int    `json:"limit"`
}

// Handler per GET /users - Lista utenti con paginazione
func getUsersHandler(c *fiber.Ctx) error {
    // Parametri di paginazione
    page := c.QueryInt("page", 1)
    limit := c.QueryInt("limit", 10)
    status := c.Query("status", "") // Filtro per status
    
    if page < 1 {
        page = 1
    }
    if limit < 1 || limit > 100 {
        limit = 10
    }
    
    offset := (page - 1) * limit
    
    // Query base
    query := `SELECT id, name, last_name, status, timestamp FROM users`
    countQuery := `SELECT COUNT(*) FROM users`
    args := []interface{}{
        limit,
        offset,
    }
    
    // Aggiungi filtro status se fornito
    if status != "" {
        query += ` WHERE status = $1`
        countQuery += ` WHERE status = $1`
        args = append(args, status)
    }
    
    // Aggiungi ordinamento e paginazione
    query += ` ORDER BY timestamp DESC LIMIT $` + strconv.Itoa(len(args)) + ` OFFSET $` + strconv.Itoa(len(args)+1)
    
    // Esegui query per gli utenti
    rows, err := database.DB.Query(query, args...)
    if err != nil {
        log.Printf("Error querying users: %v", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Errore nel recuperare gli utenti",
        })
    }
    defer rows.Close()
    
    var users []User
    for rows.Next() {
        var user User
        err := rows.Scan(&user.ID, &user.Name, &user.LastName, &user.Status, &user.Timestamp)
        if err != nil {
            log.Printf("Error scanning user: %v", err)
            continue
        }
        users = append(users, user)
    }
    
    // Conta totale utenti
    var total int
    countArgs := args[:len(args)-2] // Rimuovi limit e offset per il count
    err = database.DB.QueryRow(countQuery, countArgs...).Scan(&total)
    if err != nil {
        log.Printf("Error counting users: %v", err)
        total = len(users)
    }
    
    return c.JSON(UsersResponse{
        Users: users,
        Total: total,
        Page:  page,
        Limit: limit,
    })
}

// Handler per GET /users/:id - Dettagli utente specifico
func getUserByIDHandler(c *fiber.Ctx) error {
    id, err := strconv.Atoi(c.Params("id"))
    if err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "ID utente non valido",
        })
    }
    
    query := `SELECT id, name, last_name, status, timestamp FROM users WHERE id = $1`
    var user User
    
    err = database.DB.QueryRow(query, id).Scan(
        &user.ID, &user.Name, &user.LastName, &user.Status, &user.Timestamp,
    )
    
    if err != nil {
        if err.Error() == "sql: no rows in result set" {
            return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
                "error": "Utente non trovato",
            })
        }
        log.Printf("Error querying user by ID: %v", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Errore nel recuperare i dettagli dell'utente",
        })
    }
    
    return c.JSON(user)
}

// Handler per POST /users - Creazione di un nuovo utente
func createUserHandler(c *fiber.Ctx) error {
    var req UserRequest
    if err := c.BodyParser(&req); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Payload non valido",
        })
    }

    // Valida i campi richiesti
    if req.Name == "" || req.LastName == "" {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Nome e cognome sono richiesti",
        })
    }

    // Crea un nuovo utente
    query := `INSERT INTO users (name, last_name, status, timestamp) VALUES ($1, $2, $3, $4) RETURNING id`
    var userID int
    err := database.DB.QueryRow(query, req.Name, req.LastName, req.Status, time.Now()).Scan(&userID)
    if err != nil {
        log.Printf("Error creating user: %v", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Errore nella creazione dell'utente",
        })
    }
    
    // Restituisci l'ID del nuovo utente
    return c.Status(fiber.StatusCreated).JSON(fiber.Map{
        "message": "Utente creato con successo",
        "user_id": userID,
    })
}

// Handler per PUT /users/:id - Aggiornamento di un utente esistente
func updateUserHandler(c *fiber.Ctx) error {
    id, err := strconv.Atoi(c.Params("id"))
    if err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "ID utente non valido",
        })
    }
    
    var req UserRequest
    if err := c.BodyParser(&req); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Payload non valido",
        })
    }

    // Valida i campi richiesti
    if req.Name == "" || req.LastName == "" {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Nome e cognome sono richiesti",
        })
    }

    // Aggiorna i dettagli dell'utente
    query := `UPDATE users SET name = $1, last_name = $2, status = $3, timestamp = $4 WHERE id = $5`
    _, err = database.DB.Exec(query, req.Name, req.LastName, req.Status, time.Now(), id)
    if err != nil {
        log.Printf("Error updating user: %v", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Errore nell'aggiornamento dell'utente",
        })
    }
    
    return c.JSON(fiber.Map{
        "message": "Utente aggiornato con successo",
    })
}

// Handler per DELETE /users/:id - Cancellazione di un utente
func deleteUserHandler(c *fiber.Ctx) error {
    id, err := strconv.Atoi(c.Params("id"))
    if err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "ID utente non valido",
        })
    }
    
    query := `DELETE FROM users WHERE id = $1`
    _, err = database.DB.Exec(query, id)
    if err != nil {
        log.Printf("Error deleting user: %v", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Errore nella cancellazione dell'utente",
        })
    }
    
    return c.JSON(fiber.Map{
        "message": "Utente cancellato con successo",
    })
}

func healthHandler(c *fiber.Ctx) error {
    return c.JSON(fiber.Map{
        "status":    "healthy",
        "service":   "user-service",
        "timestamp": time.Now(),
    })
}

func qrScanHandler(c *fiber.Ctx) error {
    var req QRScanRequest
    if err := c.BodyParser(&req); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Payload non valido",
        })
    }

    scan := QRScan{
        QRCode:    req.QRCode,
        Location:  req.Location,
        Timestamp: time.Now(),
    }
    qrScans = append(qrScans, scan)

    return c.JSON(fiber.Map{
        "message":   "QR code scansionato con successo",
        "qr_code":   req.QRCode,
        "location":  req.Location,
        "timestamp": scan.Timestamp,
    })
}

func userProfileHandler(c *fiber.Ctx) error {
    user := c.Locals("user").(*jwt.Token)
    claims := user.Claims.(jwt.MapClaims)
    email := claims["email"].(string)

    return c.JSON(fiber.Map{
        "email":   email,
        "name":    "Mario Rossi",
        "userId":  "abc123",
    })
}

func saveChoiceHandler(c *fiber.Ctx) error {
    user := c.Locals("user").(*jwt.Token)
    claims := user.Claims.(jwt.MapClaims)
    email := claims["email"].(string)

    var req UserChoiceRequest
    if err := c.BodyParser(&req); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Payload non valido",
        })
    }

    choiceID := time.Now().Format("20060102150405")
    choice := UserChoice{
        ID:        choiceID,
        UserEmail: email,
        QRCode:    req.QRCode,
        Choice:    req.Choice,
        Location:  req.Location,
        Metadata:  req.Metadata,
        Timestamp: time.Now(),
    }

    userChoices = append(userChoices, choice)

    return c.Status(fiber.StatusCreated).JSON(fiber.Map{
        "message": "Scelta salvata con successo",
        "choice":  choice,
    })
}

func getUserChoicesHandler(c *fiber.Ctx) error {
    user := c.Locals("user").(*jwt.Token)
    claims := user.Claims.(jwt.MapClaims)
    email := claims["email"].(string)

    var userChoicesFiltered []UserChoice
    for _, choice := range userChoices {
        if choice.UserEmail == email {
            userChoicesFiltered = append(userChoicesFiltered, choice)
        }
    }

    return c.JSON(fiber.Map{
        "user":    email,
        "choices": userChoicesFiltered,
        "count":   len(userChoicesFiltered),
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

// jwtError handles JWT authentication errors
func jwtError(c *fiber.Ctx, err error) error {
    return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
        "error": "Token non valido o mancante",
    })
}

func main() {
    // Initialize database connection
    database.Connect()
    
    // Load JWT secret from environment variable
    jwtSecretEnv := os.Getenv("JWT_SECRET")
    if jwtSecretEnv == "" {
        log.Fatal("JWT_SECRET environment variable not set")
    }
    jwtSecret = []byte(jwtSecretEnv)

    app := fiber.New(fiber.Config{
        AppName: "User Service v1.0",
    })

    // CORS restrittivo - accetta solo richieste dal Gateway
    app.Use(cors.New(cors.Config{
        AllowOrigins:     "http://localhost:3000", // Solo dal Gateway
        AllowMethods:     "GET,POST,PUT,DELETE,OPTIONS",
        AllowHeaders:     "Origin,Content-Type,Accept,Authorization,X-Request-ID,X-Forwarded-For,X-Gateway-Request",
        AllowCredentials: true,
        MaxAge:           300, // 5 minuti
    }))

    // Middleware per bloccare accessi diretti (opzionale in sviluppo)
    // app.Use(gatewayOnly)    // Endpoint pubblici
    app.Get("/health", healthHandler)
    app.Post("/qr/scan", qrScanHandler)

    // JWT middleware per endpoint protetti
    app.Use("/user", jwtware.New(jwtware.Config{
        SigningKey:   jwtSecret,
        ErrorHandler: jwtError,
    }))

    // Endpoint protetti
    app.Get("/user/profile", userProfileHandler)
    app.Post("/user/choice", saveChoiceHandler)
    app.Get("/user/choices", getUserChoicesHandler)

    // Endpoint per gestione utenti
    app.Get("/users", getUsersHandler)
    app.Get("/users/:id", getUserByIDHandler)
    app.Post("/users", createUserHandler)
    app.Put("/users/:id", updateUserHandler)
    app.Delete("/users/:id", deleteUserHandler)

    log.Println("🚀 User Service completo avviato sulla porta 3002")
    log.Fatal(app.Listen(":3002"))
}

package main

import (
    "encoding/base64"
    "fmt"
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
    "github.com/skip2/go-qrcode"
)

// JWT secret - loaded from environment variable JWT_SECRET
var jwtSecret []byte

// User rappresenta un utente nella tabella users
type User struct {
    ID        int       `json:"id" db:"id"`
    Name      string    `json:"name" db:"name"`
    LastName  string    `json:"last_name" db:"last_name"`
    Status    string    `json:"status" db:"status"`
    Role      string    `json:"role" db:"role"`
    Timestamp time.Time `json:"timestamp" db:"timestamp"`
}

// AttendanceEvent rappresenta un evento di presenza con QR
type AttendanceEvent struct {
    ID          int       `json:"id" db:"id"`
    EventID     string    `json:"event_id" db:"event_id"`
    EventName   string    `json:"event_name" db:"event_name"`
    Date        time.Time `json:"date" db:"date"`
    QRJWT       string    `json:"-" db:"qr_jwt"`
    QRImagePath string    `json:"qr_image_path,omitempty" db:"qr_image_path"`
    ExpiresAt   time.Time `json:"expires_at" db:"expires_at"`
    CreatedBy   int       `json:"created_by" db:"created_by"`
    CreatedAt   time.Time `json:"created_at" db:"created_at"`
    IsActive    bool      `json:"is_active" db:"is_active"`
}

// Attendance rappresenta la presenza di un utente
type Attendance struct {
    ID          int       `json:"id" db:"id"`
    UserID      int       `json:"user_id" db:"user_id"`
    EventID     string    `json:"event_id" db:"event_id"`
    Timestamp   time.Time `json:"timestamp" db:"timestamp"`
    Name        string    `json:"name" db:"name"`
    Surname     string    `json:"surname" db:"surname"`
    Status      string    `json:"status" db:"status"`
    Motivazione string    `json:"motivazione,omitempty" db:"motivazione"`
    CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

// QR JWT Claims per il contenuto del QR code
type QRJWTClaims struct {
    EventID   string `json:"event_id"`
    EventName string `json:"event_name"`
    Date      string `json:"date"`
    CreatedBy int    `json:"created_by"`
    jwt.RegisteredClaims
}

// QRContent rappresenta il contenuto del QR code
type QRContent struct {
    JWT     string `json:"jwt"`
    Type    string `json:"type"`
    Version string `json:"version"`
}

// Request per generare QR (admin only)
type GenerateQRRequest struct {
    EventName    string `json:"event_name"`
    Date         string `json:"date"`
    ExpiresHours int    `json:"expires_hours"`
}

// Request per scansionare QR e registrare presenza
type AttendanceRequest struct {
    QRContent   QRContent `json:"qr_content"`
    Status      string    `json:"status"`
    Motivazione string    `json:"motivazione,omitempty"`
}

// ValidStatuses definisce gli status validi per la presenza
var ValidStatuses = []string{
    "presente", "vacation", "hospital", "family", 
    "sick", "personal", "business", "other",
}

// Funzioni helper per JWT QR
func generateQRJWT(eventID, eventName, date string, createdBy int) (string, error) {
    // Calcola scadenza (fine giornata)
    dateTime, err := time.Parse("2006-01-02", date)
    if err != nil {
        return "", fmt.Errorf("formato data non valido: %v", err)
    }
    
    // Scadenza a fine giornata
    expiresAt := time.Date(dateTime.Year(), dateTime.Month(), dateTime.Day(), 23, 59, 59, 0, dateTime.Location())
    
    claims := QRJWTClaims{
        EventID:   eventID,
        EventName: eventName,
        Date:      date,
        CreatedBy: createdBy,
        RegisteredClaims: jwt.RegisteredClaims{
            Issuer:    "attendance-system",
            Subject:   eventID,
            ExpiresAt: jwt.NewNumericDate(expiresAt),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
        },
    }
    
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(jwtSecret)
}

func validateQRJWT(tokenString string) (*QRJWTClaims, error) {
    token, err := jwt.ParseWithClaims(tokenString, &QRJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
        return jwtSecret, nil
    })
    
    if err != nil {
        return nil, err
    }
    
    if claims, ok := token.Claims.(*QRJWTClaims); ok && token.Valid {
        return claims, nil
    }
    
    return nil, fmt.Errorf("token non valido")
}

func isValidStatus(status string) bool {
    for _, valid := range ValidStatuses {
        if status == valid {
            return true
        }
    }
    return false
}

func getUserFromJWT(c *fiber.Ctx) (int, string, string, string, error) {
    user := c.Locals("user")
    if user == nil {
        log.Printf("getUserFromJWT: No user found in context")
        return 0, "", "", "", fmt.Errorf("nessun utente nel contesto JWT")
    }
    
    token, ok := user.(*jwt.Token)
    if !ok {
        log.Printf("getUserFromJWT: User context is not a JWT token")
        return 0, "", "", "", fmt.Errorf("formato token non valido")
    }
    
    claims := token.Claims.(jwt.MapClaims)
    log.Printf("getUserFromJWT: JWT claims: %+v", claims)
    
    userIDFloat, ok := claims["user_id"].(float64)
    if !ok {
        log.Printf("getUserFromJWT: user_id not found in claims or wrong type")
        return 0, "", "", "", fmt.Errorf("user_id non trovato nel token")
    }
    userID := int(userIDFloat)
    
    // Recupera dettagli user dal database
    var name, surname, role string
    query := `SELECT name, last_name, role FROM users WHERE id = $1`
    err := database.DB.QueryRow(query, userID).Scan(&name, &surname, &role)
    if err != nil {
        log.Printf("getUserFromJWT: Database error for user %d: %v", userID, err)
        return 0, "", "", "", fmt.Errorf("utente non trovato: %v", err)
    }
    
    log.Printf("getUserFromJWT: Found user %d (%s %s) with role '%s'", userID, name, surname, role)
    return userID, name, surname, role, nil
}

func hasUserScannedEvent(userID int, eventID string) (bool, error) {
    var count int
    query := `SELECT COUNT(*) FROM attendance WHERE user_id = $1 AND event_id = $2`
    err := database.DB.QueryRow(query, userID, eventID).Scan(&count)
    return count > 0, err
}

func generateQRImage(content string) (string, error) {
    // Genera QR code come base64
    qr, err := qrcode.Encode(content, qrcode.Medium, 256)
    if err != nil {
        return "", err
    }
    
    return base64.StdEncoding.EncodeToString(qr), nil
}

// Middleware per verificare ruolo admin
func adminOnly(c *fiber.Ctx) error {
    log.Printf("AdminOnly middleware: Processing request to %s", c.Path())
    
    // Verifica che il JWT sia presente
    user := c.Locals("user")
    if user == nil {
        log.Printf("AdminOnly middleware: No JWT user found in context")
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
            "error": "Token JWT mancante o non valido",
        })
    }
    
    userID, name, surname, role, err := getUserFromJWT(c)
    if err != nil {
        log.Printf("AdminOnly middleware: Error getting user from JWT: %v", err)
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
            "error": "Errore autenticazione",
        })
    }
    
    log.Printf("AdminOnly middleware: User %d (%s %s) with role '%s' accessing %s", 
        userID, name, surname, role, c.Path())
    
    if role != "admin" {
        log.Printf("AdminOnly middleware: Access denied for user %d with role '%s'", userID, role)
        return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
            "error": "Accesso negato: richiesti privilegi admin",
            "user_role": role,
            "required_role": "admin",
        })
    }
    
    log.Printf("AdminOnly middleware: Admin access granted for user %d", userID)
    return c.Next()
}
type UserRequest struct {
    Name     string `json:"name"`
    LastName string `json:"last_name"`
    Status   string `json:"status"`
}

// Response structures
type QRGenerateResponse struct {
    EventID     string    `json:"event_id"`
    EventName   string    `json:"event_name"`
    Date        string    `json:"date"`
    QRImage     string    `json:"qr_image"`
    ExpiresAt   time.Time `json:"expires_at"`
    CreatedAt   time.Time `json:"created_at"`
}

type AttendanceResponse struct {
    Message   string    `json:"message"`
    EventID   string    `json:"event_id"`
    EventName string    `json:"event_name"`
    Status    string    `json:"status"`
    Timestamp time.Time `json:"timestamp"`
}

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
    
    // Query base e conteggio
    var query, countQuery string
    var args, countArgs []interface{}
    
    // Costruisci query in base ai filtri
    if status != "" {
        query = `SELECT id, name, last_name, status, timestamp FROM users WHERE status = $1 ORDER BY timestamp DESC LIMIT $2 OFFSET $3`
        countQuery = `SELECT COUNT(*) FROM users WHERE status = $1`
        args = []interface{}{status, limit, offset}
        countArgs = []interface{}{status}
    } else {
        query = `SELECT id, name, last_name, status, timestamp FROM users ORDER BY timestamp DESC LIMIT $1 OFFSET $2`
        countQuery = `SELECT COUNT(*) FROM users`
        args = []interface{}{limit, offset}
        countArgs = []interface{}{}
    }
    
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
    if len(countArgs) > 0 {
        err = database.DB.QueryRow(countQuery, countArgs...).Scan(&total)
    } else {
        err = database.DB.QueryRow(countQuery).Scan(&total)
    }
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
    }))    // Middleware per bloccare accessi diretti (opzionale in sviluppo)
    // app.Use(gatewayOnly)
    
    // Endpoint pubblici
    app.Get("/health", healthHandler)    // JWT middleware per endpoint protetti
    app.Use("/user", jwtware.New(jwtware.Config{
        SigningKey:   jwtSecret,
        ErrorHandler: jwtError,
    }))
    
    // JWT middleware per endpoint QR (sia admin che user)
    app.Use("/qr", jwtware.New(jwtware.Config{
        SigningKey:   jwtSecret,
        ErrorHandler: jwtError,
    }))
    
    // QR Attendance System - Admin endpoints (protetti da JWT + adminOnly)
    app.Use("/qr/admin", adminOnly)
    app.Post("/qr/admin/generate", generateQRHandler)
    app.Get("/qr/admin/events", getQRListHandler)
    app.Get("/qr/admin/events/:event_id/attendance", getEventAttendanceHandler)
    
    // QR Attendance System - User endpoints (protetti da JWT)
    app.Post("/qr/scan", scanQRHandler)
    app.Get("/qr/attendance/history", getAttendanceHistoryHandler)
    app.Get("/qr/attendance/today", getTodayAttendanceHandler)

    // Endpoint protetti utente
    app.Get("/user/profile", userProfileHandler)

    // Endpoint per gestione utenti
    app.Get("/users", getUsersHandler)
    app.Get("/users/:id", getUserByIDHandler)
    app.Post("/users", createUserHandler)
    app.Put("/users/:id", updateUserHandler)
    app.Delete("/users/:id", deleteUserHandler)

    log.Println("🚀 User Service completo avviato sulla porta 3002")
    log.Fatal(app.Listen(":3002"))
}

package main

import (
    "database/sql"
    "encoding/base64"
    "fmt"
    "log"
    "os"
    "strconv"
    "strings"
    "time"
    "user-service/database"
    "user-service/models"
    "user-service/utils"

    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/fiber/v2/middleware/cors"
    jwtware "github.com/gofiber/jwt/v3"
    "github.com/golang-jwt/jwt/v4"
    "github.com/skip2/go-qrcode"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "github.com/valyala/fasthttp/fasthttpadaptor"
    _ "github.com/lib/pq"
    
    "go-cloud-backend/shared/metrics"
)

// JWT secret - loaded from environment variable JWT_SECRET
var jwtSecret []byte

// Auth service database connection
var authDB *sql.DB

// Update active users count
func updateActiveUsersCount() {
    db := database.DB
    if db != nil {
        var count int
        query := `SELECT COUNT(*) FROM users`
        if err := db.QueryRow(query).Scan(&count); err == nil {
            metrics.UpdateActiveUsers(float64(count), "user-service")
        }
    }
}

// Update database connections count
func updateDatabaseConnections() {
    db := database.DB
    if db != nil {
        stats := db.Stats()
        metrics.UpdateDatabaseConnections(float64(stats.OpenConnections), "user-service", "user_db")
    }
    
    if authDB != nil {
        stats := authDB.Stats()
        metrics.UpdateDatabaseConnections(float64(stats.OpenConnections), "user-service", "auth_db")
    }
}

// Update attendance events count
func updateAttendanceEventsCount() {
    db := database.DB
    if db != nil {
        var count int
        query := `SELECT COUNT(*) FROM attendance_events WHERE is_active = true AND expires_at > NOW()`
        if err := db.QueryRow(query).Scan(&count); err == nil {
            metrics.AttendanceEventsActive.WithLabelValues("user-service").Set(float64(count))
        }
    }
}

// User rappresenta un utente nella tabella users
type User struct {
    ID        int       `json:"id" db:"id"`
    Email     string    `json:"email,omitempty" db:"email"`
    Username  string    `json:"username,omitempty" db:"username"`
    Name      string    `json:"name" db:"name"`
    LastName  string    `json:"last_name" db:"last_name"`
    Status    string    `json:"status" db:"status"`
    Role      string    `json:"role" db:"role"`
    CreatedAt time.Time `json:"created_at" db:"created_at"`
    UpdatedAt time.Time `json:"updated_at,omitempty" db:"updated_at"`
}

// AuthUser rappresenta un utente dalla auth-service database
type AuthUser struct {
    ID        int       `json:"id" db:"id"`
    Email     string    `json:"email" db:"email"`
    Username  string    `json:"username" db:"username"`
    Name      string    `json:"name" db:"name"`
    Surname   string    `json:"surname" db:"surname"`
    Role      string    `json:"role" db:"role"`
    CreatedAt time.Time `json:"created_at" db:"created_at"`
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
    // Status field removed - presence is automatic when scanning QR
    Motivazione string    `json:"motivazione,omitempty"`
}

// ValidStatuses definisce gli status validi per la presenza/assenza
var ValidStatuses = []string{
    "present", "hospital", "family", "emergency", 
    "vacancy", "personal", "not_registered",
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

// Connect to auth database for user synchronization
func connectToAuthDB() error {
    authDBURL := os.Getenv("AUTH_DATABASE_URL")
    if authDBURL == "" {
        return fmt.Errorf("AUTH_DATABASE_URL environment variable not set")
    }
    
    var err error
    authDB, err = sql.Open("postgres", authDBURL)
    if err != nil {
        return fmt.Errorf("failed to connect to auth database: %v", err)
    }
    
    if err = authDB.Ping(); err != nil {
        return fmt.Errorf("failed to ping auth database: %v", err)
    }
    
    log.Println("✅ Connected to auth database for user sync")
    return nil
}

// Get user from auth-service database
func getUserFromAuthDB(userID int) (*AuthUser, error) {
    query := `SELECT id, email, username, name, surname, role, created_at FROM users WHERE id = $1`
    var user AuthUser
    
    err := authDB.QueryRow(query, userID).Scan(
        &user.ID, &user.Email, &user.Username, &user.Name, &user.Surname, &user.Role, &user.CreatedAt,
    )
    
    if err != nil {
        return nil, err
    }
    
    return &user, nil
}

// Check if user exists in user-service database
func userExistsInUserService(userID int) (bool, error) {
    var count int
    query := `SELECT COUNT(*) FROM users WHERE id = $1`
    err := database.DB.QueryRow(query, userID).Scan(&count)
    if err != nil {
        return false, err
    }
    return count > 0, nil
}

// Sync user from auth-service to user-service
func syncUserFromAuthService(userID int) error {
    // Check if user already exists in user-service
    exists, err := userExistsInUserService(userID)
    if err != nil {
        return fmt.Errorf("failed to check user existence: %v", err)
    }
    
    if exists {
        log.Printf("User %d already exists in user-service", userID)
        return nil
    }
    
    // Get user from auth-service
    authUser, err := getUserFromAuthDB(userID)
    if err != nil {
        return fmt.Errorf("failed to get user from auth-service: %v", err)
    }
    
    // Insert user into user-service database with all auth fields
    query := `INSERT INTO users (id, email, username, name, last_name, status, role, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
    _, err = database.DB.Exec(query, authUser.ID, authUser.Email, authUser.Username, authUser.Name, authUser.Surname, "active", authUser.Role, authUser.CreatedAt)
    if err != nil {
        return fmt.Errorf("failed to insert user into user-service: %v", err)
    }
    
    log.Printf("✅ Successfully synced user %d (%s %s) from auth-service to user-service",
        authUser.ID, authUser.Name, authUser.Surname)
    return nil
}

// Ensure user exists in user-service (auto-sync if missing)
func ensureUserExists(userID int) error {
    exists, err := userExistsInUserService(userID)
    if err != nil {
        return err
    }
    
    if !exists {
        log.Printf("User %d not found in user-service, attempting to sync from auth-service", userID)
        return syncUserFromAuthService(userID)
    }
    
    return nil
}

// Handler per POST /users - Creazione di un nuovo utente
func createUserHandler(c *fiber.Ctx) error {
    var req models.UserRequest
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
      var req models.UserRequest
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

// Sync users from auth-service to local database
func syncUsersFromAuthService() {
    // Query all users from auth-service
    authQuery := `SELECT id, email, username, name, surname, role, created_at FROM users`
    rows, err := authDB.Query(authQuery)
    if err != nil {
        log.Printf("Error querying auth-service users: %v", err)
        return
    }
    defer rows.Close()
    
    // Prepare statement for upsert
    upsertStmt, err := database.DB.Prepare(`
        INSERT INTO users (id, email, username, name, surname, role, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (id) DO UPDATE SET
            email = EXCLUDED.email,
            username = EXCLUDED.username,
            name = EXCLUDED.name,
            surname = EXCLUDED.surname,
            role = EXCLUDED.role,
            created_at = EXCLUDED.created_at
    `)
    if err != nil {
        log.Printf("Error preparing upsert statement: %v", err)
        return
    }
    defer upsertStmt.Close()
    
    // Sync each user
    for rows.Next() {
        var user AuthUser
        if err := rows.Scan(&user.ID, &user.Email, &user.Username, &user.Name, &user.Surname, &user.Role, &user.CreatedAt); err != nil {
            log.Printf("Error scanning auth-service user: %v", err)
            continue
        }
        
        // Upsert user into local database
        _, err := upsertStmt.Exec(user.ID, user.Email, user.Username, user.Name, user.Surname, user.Role, user.CreatedAt)
        if err != nil {
            log.Printf("Error upserting user %d: %v", user.ID, err)
        } else {
            log.Printf("Synchronized user %d from auth-service", user.ID)
        }
    }
}

// Connect to auth-service database
func connectAuthServiceDB() {
    var err error
    authDB, err = sql.Open("postgres", "host=localhost port=5432 user=youruser dbname=authservice password=yourpassword sslmode=disable")
    if err != nil {
        log.Fatalf("Error connecting to auth-service database: %v", err)
    }
    
    // Test the connection
    err = authDB.Ping()
    if err != nil {
        log.Fatalf("Error pinging auth-service database: %v", err)
    }
    
    log.Println("Connected to auth-service database")
}

func main() {
    // Initialize database connection
    database.Connect()
    
    // Connect to auth-service database for user synchronization
    err := connectToAuthDB()
    if err != nil {
        log.Printf("Warning: Could not connect to auth-service database: %v", err)
        log.Println("User synchronization will not be available")
    }
    
    // Load JWT secret from environment variable
    jwtSecretEnv := os.Getenv("JWT_SECRET")
    if jwtSecretEnv == "" {
        log.Fatal("JWT_SECRET environment variable not set")
    }
    jwtSecret = []byte(jwtSecretEnv)

    app := fiber.New(fiber.Config{
        AppName: "User Service v1.0",
    })

    // Add metrics middleware to track HTTP requests
    app.Use(metrics.HTTPMetricsMiddleware("user-service"))

    // CORS restrittivo - accetta solo richieste dal Gateway
    app.Use(cors.New(cors.Config{
        AllowOrigins:     "http://localhost:3000", // Solo dal Gateway
        AllowMethods:     "GET,POST,PUT,DELETE,OPTIONS",
        AllowHeaders:     "Origin,Content-Type,Accept,Authorization,X-Request-ID,X-Forwarded-For,X-Gateway-Request",
        AllowCredentials: true,
        MaxAge:           300, // 5 minuti
    }))

    // Start periodic metrics updates
    go func() {
        for {
            time.Sleep(30 * time.Second)
            updateActiveUsersCount()
            updateDatabaseConnections()
            updateAttendanceEventsCount()
        }
    }()

    // Middleware per bloccare accessi diretti (opzionale in sviluppo)
    // app.Use(gatewayOnly)
      // Endpoint pubblici
    app.Get("/health", healthHandler)

    // Prometheus metrics endpoint
    app.Get("/metrics", func(c *fiber.Ctx) error {
        handler := fasthttpadaptor.NewFastHTTPHandler(promhttp.Handler())
        handler(c.Context())
        return nil
    })

    // JWT middleware per endpoint protetti
    app.Use("/user", jwtware.New(jwtware.Config{
        SigningKey:   jwtSecret,
        ErrorHandler: jwtError,
    }))
    
    // JWT middleware per endpoint QR (sia admin che user)
    app.Use("/qr", jwtware.New(jwtware.Config{
        SigningKey:   jwtSecret,
        ErrorHandler: jwtError,
    }))    // QR Attendance System - Admin endpoints (protetti da JWT + adminOnly)
    app.Use("/qr/admin", adminOnly)
    
    // Add detailed logging for QR endpoints
    app.Use("/qr/admin/events/:event_id/*", func(c *fiber.Ctx) error {
        eventID := c.Params("event_id")
        endpoint := c.Path()
        method := c.Method()
        log.Printf("🔍 QR_ENDPOINT_DEBUG: %s %s (event_id: %s)", method, endpoint, eventID)
        return c.Next()
    })
    
    app.Post("/qr/admin/generate", generateQRHandler)
    app.Get("/qr/admin/events", getQRListHandler)
    app.Get("/qr/admin/events/:event_id/attendance", func(c *fiber.Ctx) error {
        log.Printf("🎯 ROUTE_DEBUG: /attendance endpoint called - using getEventUsersHandler")
        return getEventUsersHandler(c)
    })
    app.Get("/qr/admin/events/:event_id/users", func(c *fiber.Ctx) error {
        log.Printf("🎯 ROUTE_DEBUG: /users endpoint called - using getEventUsersHandler") 
        return getEventUsersHandler(c)
    })
    app.Delete("/qr/admin/events/:event_id", deleteEventHandler)
    
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

// Create empty attendance table for selective QR-only system
func createAttendanceTableEmpty(eventID string) error {
    // Sanitize table name (replace hyphens with underscores, ensure valid SQL identifier)
    tableName := "attendance_" + strings.ReplaceAll(eventID, "-", "_")
    
    // Create table with enhanced structure for status management
    createTableQuery := fmt.Sprintf(`
        CREATE TABLE IF NOT EXISTS %s (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            name VARCHAR(255) NOT NULL,
            surname VARCHAR(255) NOT NULL,
            scanned_at TIMESTAMPTZ,
            timestamp TIMESTAMP NULL,
            status VARCHAR(50) DEFAULT 'present' CHECK (status IN ('present', 'hospital', 'family', 'emergency', 'vacancy', 'personal', 'not_registered')),
            motivazione TEXT,
            updated_by INTEGER REFERENCES users(id),
            updated_at TIMESTAMPTZ DEFAULT NOW(),
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id)
        )`, tableName)
    
    _, err := database.DB.Exec(createTableQuery)
    if err != nil {
        return fmt.Errorf("failed to create attendance table %s: %v", tableName, err)
    }
    
    // Create indexes for performance
    indexQueries := []string{
        fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_user_id ON %s(user_id)", tableName, tableName),
        fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_timestamp ON %s(timestamp)", tableName, tableName),
        fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_status ON %s(status)", tableName, tableName),
        fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_updated_at ON %s(updated_at)", tableName, tableName),
        fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_scanned_at ON %s(scanned_at)", tableName, tableName),
    }
    
    for _, indexQuery := range indexQueries {
        if _, err := database.DB.Exec(indexQuery); err != nil {
            log.Printf("Warning: failed to create index for table %s: %v", tableName, err)
        }
    }
    
    log.Printf("✅ Created EMPTY attendance table: %s for selective QR-only system", tableName)
    return nil
}

// Insert attendance record ONLY when user scans QR code (selective system)
func insertAttendanceRecordOnScan(tableName string, userID int, userName, userSurname string) error {
    // Check if user already exists in this event
    checkSQL := fmt.Sprintf("SELECT id, status FROM %s WHERE user_id = $1", tableName)
    var existingID int
    var currentStatus string
    err := database.DB.QueryRow(checkSQL, userID).Scan(&existingID, &currentStatus)
    
    if err == sql.ErrNoRows {
        // User doesn't exist, insert new record with automatic "present" status
        insertSQL := fmt.Sprintf(`
            INSERT INTO %s (user_id, name, surname, scanned_at, status, updated_at) 
            VALUES ($1, $2, $3, NOW(), 'present', NOW())`, tableName)
        
        if _, err := database.DB.Exec(insertSQL, userID, userName, userSurname); err != nil {
            return fmt.Errorf("failed to insert attendance record: %v", err)
        }
        
        log.Printf("✅ NEW USER: Inserted attendance record for user %d (%s %s) with 'present' status", userID, userName, userSurname)
    } else if err == nil {
        // User exists, update scanned_at timestamp and preserve current status
        updateSQL := fmt.Sprintf(`
            UPDATE %s 
            SET scanned_at = NOW(), updated_at = NOW()
            WHERE user_id = $1`, tableName)
        
        if _, err := database.DB.Exec(updateSQL, userID); err != nil {
            return fmt.Errorf("failed to update attendance record: %v", err)
        }
        
        log.Printf("✅ RESCAN: Updated scan time for user %d (%s %s), preserved status '%s'", userID, userName, userSurname, currentStatus)
    } else {
        return fmt.Errorf("failed to check existing attendance: %v", err)
    }
    
    return nil
}

// Wrapper functions for backward compatibility
func getUserFromJWT(c *fiber.Ctx) (int, string, string, string, error) {
    return utils.GetUserFromJWT(c)
}

func generateQRImage(content string) (string, error) {
    // Genera QR code come base64
    qr, err := qrcode.Encode(content, qrcode.Medium, 256)
    if err != nil {
        return "", err
    }
    
    return base64.StdEncoding.EncodeToString(qr), nil
}

func hasUserScannedEventDynamic(userID int, eventID string) (bool, error) {
    tableName := "attendance_" + strings.ReplaceAll(eventID, "-", "_")
    
    // Check if table exists first
    var tableExists bool
    checkTableQuery := `
        SELECT EXISTS (
            SELECT FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_name = $1
        )`
    err := database.DB.QueryRow(checkTableQuery, tableName).Scan(&tableExists)
    if err != nil {
        return false, err
    }
    
    if !tableExists {
        // Table doesn't exist, so user hasn't scanned
        return false, nil
    }
    
    // Check if user has actually SCANNED (scanned_at IS NOT NULL) for this event
    var count int
    query := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE user_id = $1 AND scanned_at IS NOT NULL", tableName)
    err = database.DB.QueryRow(query, userID).Scan(&count)
    if err != nil {
        return false, err
    }
    
    return count > 0, nil
}

func adminOnly(c *fiber.Ctx) error {
    _, _, _, role, err := getUserFromJWT(c)
    if err != nil {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
            "error": "Authentication required",
        })
    }
    
    if role != "admin" {
        return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
            "error": "Admin access required",
        })
    }
    
    return c.Next()
}

func getUsersHandler(c *fiber.Ctx) error {
    // Parametri paginazione
    page := c.QueryInt("page", 1)
    limit := c.QueryInt("limit", 10)
    if page < 1 {
        page = 1
    }
    if limit < 1 || limit > 100 {
        limit = 10
    }
    offset := (page - 1) * limit
    
    // Query utenti
    query := `SELECT id, name, last_name, status, created_at FROM users ORDER BY name ASC LIMIT $1 OFFSET $2`
    rows, err := database.DB.Query(query, limit, offset)
    if err != nil {
        log.Printf("Error querying users: %v", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Errore nel recuperare gli utenti",
        })
    }
    defer rows.Close()
    
    var users []models.User
    for rows.Next() {
        var user models.User
        err := rows.Scan(&user.ID, &user.Name, &user.LastName, &user.Status, &user.CreatedAt)
        if err != nil {
            log.Printf("Error scanning user: %v", err)
            continue
        }
        users = append(users, user)
    }
    
    // Conta totale
    var total int
    countQuery := `SELECT COUNT(*) FROM users`
    err = database.DB.QueryRow(countQuery).Scan(&total)
    if err != nil {
        total = len(users)
    }
    
    response := models.UsersResponse{
        Users: users,
        Total: total,
        Page:  page,
        Limit: limit,
    }
    
    return c.JSON(response)
}

func getUserByIDHandler(c *fiber.Ctx) error {
    id, err := strconv.Atoi(c.Params("id"))
    if err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "ID non valido",
        })
    }
    
    var user models.User
    query := `SELECT id, name, last_name, status, created_at FROM users WHERE id = $1`
    err = database.DB.QueryRow(query, id).Scan(
        &user.ID, &user.Name, &user.LastName, &user.Status, &user.CreatedAt,
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

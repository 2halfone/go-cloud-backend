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

    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/fiber/v2/middleware/cors"
    jwtware "github.com/gofiber/jwt/v3"
    "github.com/golang-jwt/jwt/v4"
    "github.com/skip2/go-qrcode"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "github.com/valyala/fasthttp/fasthttpadaptor"
    _ "github.com/lib/pq"
)

// JWT secret - loaded from environment variable JWT_SECRET
var jwtSecret []byte

// Auth service database connection
var authDB *sql.DB

// Prometheus metrics
var (
    // HTTP Metrics
    httpRequestsTotal = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "http_requests_total",
            Help: "Total number of HTTP requests",
        },
        []string{"method", "endpoint", "status_code", "service"},
    )

    httpRequestDuration = promauto.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "http_request_duration_seconds",
            Help:    "Duration of HTTP requests in seconds",
            Buckets: prometheus.DefBuckets,
        },
        []string{"method", "endpoint", "service"},
    )

    // QR Code Metrics
    qrScansTotal = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "qr_scans_total",
            Help: "Total number of QR code scans",
        },
        []string{"event_id", "status", "service"},
    )

    qrEventsTotal = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "qr_events_total",
            Help: "Total number of QR events created",
        },
        []string{"service"},
    )

    // Active Users
    activeUsers = promauto.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "active_users_total",
            Help: "Number of active users",
        },
        []string{"service"},
    )

    // Database Connections
    databaseConnections = promauto.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "database_connections_active",
            Help: "Number of active database connections",
        },
        []string{"service", "database"},
    )

    // System Errors
    systemErrorsTotal = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "system_errors_total",
            Help: "Total number of system errors",
        },
        []string{"service", "error_type"},
    )

    // Attendance Events
    attendanceEventsTotal = promauto.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "attendance_events_active",
            Help: "Number of active attendance events",
        },
        []string{"service"},
    )
)

// Metrics middleware for HTTP requests
func metricsMiddleware() fiber.Handler {
    return func(c *fiber.Ctx) error {
        start := time.Now()

        // Process the request
        err := c.Next()

        duration := time.Since(start)
        statusCode := strconv.Itoa(c.Response().StatusCode())

        // Record metrics
        httpRequestsTotal.WithLabelValues(
            c.Method(),
            c.Path(),
            statusCode,
            "user-service",
        ).Inc()

        httpRequestDuration.WithLabelValues(
            c.Method(),
            c.Path(),
            "user-service",
        ).Observe(duration.Seconds())

        return err
    }
}

// Update active users count
func updateActiveUsersCount() {
    db := database.DB
    if db != nil {
        var count int
        query := `SELECT COUNT(*) FROM users WHERE status = 'active'`
        if err := db.QueryRow(query).Scan(&count); err == nil {
            activeUsers.WithLabelValues("user-service").Set(float64(count))
        }
    }
}

// Update database connections count
func updateDatabaseConnections() {
    db := database.DB
    if db != nil {
        stats := db.Stats()
        databaseConnections.WithLabelValues("user-service", "user_db").Set(float64(stats.OpenConnections))
    }
    
    if authDB != nil {
        stats := authDB.Stats()
        databaseConnections.WithLabelValues("user-service", "auth_db").Set(float64(stats.OpenConnections))
    }
}

// Update attendance events count
func updateAttendanceEventsCount() {
    db := database.DB
    if db != nil {
        var count int
        query := `SELECT COUNT(*) FROM attendance_events WHERE is_active = true AND expires_at > NOW()`
        if err := db.QueryRow(query).Scan(&count); err == nil {
            attendanceEventsTotal.WithLabelValues("user-service").Set(float64(count))
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
    Status      string    `json:"status"`
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
      // Estrai il ruolo dal JWT invece del database
    role, ok := claims["role"].(string)
    if !ok {
        log.Printf("getUserFromJWT: role not found in JWT claims, defaulting to 'user'")
        role = "user"
    }
    
    // Estrai name e surname dal JWT invece del database
    name, ok := claims["name"].(string)
    if !ok {
        log.Printf("getUserFromJWT: name not found in JWT claims")
        name = "Unknown"
    }
    
    surname, ok := claims["surname"].(string)
    if !ok {
        log.Printf("getUserFromJWT: surname not found in JWT claims")
        surname = "User"
    }
    
    log.Printf("getUserFromJWT: Successfully extracted from JWT - userID=%d, name='%s', surname='%s', role='%s'", userID, name, surname, role)
    
    return userID, name, surname, role, nil
}

// Create dynamic attendance table for each event with enhanced status management
func createAttendanceTable(eventID string) error {
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
            status VARCHAR(50) DEFAULT 'not_registered' CHECK (status IN ('present', 'hospital', 'family', 'emergency', 'vacancy', 'personal', 'not_registered')),
            motivazione TEXT,
            updated_by INTEGER REFERENCES users(id),
            updated_at TIMESTAMPTZ DEFAULT NOW(),
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id)
        )`, tableName)
    
    _, err := database.DB.Exec(createTableQuery)
    if err != nil {
        return fmt.Errorf("failed to create attendance table %s: %v", tableName, err)
    }    // DISABLED: Do not use automated setup that installs problematic triggers
    // setupSQL := "SELECT setup_new_attendance_table($1)"
    log.Printf("Skipping automated trigger setup to avoid auto-present issue for table %s", tableName)
    
    // Manual setup WITHOUT problematic triggers
    log.Printf("Setting up table %s without auto-present triggers", tableName)
      // Manual setup WITHOUT problematic triggers
    log.Printf("Setting up table %s without auto-present triggers", tableName)
        
        // Manual index creation (keep the indexes, just skip the problematic trigger)
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
        
        // Manual user population
        if err := populateEventUsers(tableName); err != nil {
            log.Printf("Warning: failed to populate users for table %s: %v", tableName, err)
        }

    log.Printf("✅ Created attendance table: %s with enhanced status management", tableName)
    return nil
}

// Populate all active users into event table with default status
func populateEventUsers(tableName string) error {
    // Get all active users
    query := `SELECT id, name, last_name FROM users WHERE status = 'active'`
    rows, err := database.DB.Query(query)
    if err != nil {
        return fmt.Errorf("failed to query users: %v", err)
    }
    defer rows.Close()
    
    userCount := 0
    for rows.Next() {
        var userID int
        var name, lastName string
        
        err := rows.Scan(&userID, &name, &lastName)
        if err != nil {
            log.Printf("Error scanning user: %v", err)
            continue
        }
        
        // Insert user with default status 'not_registered'
        insertQuery := fmt.Sprintf(`
            INSERT INTO %s (user_id, name, surname, status, timestamp, updated_at) 
            VALUES ($1, $2, $3, $4, NULL, NOW()) 
            ON CONFLICT (user_id) DO NOTHING`, tableName)
        
        _, err = database.DB.Exec(insertQuery, userID, name, lastName, "not_registered")
        if err != nil {
            log.Printf("Error inserting user %d into %s: %v", userID, tableName, err)
            continue
        }
        
        userCount++
    }
    
    log.Printf("✅ Populated %d users in event table %s", userCount, tableName)
    return nil
}

// Check if user has scanned for a specific event (using dynamic table)
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
    
    // Check if user exists in the event's attendance table
    var count int
    query := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE user_id = $1", tableName)
    err = database.DB.QueryRow(query, userID).Scan(&count)
    if err != nil {
        return false, err
    }
    
    return count > 0, nil
}

// Insert or update attendance record for QR scan - FIXED to properly update scanned_at
func insertAttendanceRecord(tableName string, userID int, userName, userSurname string) error {
    // Check if user already exists in this event
    checkSQL := fmt.Sprintf("SELECT id FROM %s WHERE user_id = $1", tableName)
    var existingID int
    err := database.DB.QueryRow(checkSQL, userID).Scan(&existingID)
    
    if err == sql.ErrNoRows {
        // User doesn't exist, insert new record with scanned_at timestamp
        insertSQL := fmt.Sprintf(`
            INSERT INTO %s (user_id, name, surname, scanned_at, status, updated_at) 
            VALUES ($1, $2, $3, NOW(), 'not_registered', NOW())`, tableName)
        
        if _, err := database.DB.Exec(insertSQL, userID, userName, userSurname); err != nil {
            return fmt.Errorf("failed to insert attendance record: %v", err)
        }
        
        log.Printf("✅ Inserted new attendance record for user %d with scanned_at timestamp", userID)    } else if err == nil {
        // User exists, update only scanned_at timestamp (don't set status yet)
        updateSQL := fmt.Sprintf(`
            UPDATE %s 
            SET scanned_at = NOW(), updated_at = NOW()
            WHERE user_id = $1`, tableName)
        
        if _, err := database.DB.Exec(updateSQL, userID); err != nil {
            return fmt.Errorf("failed to update attendance record: %v", err)
        }
        
        log.Printf("✅ Updated scanned_at timestamp for user %d (status remains unchanged for manual admin setting)", userID)
    } else {
        return fmt.Errorf("failed to check existing attendance: %v", err)
    }
    
    return nil
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
        query = `SELECT id, name, last_name, status, created_at FROM users WHERE status = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
        countQuery = `SELECT COUNT(*) FROM users WHERE status = $1`
        args = []interface{}{status, limit, offset}
        countArgs = []interface{}{status}
    } else {
        query = `SELECT id, name, last_name, status, created_at FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2`
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
        err := rows.Scan(&user.ID, &user.Name, &user.LastName, &user.Status, &user.CreatedAt)
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
      query := `SELECT id, name, last_name, status, created_at FROM users WHERE id = $1`
    var user User
    
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
    app.Use(metricsMiddleware())

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
    app.Post("/qr/admin/generate", generateQRHandler)
    app.Get("/qr/admin/events", getQRListHandler)
    app.Get("/qr/admin/events/:event_id/attendance", getEventAttendanceHandler)
    app.Get("/qr/admin/events/:event_id/users", getEventUsersHandler)
    app.Patch("/qr/admin/events/:event_id/users/:user_id/status", updateUserStatusHandler)
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

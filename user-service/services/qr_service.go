package services

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
	"user-service/database"
	"user-service/models"

	"github.com/golang-jwt/jwt/v4"
	"github.com/skip2/go-qrcode"
)

// JWT secret - loaded from environment variable JWT_SECRET
var jwtSecret []byte

// Auth service database connection
var authDB *sql.DB

// Initialize JWT secret and auth database connection
func InitializeServices() error {
	// Load JWT secret
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return fmt.Errorf("JWT_SECRET environment variable not set")
	}
	jwtSecret = []byte(secret)

	// Connect to auth database
	return connectToAuthDB()
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

// Funzioni helper per JWT QR
func GenerateQRJWT(eventID, eventName, date string, createdBy int) (string, error) {
	// Parse della data per impostare la scadenza
	dateTime, err := time.Parse("2006-01-02", date)
	if err != nil {
		return "", fmt.Errorf("formato data non valido: %v", err)
	}

	// Scadenza a fine giornata
	expiresAt := time.Date(dateTime.Year(), dateTime.Month(), dateTime.Day(), 23, 59, 59, 0, dateTime.Location())

	claims := models.QRJWTClaims{
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

func ValidateQRJWT(tokenString string) (*models.QRJWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &models.QRJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*models.QRJWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("token non valido")
}

func IsValidStatus(status string) bool {
	for _, valid := range models.ValidStatuses {
		if status == valid {
			return true
		}
	}
	return false
}

// Get user from auth-service database
func GetUserFromAuthDB(userID int) (*models.AuthUser, error) {
	query := `SELECT id, email, username, name, surname, role, created_at FROM users WHERE id = $1`
	var user models.AuthUser

	err := authDB.QueryRow(query, userID).Scan(
		&user.ID, &user.Email, &user.Username, &user.Name, &user.Surname, &user.Role, &user.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &user, nil
}

// Check if user exists in user-service database
func UserExistsInUserService(userID int) (bool, error) {
	var count int
	query := `SELECT COUNT(*) FROM users WHERE id = $1`
	err := database.DB.QueryRow(query, userID).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// Sync user from auth-service to user-service
func SyncUserFromAuthService(userID int) error {
	// Check if user already exists in user-service
	exists, err := UserExistsInUserService(userID)
	if err != nil {
		return fmt.Errorf("failed to check user existence: %v", err)
	}

	if exists {
		log.Printf("User %d already exists in user-service", userID)
		return nil
	}

	// Get user from auth-service
	authUser, err := GetUserFromAuthDB(userID)
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
func EnsureUserExists(userID int) error {
	exists, err := UserExistsInUserService(userID)
	if err != nil {
		return err
	}

	if !exists {
		log.Printf("User %d not found in user-service, attempting to sync from auth-service", userID)
		return SyncUserFromAuthService(userID)
	}

	return nil
}

// Create dynamic attendance table for each event with enhanced status management
func CreateAttendanceTable(eventID string) error {
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
	}	// DISABLED: Use the new automated setup function from migration 0009
	// setupSQL := "SELECT setup_new_attendance_table($1)"
	log.Printf("Skipping automated trigger setup to avoid auto-present issue for table %s", tableName)
	
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
	if err := PopulateEventUsers(tableName); err != nil {
		log.Printf("Warning: failed to populate users for table %s: %v", tableName, err)
	}

	log.Printf("✅ Created attendance table: %s with enhanced status management", tableName)
	return nil
}

// Populate all active users into event table with default status
func PopulateEventUsers(tableName string) error {
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
func HasUserScannedEventDynamic(userID int, eventID string) (bool, error) {
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

// Insert or update attendance record for QR scan (trigger auto-sets status to 'present')
func InsertAttendanceRecord(tableName string, userID int, userName, userSurname string) error {
	// Check if user already exists in this event
	checkSQL := fmt.Sprintf("SELECT id FROM %s WHERE user_id = $1", tableName)
	var existingID int
	err := database.DB.QueryRow(checkSQL, userID).Scan(&existingID)

	if err == sql.ErrNoRows {
		// User doesn't exist, insert new record
		// The trigger will automatically set status to 'present' and scanned_at
		insertSQL := fmt.Sprintf(`
            INSERT INTO %s (user_id, name, surname, scanned_at, status, updated_at) 
            VALUES ($1, $2, $3, NOW(), 'not_registered', NOW())`, tableName)

		if _, err := database.DB.Exec(insertSQL, userID, userName, userSurname); err != nil {
			return fmt.Errorf("failed to insert attendance record: %v", err)
		}

		log.Printf("✅ Inserted new attendance record for user %d (trigger will set to present)", userID)	} else if err == nil {
		// User exists, update only scanned_at timestamp (don't force status to present)
		updateSQL := fmt.Sprintf(`
            UPDATE %s 
            SET scanned_at = NOW(), updated_at = NOW()
            WHERE user_id = $1`, tableName)

		if _, err := database.DB.Exec(updateSQL, userID); err != nil {
			return fmt.Errorf("failed to update attendance record: %v", err)
		}

		log.Printf("✅ Updated scan time for user %d (status remains unchanged for manual admin setting)", userID)
	} else {
		return fmt.Errorf("failed to check existing attendance: %v", err)
	}

	return nil
}

func HasUserScannedEvent(userID int, eventID string) (bool, error) {
	var count int
	query := `SELECT COUNT(*) FROM attendance WHERE user_id = $1 AND event_id = $2`
	err := database.DB.QueryRow(query, userID, eventID).Scan(&count)
	return count > 0, err
}

func GenerateQRImage(content string) (string, error) {
	// Genera QR code come base64
	qr, err := qrcode.Encode(content, qrcode.Medium, 256)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(qr), nil
}

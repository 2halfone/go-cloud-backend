package models

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
)

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

type UserRequest struct {
	Name     string `json:"name"`
	LastName string `json:"last_name"`
	Status   string `json:"status"`
}

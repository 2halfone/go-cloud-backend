package main

import (
    "log"
    "time"

    "github.com/gofiber/fiber/v2"
    jwtware "github.com/gofiber/jwt/v3"
    "github.com/golang-jwt/jwt/v4"
)

// Secret condiviso con auth-service
var jwtSecret = []byte("la-tua-chiave-segreta-qui")

// Strutture dati per QR e scelte
type QRScan struct {
    QRCode    string    `json:"qr_code"`
    Location  string    `json:"location"`
    Timestamp time.Time `json:"timestamp"`
}

type UserChoice struct {
    ID        string    `json:"id"`
    UserEmail string    `json:"user_email"`
    QRCode    string    `json:"qr_code"`
    Choice    string    `json:"choice"`
    Location  string    `json:"location"`
    Metadata  string    `json:"metadata"`
    Timestamp time.Time `json:"timestamp"`
}

// Storage in memoria
var qrScans = []QRScan{}
var userChoices = []UserChoice{}

// Request types
type QRScanRequest struct {
    QRCode   string `json:"qr_code"`
    Location string `json:"location"`
}

type UserChoiceRequest struct {
    QRCode   string `json:"qr_code"`
    Choice   string `json:"choice"`
    Location string `json:"location"`
    Metadata string `json:"metadata"`
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

func main() {
    app := fiber.New(fiber.Config{
        AppName: "User Service v1.0",
    })

    // Endpoint pubblici
    app.Get("/health", healthHandler)
    app.Post("/qr/scan", qrScanHandler)

    // JWT middleware per endpoint protetti
    app.Use("/user", jwtware.New(jwtware.Config{
        SigningKey: jwtSecret,
        ErrorHandler: func(c *fiber.Ctx, err error) error {
            return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
                "error": "Token non valido o mancante",
            })
        },
    }))

    // Endpoint protetti
    app.Get("/user/profile", userProfileHandler)
    app.Post("/user/choice", saveChoiceHandler)
    app.Get("/user/choices", getUserChoicesHandler)

    log.Println("🚀 User Service completo avviato sulla porta 3002")
    log.Fatal(app.Listen(":3002"))
}

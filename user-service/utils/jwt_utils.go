package utils

import (
	"fmt"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
)

// GetUserFromJWT estrae i dati dell'utente dal JWT token nel contesto Fiber
func GetUserFromJWT(c *fiber.Ctx) (int, string, string, string, error) {
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

// AdminOnly middleware per verificare ruolo admin
func AdminOnly(c *fiber.Ctx) error {
	log.Printf("AdminOnly middleware: Processing request to %s", c.Path())

	// Verifica che il JWT sia presente
	user := c.Locals("user")
	if user == nil {
		log.Printf("AdminOnly middleware: No JWT user found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Token JWT mancante o non valido",
		})
	}

	userID, name, surname, role, err := GetUserFromJWT(c)
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
			"error":         "Accesso negato: richiesti privilegi admin",
			"user_role":     role,
			"required_role": "admin",
		})
	}

	log.Printf("AdminOnly middleware: Admin access granted for user %d", userID)
	return c.Next()
}

// JwtError handles JWT authentication errors
func JwtError(c *fiber.Ctx, err error) error {
	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
		"error": "Token non valido o mancante",
	})
}

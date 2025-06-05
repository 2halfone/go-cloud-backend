package main

import (
    "log"
    "time"

    "github.com/gofiber/fiber/v2"
    jwtware "github.com/gofiber/jwt/v3"
    "github.com/golang-jwt/jwt/v4"
    "golang.org/x/crypto/bcrypt"
)

// Secret usato per firmare il JWT (in produzione caricalo da variabile d'ambiente)
var jwtSecret = []byte("la-tua-chiave-segreta-qui")

// User rappresenta un utente registrato (per semplicità, memorizzato in memoria)
type User struct {
    Email    string
    Password string // hashed
}

// In-memory store molto semplice (map da email → User)
var users = map[string]User{}

// request payload per /register
type registerRequest struct {
    Email    string `json:"email"`
    Password string `json:"password"`
}

func registerHandler(c *fiber.Ctx) error {
    var req registerRequest
    if err := c.BodyParser(&req); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Payload non valido",
        })
    }

    // Controlla se l'utente esiste già
    if _, exists := users[req.Email]; exists {
        return c.Status(fiber.StatusConflict).JSON(fiber.Map{
            "error": "Utente già registrato",
        })
    }

    // Hash della password
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Errore server nel processare la password",
        })
    }

    // Salva l'utente in memoria
    users[req.Email] = User{
        Email:    req.Email,
        Password: string(hashedPassword),
    }

    return c.Status(fiber.StatusCreated).JSON(fiber.Map{
        "message": "Registrazione avvenuta con successo",
    })
}

// request payload per /login
type loginRequest struct {
    Email    string `json:"email"`
    Password string `json:"password"`
}

func loginHandler(c *fiber.Ctx) error {
    var req loginRequest
    if err := c.BodyParser(&req); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Payload non valido",
        })
    }

    // Controlla se l'utente esiste
    user, exists := users[req.Email]
    if !exists {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
            "error": "Credenziali errate",
        })
    }

    // Verifica password
    if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
            "error": "Credenziali errate",
        })
    }

    // Genera JWT
    token := jwt.New(jwt.SigningMethodHS256)
    claims := token.Claims.(jwt.MapClaims)
    claims["email"] = user.Email
    claims["exp"] = time.Now().Add(24 * time.Hour).Unix() // scade dopo 24h

    tokenString, err := token.SignedString(jwtSecret)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Impossibile generare il token",
        })
    }

    return c.JSON(fiber.Map{
        "token": tokenString,
    })
}

func main() {
    app := fiber.New()    // Endpoint per registrare un nuovo utente
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

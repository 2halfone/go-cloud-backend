package main

import (
    "log"

    "github.com/gofiber/fiber/v2"
    jwtware "github.com/gofiber/jwt/v3"
    "github.com/gofiber/fiber/v2/middleware/proxy"
)

// Deve corrispondere esattamente alla chiave segreta di auth-service
var jwtSecret = []byte("la-tua-chiave-segreta-qui")

func main() {
    app := fiber.New()

    // -------------------------------------------------------
    // 1) Middleware globale per validare il JWT in ingresso
    // -------------------------------------------------------
    // Tutte le rotte “protette” passeranno da qui: controlla che il token sia valido,
    // che non sia scaduto e che la firma corrisponda.
    app.Use(jwtware.New(jwtware.Config{
        SigningKey:   jwtSecret,
        ErrorHandler: jwtError, // funzione personalizzata per gestire errori JWT
    }))

    // -------------------------------------------------------
    // 2) Configurazione delle rotte proxy
    // -------------------------------------------------------
    // Inoltra tutto ciò che arriva su /user/* verso user-service (porta 3002)
    app.All("/user/*", func(c *fiber.Ctx) error {
        // Costruisci l’URL di destinazione: mantieni il path completo (/user/…)
        target := "http://localhost:3002" + c.OriginalURL()
        // Inoltra la richiesta con tutti gli header (incluso Authorization)
        return proxy.Do(c, target)
    })

    // Inoltra tutto ciò che arriva su /shop/* verso shop-service (porta 3003)
    app.All("/shop/*", func(c *fiber.Ctx) error {
        target := "http://localhost:3003" + c.OriginalURL()
        return proxy.Do(c, target)
    })

    // Inoltra tutto ciò che arriva su /chat/* verso chat-service (porta 3004)
    app.All("/chat/*", func(c *fiber.Ctx) error {
        target := "http://localhost:3004" + c.OriginalURL()
        return proxy.Do(c, target)
    })

    // Rotta di default (opzionale): se qualcuno chiama la root, possiamo rispondere con un messaggio informativo
    app.Get("/", func(c *fiber.Ctx) error {
        return c.JSON(fiber.Map{
            "message": "Gateway attivo. Rotte: /user/*, /shop/*, /chat/* (richiede JWT)",
        })
    })

    log.Println("Gateway in ascolto sulla porta 3000")
    if err := app.Listen(":3000"); err != nil {
        log.Fatal(err)
    }
}

// jwtError viene invocata se il token non è valido o è assente.
// Possiamo restituire un JSON con errore 401.
func jwtError(c *fiber.Ctx, err error) error {
    return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
        "error": "Accesso negato: token non valido o mancante",
    })
}

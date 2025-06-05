package main

import (
    "github.com/gofiber/fiber/v2"
    "log"
)

func main() {
    app := fiber.New()
    app.Get("/user/profile", func(c *fiber.Ctx) error {
        return c.JSON(fiber.Map{
            "userId": "abc123",
            "email":  "prova@example.com",
            "name":   "Mario Rossi",
        })
    })

    log.Println("User-service in ascolto sulla porta 3002")
    log.Fatal(app.Listen(":3002"))
}

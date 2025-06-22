package main

import "github.com/gofiber/fiber/v2"

func SocialLogHandler(c *fiber.Ctx) error {
	// Gestione richiesta log
	return c.SendStatus(201)
}

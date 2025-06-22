package main

import (
	"log"
	"os"
	"database/sql"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	_ "github.com/lib/pq"

	"go-cloud-backend/shared/metrics"
)

func main() {
	log.Println("Social Log Service avviato")
	metrics.InitMetrics()

	db, err := sql.Open("postgres", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	app := fiber.New()
	app.Use(metrics.HTTPMetricsMiddleware("social-log-service"))

	app.Post("/api/social/log", func(c *fiber.Ctx) error {
		var logReq SocialLog
		if err := c.BodyParser(&logReq); err != nil {
			metrics.RecordSystemError("body_parse", "social-log-service")
			return c.Status(400).JSON(fiber.Map{"error": "Invalid body"})
		}
		if logReq.Social == "" || logReq.Content == "" || logReq.Status == "" || logReq.Timestamp == "" {
			metrics.RecordSystemError("missing_fields", "social-log-service")
			return c.Status(400).JSON(fiber.Map{"error": "Missing fields"})
		}
		_, err := db.Exec(`INSERT INTO social_logs (social, timestamp, content, status) VALUES ($1, $2, $3, $4)`, logReq.Social, logReq.Timestamp, logReq.Content, logReq.Status)
		if err != nil {
			metrics.RecordSystemError("db_error", "social-log-service")
			return c.Status(500).JSON(fiber.Map{"error": "DB error"})
		}
		return c.SendStatus(201)
	})

	app.Get("/metrics", func(c *fiber.Ctx) error {
		promhttp.Handler().ServeHTTP(c.Context().Response.BodyWriter(), c.Context().Request)
		return nil
	})

	log.Fatal(app.Listen(":8080"))
}

// Trigger test: aggiunto commento per forzare workflow

type SocialLog struct {
	Social   string    `json:"social"`
	Timestamp time.Time `json:"timestamp"`
	Content   string    `json:"content"`
	Status    string    `json:"status"`
}

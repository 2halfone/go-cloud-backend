//. user-service/database/connection.go
package database

import (
    "database/sql"
    "log"
    "os"
    _ "github.com/lib/pq"
)

var DB *sql.DB

func Connect() {
    var err error
    dbURL := os.Getenv("USER_DATABASE_URL")
    
    DB, err = sql.Open("postgres", dbURL)
    if err != nil {
        log.Fatal("Failed to connect to user database:", err)
    }
    
    if err = DB.Ping(); err != nil {
        log.Fatal("Failed to ping user database:", err)
    }
    
    log.Println("✅ Connected to user database")
}

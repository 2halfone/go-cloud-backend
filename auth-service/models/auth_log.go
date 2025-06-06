// auth-service/models/auth_log.go
package models

import (
    "time"
    "auth-service/database"
)

type AuthLog struct {
    ID        int       `json:"id"`
    UserEmail string    `json:"user_email"`
    Action    string    `json:"action"`
    Timestamp time.Time `json:"timestamp"`
}

func LogAuthAction(userEmail, action string) error {
    query := `INSERT INTO auth_logs (user_email, action) VALUES ($1, $2)`
    _, err := database.DB.Exec(query, userEmail, action)
    return err
}

func GetAuthLogs() ([]AuthLog, error) {
    query := `SELECT id, user_email, action, timestamp FROM auth_logs ORDER BY timestamp DESC`
    rows, err := database.DB.Query(query)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    
    var logs []AuthLog
    for rows.Next() {
        var log AuthLog
        err := rows.Scan(&log.ID, &log.UserEmail, &log.Action, &log.Timestamp)
        if err != nil {
            continue
        }
        logs = append(logs, log)
    }
    return logs, nil
}
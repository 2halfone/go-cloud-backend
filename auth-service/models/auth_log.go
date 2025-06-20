// auth-service/models/auth_log.go
package models

import (
    "auth-service/database"
    "fmt"
    "log"
    "time"
)

type AuthLog struct {
    ID        int       `json:"id"`
    UserEmail string    `json:"user_email"`
    Username  string    `json:"username,omitempty"`
    Action    string    `json:"action"`
    Timestamp time.Time `json:"timestamp"`
    IPAddress string    `json:"ip_address,omitempty"`
    UserAgent string    `json:"user_agent,omitempty"`
    Success   bool      `json:"success"`
}

func LogAuthAction(userEmail, action string) error {
    query := `INSERT INTO auth_logs (user_email, action) VALUES ($1, $2)`
    _, err := database.DB.Exec(query, userEmail, action)
    return err
}

// LogAuthActionDetailed logs authentication with additional details
func LogAuthActionDetailed(userEmail, username, action, ipAddress, userAgent string, success bool) (err error) {
    defer func() {
        if r := recover(); r != nil {
            log.Printf("PANIC in LogAuthActionDetailed: %v (userEmail=%s, action=%s)", r, userEmail, action)
            err = fmt.Errorf("panic: %v", r)
        }
    }()
    if database.DB == nil {
        log.Printf("LogAuthActionDetailed: database.DB is nil! userEmail=%s, action=%s", userEmail, action)
        return fmt.Errorf("database.DB is nil")
    }
    query := `INSERT INTO auth_logs (user_email, action, ip_address, user_agent, success) VALUES ($1, $2, $3, $4, $5)`
    _, err = database.DB.Exec(query, userEmail, action, ipAddress, userAgent, success)
    if err != nil {
        log.Printf("LogAuthActionDetailed: DB Exec error: %v (userEmail=%s, action=%s)", err, userEmail, action)
    }
    return err
}

func GetAuthLogs() ([]AuthLog, error) {
    query := `
        SELECT al.id, al.user_email, al.action, al.timestamp,
               COALESCE(al.ip_address, '') as ip_address,
               COALESCE(al.user_agent, '') as user_agent,
               COALESCE(al.success, true) as success,
               COALESCE(u.username, '') as username
        FROM auth_logs al
        LEFT JOIN users u ON al.user_email = u.email
        ORDER BY al.timestamp DESC`
    rows, err := database.DB.Query(query)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    
    var logs []AuthLog
    for rows.Next() {
        var log AuthLog
        err := rows.Scan(&log.ID, &log.UserEmail, &log.Action, &log.Timestamp, 
                        &log.IPAddress, &log.UserAgent, &log.Success, &log.Username)
        if err != nil {
            continue
        }
        logs = append(logs, log)
    }
    return logs, nil
}
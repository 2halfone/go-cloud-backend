package main

import (
    "database/sql"
    "encoding/json"
    "fmt"
    "log"
    "strings"
    "time"
    "user-service/database"

    "github.com/gofiber/fiber/v2"
    "go-cloud-backend/shared/metrics"
)

// ============================================================================
// QR ATTENDANCE SYSTEM HANDLERS
// ============================================================================

// Handler per generare QR code (admin only)
func generateQRHandler(c *fiber.Ctx) error {
    var req GenerateQRRequest
    if err := c.BodyParser(&req); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Payload non valido",
        })
    }
    
    // Validazioni
    if req.EventName == "" || req.Date == "" {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Nome evento e data sono richiesti",
        })
    }
      // Valida formato data
    _, err := time.Parse("2006-01-02", req.Date)
    if err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Formato data non valido (YYYY-MM-DD)",
        })
    }
    
    userID, _, _, _, err := getUserFromJWT(c)
    if err != nil {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
            "error": "Errore autenticazione",
        })
    }
    
    // Genera event_id univoco basato su nome evento + data
    eventNameSlug := strings.ToLower(strings.ReplaceAll(req.EventName, " ", "-"))
    eventID := fmt.Sprintf("%s-%s", eventNameSlug, req.Date)
    
    log.Printf("generateQRHandler: Generated event_id: %s", eventID)
    
    // Controlla se esiste già questo specifico evento (non solo la data)
    var existingID int
    checkQuery := `SELECT id FROM attendance_events WHERE event_id = $1`
    err = database.DB.QueryRow(checkQuery, eventID).Scan(&existingID)
    if err == nil {
        log.Printf("generateQRHandler: Event already exists: %s", eventID)
        return c.Status(fiber.StatusConflict).JSON(fiber.Map{
            "error": fmt.Sprintf("Evento '%s' per la data %s già esistente", req.EventName, req.Date),
            "event_id": eventID,
        })
    }
      // Genera JWT per QR
    qrJWT, err := generateQRJWT(eventID, req.EventName, req.Date, userID)
    err = nil
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Errore generazione JWT",
        })
    }
    
    // Crea contenuto QR
    qrContent := QRContent{
        JWT:     qrJWT,
        Type:    "attendance_qr",
        Version: "1.0",
    }
    
    qrContentJSON, err := json.Marshal(qrContent)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Errore serializzazione QR",
        })
    }
    
    // Genera immagine QR
    qrImageBase64, err := generateQRImage(string(qrContentJSON))
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Errore generazione immagine QR",
        })
    }
    
    // Calcola scadenza
    dateTime, _ := time.Parse("2006-01-02", req.Date)
    expiresAt := time.Date(dateTime.Year(), dateTime.Month(), dateTime.Day(), 23, 59, 59, 0, dateTime.Location())
      // Salva nel database
    insertQuery := `
        INSERT INTO attendance_events (event_id, event_name, date, qr_jwt, expires_at, created_by)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id`
      var newEventID int
    err = database.DB.QueryRow(insertQuery, eventID, req.EventName, dateTime, qrJWT, expiresAt, userID).Scan(&newEventID)
    if err != nil {
        log.Printf("Error creating attendance event: %v", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Errore salvataggio evento",
        })
    }
    
    log.Printf("generateQRHandler: Event created successfully with ID: %d, event_id: %s", newEventID, eventID)
    
    // Create EMPTY attendance table for selective QR-only system
    err = createAttendanceTableEmpty(eventID)
    if err != nil {
        log.Printf("generateQRHandler: Warning - failed to create empty attendance table: %v", err)
        // Don't fail the request, just log the warning
    } else {
        log.Printf("generateQRHandler: ✅ Created EMPTY table for selective QR-only participation")
    }
    
    // Record QR event creation metric
    metrics.QREventsTotal.WithLabelValues("user-service").Inc()
    
    return c.Status(fiber.StatusCreated).JSON(fiber.Map{
        "message":         "QR generato con successo",
        "event_id":        eventID,
        "event_name":      req.EventName,
        "date":            req.Date,
        "expires_at":      expiresAt.Format(time.RFC3339),
        "qr_content":      string(qrContentJSON),
        "qr_image_base64": "data:image/png;base64," + qrImageBase64,
    })
}

// Handler per scansionare QR e registrare presenza
func scanQRHandler(c *fiber.Ctx) error {
    var req AttendanceRequest
    if err := c.BodyParser(&req); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Payload non valido",
        })
    }
      // Validazioni
    if req.QRContent.JWT == "" {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "QR content è richiesto",
        })
    }
    
    // Validate QR type (mantieni validazione QR essenziale)
    if req.QRContent.Type != "" && req.QRContent.Type != "attendance_qr" {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Tipo QR non supportato",
            "received_type": req.QRContent.Type,
        })
    }
    
    // Ottieni user da JWT
    userID, name, surname, role, err := getUserFromJWT(c)
    if err != nil {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
            "error": "Errore autenticazione",
        })
    }
    
    // Valida JWT del QR
    qrClaims, err := validateQRJWT(req.QRContent.JWT)
    if err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "QR non valido o scaduto",
        })
    }
    
    // Controlla se QR esiste nel database
    var eventExists bool
    checkEventQuery := `SELECT EXISTS(SELECT 1 FROM attendance_events WHERE event_id = $1 AND is_active = true)`
    err = database.DB.QueryRow(checkEventQuery, qrClaims.EventID).Scan(&eventExists)
    if err != nil || !eventExists {
        return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
            "error": "Evento non trovato o non attivo",
        })
    }
      // Controlla se user ha già scansionato per questo evento (solo per user normali)
    if role != "admin" {
        hasScanned, err := hasUserScannedEventDynamic(userID, qrClaims.EventID)
        if err != nil {
            log.Printf("Error checking user scan: %v", err)
            return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
                "error": "Errore verifica presenza esistente",
            })
        }
        
        if hasScanned {
            return c.Status(fiber.StatusConflict).JSON(fiber.Map{
                "error": "Hai già registrato la presenza per questo evento",
            })
        }    }
    
    // Ensure user exists in user-service database (auto-sync from auth-service if needed)
    err = ensureUserExists(userID)
    if err != nil {
        log.Printf("Error ensuring user exists: %v", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Errore sincronizzazione utente",
            "details": err.Error(),
        })    }        // Registra presenza nella tabella dinamica dell'evento con sistema selettivo
    tableName := "attendance_" + strings.ReplaceAll(qrClaims.EventID, "-", "_")
    err = insertAttendanceRecordOnScan(tableName, userID, name, surname)
    if err != nil {
        log.Printf("Error saving attendance: %v", err)
        // Record failed QR scan metric
        metrics.QRScansTotal.WithLabelValues(qrClaims.EventID, "failed", "user-service").Inc()
        metrics.SystemErrorsTotal.WithLabelValues("user-service", "database_error").Inc()
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Errore salvataggio presenza",
        })
    }
      // Record successful QR scan metric
    metrics.QRScansTotal.WithLabelValues(qrClaims.EventID, "success", "user-service").Inc()

    return c.Status(fiber.StatusCreated).JSON(fiber.Map{
        "success":     true,
        "message":     "Presenza registrata automaticamente",
        "event_id":    qrClaims.EventID,
        "event_name":  qrClaims.EventName,
        "status":      "present", // Always present when scanning
        "timestamp":   time.Now().Format(time.RFC3339),
        "validation":  "automatic",
        "table_name":  tableName,
    })
}

// Handler per ottenere storico presenze utente
func getAttendanceHistoryHandler(c *fiber.Ctx) error {
    userID, _, _, _, err := getUserFromJWT(c)
    if err != nil {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
            "error": "Errore autenticazione",
        })
    }
    
    // Parametri paginazione
    page := c.QueryInt("page", 1)
    limit := c.QueryInt("limit", 10)
    if page < 1 {
        page = 1
    }
    if limit < 1 || limit > 100 {
        limit = 10
    }
    offset := (page - 1) * limit
    
    // Query presenze
    query := `
        SELECT a.id, a.event_id, ae.event_name, ae.date, a.timestamp, a.status, a.motivazione
        FROM attendance a
        JOIN attendance_events ae ON a.event_id = ae.event_id
        WHERE a.user_id = $1
        ORDER BY a.timestamp DESC
        LIMIT $2 OFFSET $3`
    
    rows, err := database.DB.Query(query, userID, limit, offset)
    if err != nil {
        log.Printf("Error querying attendance history: %v", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Errore recupero storico presenze",
        })
    }
    defer rows.Close()
    
    var attendances []map[string]interface{}
    for rows.Next() {
        var id int
        var eventID, eventName, status, motivazione string
        var date, timestamp time.Time
        
        err := rows.Scan(&id, &eventID, &eventName, &date, &timestamp, &status, &motivazione)
        if err != nil {
            log.Printf("Error scanning attendance: %v", err)
            continue
        }
        
        attendance := map[string]interface{}{
            "id":         id,
            "event_id":   eventID,
            "event_name": eventName,
            "date":       date.Format("2006-01-02"),
            "timestamp":  timestamp.Format(time.RFC3339),
            "status":     status,
        }
        
        if motivazione != "" {
            attendance["motivazione"] = motivazione
        }
        
        attendances = append(attendances, attendance)
    }
    
    // Conta totale
    var total int
    countQuery := `SELECT COUNT(*) FROM attendance WHERE user_id = $1`
    err = database.DB.QueryRow(countQuery, userID).Scan(&total)
    if err != nil {
        total = len(attendances)
    }
    
    return c.JSON(fiber.Map{
        "attendances": attendances,
        "total":       total,
        "page":        page,
        "limit":       limit,
    })
}

// Handler per presenza di oggi
func getTodayAttendanceHandler(c *fiber.Ctx) error {
    userID, _, _, _, err := getUserFromJWT(c)
    if err != nil {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
            "error": "Errore autenticazione",
        })
    }
    
    today := time.Now().Format("2006-01-02")
    todayEventID := fmt.Sprintf("daily-%s", today)
    
    query := `
        SELECT a.id, a.timestamp, a.status, a.motivazione, ae.event_name
        FROM attendance a
        JOIN attendance_events ae ON a.event_id = ae.event_id
        WHERE a.user_id = $1 AND a.event_id = $2`
    
    var id int
    var timestamp time.Time
    var status, motivazione, eventName string
    
    err = database.DB.QueryRow(query, userID, todayEventID).Scan(&id, &timestamp, &status, &motivazione, &eventName)
    if err != nil {
        // Nessuna presenza oggi
        return c.JSON(fiber.Map{
            "has_attendance": false,
            "date":          today,
        })
    }
    
    attendance := map[string]interface{}{
        "id":         id,
        "status":     status,
        "timestamp":  timestamp.Format(time.RFC3339),
        "event_name": eventName,
    }
    
    if motivazione != "" {
        attendance["motivazione"] = motivazione
    }
    
    return c.JSON(fiber.Map{
        "has_attendance": true,
        "date":          today,
        "attendance":    attendance,
    })
}

// ORIGINAL: Handler per presenze di un evento (admin only) - Legacy compatibility
func getEventAttendanceHandler(c *fiber.Ctx) error {
    log.Printf("⚠️  LEGACY DEBUG: getEventAttendanceHandler called - THIS SHOULD NOT BE USED!")
    
    eventID := c.Params("event_id")
    log.Printf("⚠️  LEGACY DEBUG: Legacy handler called with event_id: %s", eventID)
    
    if eventID == "" {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Event ID is required",
        })
    }
    
    // Verify admin role
    _, _, _, role, err := getUserFromJWT(c)
    if err != nil {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
            "error": "Authentication error",
        })
    }
    
    if role != "admin" {
        return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
            "error": "Admin access required",
        })
    }
    
    log.Printf("⚠️  LEGACY DEBUG: Using legacy handler - redirecting to new handler logic")
    
    tableName := "attendance_" + strings.ReplaceAll(eventID, "-", "_")
    
    // Check if table exists
    var tableExists bool
    checkTableQuery := `
        SELECT EXISTS (
            SELECT FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_name = $1
        )`
    err = database.DB.QueryRow(checkTableQuery, tableName).Scan(&tableExists)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Database error",
        })
    }
    
    if !tableExists {
        return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
            "error": "Event not found or no attendance recorded",
        })
    }
    
    // Get attendance records - Enhanced query for new schema
    query := fmt.Sprintf(`
        SELECT user_id, name, surname, 
               COALESCE(scanned_at, timestamp) as attendance_time, 
               status, 
               COALESCE(motivazione, '') as motivazione
        FROM %s 
        ORDER BY attendance_time ASC
    `, tableName)
    
    log.Printf("⚠️  LEGACY DEBUG: Executing legacy query on table %s", tableName)
    
    rows, err := database.DB.Query(query)
    if err != nil {
        log.Printf("Error querying attendance records: %v", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Error fetching attendance records",
        })
    }
    defer rows.Close()
    
    var attendances []map[string]interface{}
    for rows.Next() {
        var userID int
        var name, surname, status, motivazione string
        var attendanceTime sql.NullTime
        
        err := rows.Scan(&userID, &name, &surname, &attendanceTime, &status, &motivazione)
        if err != nil {
            log.Printf("Error scanning attendance record: %v", err)
            continue
        }
        
        record := map[string]interface{}{
            "user_id": userID,
            "name":    name,
            "surname": surname,
            "status":  status,
        }
        
        if attendanceTime.Valid {
            record["timestamp"] = attendanceTime.Time.Format(time.RFC3339)
        } else {
            record["timestamp"] = nil
        }
        
        if motivazione != "" {
            record["motivazione"] = motivazione
        }
        
        attendances = append(attendances, record)
    }
    
    log.Printf("⚠️  LEGACY DEBUG: Legacy handler returning %d attendance records", len(attendances))
    
    // Get event details
    var eventName string
    var eventDate time.Time
    eventQuery := `SELECT event_name, date FROM attendance_events WHERE event_id = $1`
    err = database.DB.QueryRow(eventQuery, eventID).Scan(&eventName, &eventDate)
    if err != nil {
        log.Printf("Error getting event details: %v", err)
        eventName = "Unknown Event"
    }
    
    return c.JSON(fiber.Map{
        "event_id":     eventID,
        "event_name":   eventName,
        "event_date":   eventDate.Format("2006-01-02"),
        "table_name":   tableName,
        "attendances":  attendances,
        "total_count":  len(attendances),
    })
}

// Handler per lista QR generati (admin only)
func getQRListHandler(c *fiber.Ctx) error {
    query := `
        SELECT event_id, event_name, date, expires_at, created_at, is_active
        FROM attendance_events
        ORDER BY created_at DESC`
    
    rows, err := database.DB.Query(query)
    if err != nil {
        log.Printf("Error querying QR list: %v", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Errore recupero lista QR",
        })
    }
    defer rows.Close()

    var qrList []map[string]interface{}
    for rows.Next() {
        var eventID, eventName string
        var date, expiresAt, createdAt time.Time
        var isActive bool
        
        err := rows.Scan(&eventID, &eventName, &date, &expiresAt, &createdAt, &isActive)
        if err != nil {
            log.Printf("Error scanning QR: %v", err)
            continue
        }

        // Get user statistics for this event
        tableName := "attendance_" + strings.ReplaceAll(eventID, "-", "_")
        stats := getEventStatistics(tableName)

        qr := map[string]interface{}{
            "event_id":     eventID,
            "event_name":   eventName,
            "date":         date.Format("2006-01-02"),
            "expires_at":   expiresAt.Format(time.RFC3339),
            "created_at":   createdAt.Format(time.RFC3339),
            "is_active":    isActive,
            "statistics":   stats,
        }
        
        qrList = append(qrList, qr)
    }
    
    return c.JSON(fiber.Map{
        "events": qrList,
        "total":  len(qrList),
    })
}

// NEW: Handler per ottenere tutti gli utenti di un evento con status (admin only)
func getEventUsersHandler(c *fiber.Ctx) error {
    eventID := c.Params("event_id")
    log.Printf("🔍 DEBUG: getEventUsersHandler called with event_id: %s", eventID)
    
    if eventID == "" {
        log.Printf("❌ DEBUG: Missing event_id parameter")
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Event ID is required",
        })
    }
    
    // Verify admin role
    _, _, _, role, err := getUserFromJWT(c)
    if err != nil {
        log.Printf("❌ DEBUG: JWT authentication failed: %v", err)
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
            "error": "Authentication error",
        })
    }
    
    if role != "admin" {
        log.Printf("❌ DEBUG: Access denied for non-admin user with role: %s", role)
        return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
            "error": "Admin access required",
        })
    }
    
    log.Printf("✅ DEBUG: Admin access granted, proceeding with event data retrieval")
    
    tableName := "attendance_" + strings.ReplaceAll(eventID, "-", "_")
    log.Printf("🗄️  DEBUG: Looking for table: %s", tableName)
    
    // Check if table exists
    var tableExists bool
    checkTableQuery := `
        SELECT EXISTS (
            SELECT FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_name = $1
        )`
    err = database.DB.QueryRow(checkTableQuery, tableName).Scan(&tableExists)
    if err != nil {
        log.Printf("❌ DEBUG: Database error checking table existence: %v", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Database error",
        })
    }
    
    if !tableExists {
        log.Printf("❌ DEBUG: Table %s does not exist", tableName)
        return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
            "error": "Event not found",
        })
    }
      log.Printf("✅ DEBUG: Table %s exists, querying ONLY users who scanned QR", tableName)
      
    // Get ONLY users who have actually scanned QR codes (selective system)
    query := fmt.Sprintf(`
        SELECT user_id, name, surname, COALESCE(status, 'present') as status, 
               scanned_at, updated_at, updated_by
        FROM %s 
        WHERE scanned_at IS NOT NULL
        ORDER BY scanned_at DESC, surname ASC, name ASC
    `, tableName)
    
    log.Printf("🔍 DEBUG: Executing SELECTIVE query: %s", query)
    
    rows, err := database.DB.Query(query)
    if err != nil {
        log.Printf("❌ DEBUG: Error querying event users: %v", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Error fetching event users",
        })
    }
    defer rows.Close()
      
    var users []map[string]interface{}
    userCount := 0
    for rows.Next() {
        var userID, updatedBy sql.NullInt64
        var name, surname, status string
        var scannedAt, updatedAt sql.NullTime
        
        err := rows.Scan(&userID, &name, &surname, &status, &scannedAt, &updatedAt, &updatedBy)
        if err != nil {
            log.Printf("❌ DEBUG: Error scanning user record: %v", err)
            continue
        }
        
        // Ensure userID is valid
        if !userID.Valid {
            log.Printf("⚠️  DEBUG: Invalid user_id found, skipping record")
            continue
        }
        
        // Ensure status has a default value if empty
        if status == "" {
            status = "not_registered"
        }
          
        user := map[string]interface{}{
            "user_id":    int(userID.Int64), // Cast to int for Flutter compatibility
            "name":       name,
            "surname":    surname,
            "status":     status,
            "updated_at": nil,
        }
        
        if scannedAt.Valid {
            user["scanned_at"] = scannedAt.Time.Format(time.RFC3339)
        } else {
            user["scanned_at"] = nil
        }
        
        if updatedAt.Valid {
            user["updated_at"] = updatedAt.Time.Format(time.RFC3339)
        }
        
        if updatedBy.Valid {
            user["updated_by"] = int(updatedBy.Int64) // Cast to int for Flutter compatibility
        } else {
            user["updated_by"] = nil
        }
        
        users = append(users, user)
        userCount++
    }
      log.Printf("📊 DEBUG: Retrieved %d QR SCANNERS from table %s (selective system)", userCount, tableName)
    log.Printf("📋 DEBUG: First few QR scanners: %+v", func() []map[string]interface{} {
        if len(users) > 3 {
            return users[:3]
        }
        return users
    }())
    
    // Get event details
    var eventName string
    var eventDate time.Time
    eventQuery := `SELECT event_name, date FROM attendance_events WHERE event_id = $1`
    err = database.DB.QueryRow(eventQuery, eventID).Scan(&eventName, &eventDate)
    if err != nil {
        log.Printf("⚠️  DEBUG: Error getting event details: %v", err)
        eventName = "Unknown Event"
    }
    
    // Calculate statistics
    stats := calculateEventStats(users)
      response := fiber.Map{
        "event_id":      eventID,
        "event_name":    eventName,
        "event_date":    eventDate.Format("2006-01-02"),
        "users":         users,
        "qr_scanners":   len(users), // Only QR scanners in selective system
        "total_users":   len(users), // For backward compatibility
        "statistics":    stats,
        "system_type":   "selective_qr_only",
    }
      log.Printf("🎯 DEBUG: Returning response with %d QR SCANNERS (selective system), event: %s", len(users), eventName)
    log.Printf("📊 DEBUG: Selective system summary: qr_scanners=%d, event_id=%s", len(users), eventID)
    
    return c.JSON(response)
}

// Handler per cancellare un evento (admin only)
func deleteEventHandler(c *fiber.Ctx) error {
    eventID := c.Params("event_id")
    if eventID == "" {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Event ID is required",
        })
    }

    // Verify admin role
    adminID, _, _, role, err := getUserFromJWT(c)
    if err != nil {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
            "error": "Authentication error",
        })
    }

    if role != "admin" {
        return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
            "error": "Admin access required",
        })
    }

    // Check if event exists
    var eventExists bool
    var eventName string
    checkEventQuery := `SELECT EXISTS(SELECT 1 FROM attendance_events WHERE event_id = $1), 
                       COALESCE((SELECT event_name FROM attendance_events WHERE event_id = $1), '')`
    err = database.DB.QueryRow(checkEventQuery, eventID).Scan(&eventExists, &eventName)
    if err != nil || !eventExists {
        return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
            "error": "Event not found",
        })
    }

    // Drop the dynamic attendance table
    tableName := "attendance_" + strings.ReplaceAll(eventID, "-", "_")
    dropTableQuery := fmt.Sprintf(`DROP TABLE IF EXISTS %s`, tableName)
    _, err = database.DB.Exec(dropTableQuery)
    if err != nil {
        log.Printf("Warning: Failed to drop table %s: %v", tableName, err)
        // Continue with event deletion even if table drop fails
    }

    // Delete the event from attendance_events table
    deleteEventQuery := `DELETE FROM attendance_events WHERE event_id = $1`
    result, err := database.DB.Exec(deleteEventQuery, eventID)
    if err != nil {
        log.Printf("Error deleting event: %v", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Error deleting event",
        })
    }

    rowsAffected, _ := result.RowsAffected()
    if rowsAffected == 0 {
        return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
            "error": "Event not found",
        })
    }

    log.Printf("ADMIN_ACTION: Admin %d deleted event %s (%s) and table %s", 
        adminID, eventID, eventName, tableName)

    return c.JSON(fiber.Map{
        "message":    "Event deleted successfully",
        "event_id":   eventID,
        "event_name": eventName,
        "deleted_by": adminID,
    })
}

// Helper function: Calculate event statistics
func calculateEventStats(users []map[string]interface{}) map[string]interface{} {
    stats := map[string]int{
        "present":        0,
        "hospital":       0,
        "family":         0,
        "emergency":      0,
        "vacancy":        0,
        "personal":       0,
        "not_registered": 0,
    }
    
    totalUsers := len(users)
    scannedCount := 0
      for _, user := range users {
        // Safe type assertion for status
        status, ok := user["status"].(string)
        if !ok || status == "" {
            status = "not_registered" // Default fallback
        }
        
        if count, exists := stats[status]; exists {
            stats[status] = count + 1
        }
        
        if user["scanned_at"] != nil {
            scannedCount++
        }
    }
    
    presentCount := stats["present"]
    absentCount := totalUsers - presentCount
    
    return map[string]interface{}{
        "total_users":    totalUsers,
        "present_count":  presentCount,
        "absent_count":   absentCount,
        "scanned_count":  scannedCount,
        "status_breakdown": stats,
        "attendance_rate": func() float64 {
            if totalUsers == 0 {
                return 0.0
            }
            return float64(presentCount) / float64(totalUsers) * 100
        }(),
    }
}

// Helper function: Get event statistics from database
func getEventStatistics(tableName string) map[string]interface{} {
    // Check if table exists
    var tableExists bool
    checkQuery := `
        SELECT EXISTS (
            SELECT FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_name = $1
        )`
    err := database.DB.QueryRow(checkQuery, tableName).Scan(&tableExists)
    if err != nil || !tableExists {
        return map[string]interface{}{
            "total_users":    0,
            "present_count":  0,
            "absent_count":   0,
            "scanned_count":  0,
            "status_breakdown": map[string]int{},
            "attendance_rate": 0.0,
        }
    }
      // Get status breakdown with null safety using COALESCE
    statusQuery := fmt.Sprintf(`
        SELECT COALESCE(status, 'not_registered') as status, COUNT(*) as count 
        FROM %s 
        GROUP BY COALESCE(status, 'not_registered')
    `, tableName)
    
    rows, err := database.DB.Query(statusQuery)
    if err != nil {
        log.Printf("Error querying status breakdown: %v", err)
        return map[string]interface{}{"error": "Database error"}
    }
    defer rows.Close()
    
    statusBreakdown := make(map[string]int)
    totalUsers := 0
    presentCount := 0
      for rows.Next() {
        var status string
        var count int
        if err := rows.Scan(&status, &count); err != nil {
            log.Printf("Error scanning status breakdown: %v", err)
            continue
        }
        
        // Ensure status is not empty
        if status == "" {
            status = "not_registered"
        }
        
        statusBreakdown[status] = count
        totalUsers += count
        if status == "present" {
            presentCount = count
        }
    }
    
    // Get scanned count
    scannedQuery := fmt.Sprintf(`
        SELECT COUNT(*) 
        FROM %s 
        WHERE scanned_at IS NOT NULL
    `, tableName)
    
    var scannedCount int
    err = database.DB.QueryRow(scannedQuery).Scan(&scannedCount)
    if err != nil {
        scannedCount = 0
    }
    
    absentCount := totalUsers - presentCount
    attendanceRate := 0.0
    if totalUsers > 0 {
        attendanceRate = float64(presentCount) / float64(totalUsers) * 100
    }
    
    return map[string]interface{}{
        "total_users":      totalUsers,
        "present_count":    presentCount,
        "absent_count":     absentCount,
        "scanned_count":    scannedCount,
        "status_breakdown": statusBreakdown,
        "attendance_rate":  attendanceRate,
    }
}

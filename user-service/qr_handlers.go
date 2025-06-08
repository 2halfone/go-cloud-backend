package main

import (
    "encoding/json"
    "fmt"
    "log"
    "time"
    "user-service/database"

    "github.com/gofiber/fiber/v2"
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
    
    // Genera event_id univoco
    eventID := fmt.Sprintf("daily-%s", req.Date)
    
    // Controlla se esiste già un QR per questa data
    var existingID int
    checkQuery := `SELECT id FROM attendance_events WHERE event_id = $1`
    err = database.DB.QueryRow(checkQuery, eventID).Scan(&existingID)
    if err == nil {
        return c.Status(fiber.StatusConflict).JSON(fiber.Map{
            "error": "QR per questa data già esistente",
            "event_id": eventID,
        })
    }
    
    // Genera JWT per QR
    qrJWT, err := generateQRJWT(eventID, req.EventName, req.Date, userID)
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
    if req.QRContent.JWT == "" || req.Status == "" {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "QR content e status sono richiesti",
        })
    }
    
    if !isValidStatus(req.Status) {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Status non valido",
            "valid_statuses": ValidStatuses,
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
        hasScanned, err := hasUserScannedEvent(userID, qrClaims.EventID)
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
        }
    }
    
    // Registra presenza
    insertQuery := `
        INSERT INTO attendance (user_id, event_id, name, surname, status, motivazione)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id, timestamp`
    
    var attendanceID int
    var timestamp time.Time
    err = database.DB.QueryRow(insertQuery, userID, qrClaims.EventID, name, surname, req.Status, req.Motivazione).Scan(&attendanceID, &timestamp)
    if err != nil {
        log.Printf("Error saving attendance: %v", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Errore salvataggio presenza",
        })
    }
    
    return c.Status(fiber.StatusCreated).JSON(fiber.Map{
        "message":       "Presenza registrata con successo",
        "attendance_id": attendanceID,
        "event_id":      qrClaims.EventID,
        "event_name":    qrClaims.EventName,
        "status":        req.Status,
        "timestamp":     timestamp.Format(time.RFC3339),
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
        
        qr := map[string]interface{}{
            "event_id":   eventID,
            "event_name": eventName,
            "date":       date.Format("2006-01-02"),
            "expires_at": expiresAt.Format(time.RFC3339),
            "created_at": createdAt.Format(time.RFC3339),
            "is_active":  isActive,
        }
        
        qrList = append(qrList, qr)
    }
    
    return c.JSON(fiber.Map{
        "qr_codes": qrList,
        "total":    len(qrList),
    })
}

// Handler per presenze di un evento (admin only)
func getEventAttendanceHandler(c *fiber.Ctx) error {
    eventID := c.Params("event_id")
    if eventID == "" {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Event ID richiesto",
        })
    }
    
    // Recupera info evento
    var eventName string
    var eventDate time.Time
    eventQuery := `SELECT event_name, date FROM attendance_events WHERE event_id = $1`
    err := database.DB.QueryRow(eventQuery, eventID).Scan(&eventName, &eventDate)
    if err != nil {
        return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
            "error": "Evento non trovato",
        })
    }
    
    // Recupera presenze
    attendanceQuery := `
        SELECT a.user_id, a.name, a.surname, a.status, a.timestamp, a.motivazione
        FROM attendance a
        WHERE a.event_id = $1
        ORDER BY a.timestamp ASC`
    
    rows, err := database.DB.Query(attendanceQuery, eventID)
    if err != nil {
        log.Printf("Error querying event attendance: %v", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Errore recupero presenze evento",
        })
    }
    defer rows.Close()
    
    var attendances []map[string]interface{}
    statusCounts := make(map[string]int)
    
    for rows.Next() {
        var userID int
        var name, surname, status, motivazione string
        var timestamp time.Time
        
        err := rows.Scan(&userID, &name, &surname, &status, &timestamp, &motivazione)
        if err != nil {
            log.Printf("Error scanning attendance: %v", err)
            continue
        }
        
        attendance := map[string]interface{}{
            "user_id":   userID,
            "name":      name,
            "surname":   surname,
            "status":    status,
            "timestamp": timestamp.Format(time.RFC3339),
        }
        
        if motivazione != "" {
            attendance["motivazione"] = motivazione
        }
        
        attendances = append(attendances, attendance)
        statusCounts[status]++
    }
    
    return c.JSON(fiber.Map{
        "event": fiber.Map{
            "event_id":   eventID,
            "event_name": eventName,
            "date":       eventDate.Format("2006-01-02"),
        },
        "attendances": attendances,
        "summary": fiber.Map{
            "total":  len(attendances),
            "status": statusCounts,
        },
    })
}

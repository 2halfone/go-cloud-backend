-- user-service/migrations/0004_create_attendance.sql
-- Tabella per registrare le presenze degli utenti

CREATE TABLE IF NOT EXISTS attendance (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id),
    event_id VARCHAR(100) NOT NULL,                 -- riferimento a attendance_events.event_id
    timestamp TIMESTAMP DEFAULT NOW(),              -- momento della scansione
    name VARCHAR(100) NOT NULL,                     -- nome utente (denormalizzato)
    surname VARCHAR(100) NOT NULL,                  -- cognome utente (denormalizzato)
    status VARCHAR(20) NOT NULL CHECK (status IN (
        'presente',     -- Presente
        'vacation',     -- Ferie
        'hospital',     -- Malattia/Ospedale
        'family',       -- Motivi familiari
        'sick',         -- Malattia
        'personal',     -- Motivi personali  
        'business',     -- Trasferta/Business
        'other'         -- Altro motivo
    )),
    motivazione TEXT,                               -- dettagli aggiuntivi (opzionale)
    created_at TIMESTAMP DEFAULT NOW(),
    
    -- Un utente può registrare presenza una sola volta per evento
    UNIQUE(user_id, event_id)
);

-- Indici per performance
CREATE INDEX idx_attendance_user_id ON attendance(user_id);
CREATE INDEX idx_attendance_event_id ON attendance(event_id);
CREATE INDEX idx_attendance_status ON attendance(status);
CREATE INDEX idx_attendance_timestamp ON attendance(timestamp);

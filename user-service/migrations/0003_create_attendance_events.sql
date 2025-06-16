-- user-service/migrations/0003_create_attendance_events.sql
-- Tabella per gli eventi di presenza con QR codes

CREATE TABLE IF NOT EXISTS attendance_events (
    id SERIAL PRIMARY KEY,
    event_id VARCHAR(100) UNIQUE NOT NULL,          -- daily-2025-06-08
    event_name VARCHAR(255) NOT NULL,               -- Presenza Giornaliera
    date DATE NOT NULL,                             -- 2025-06-08
    qr_jwt TEXT NOT NULL,                           -- JWT completo per QR
    qr_image_path TEXT,                             -- Path immagine QR (opzionale)
    expires_at TIMESTAMP NOT NULL,                  -- 2025-06-08 23:59:59
    created_by INT REFERENCES users(id),            -- Admin che ha creato
    created_at TIMESTAMP DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE
);

-- Indici per performance
CREATE INDEX idx_attendance_events_date ON attendance_events(date);
CREATE INDEX idx_attendance_events_event_id ON attendance_events(event_id);
CREATE INDEX idx_attendance_events_active ON attendance_events(is_active);

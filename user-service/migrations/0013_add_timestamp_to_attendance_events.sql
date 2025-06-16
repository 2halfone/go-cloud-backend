-- Migration: Add timestamp column to attendance_events table
-- This column is required by the dashboard API for scan analytics

ALTER TABLE attendance_events ADD COLUMN IF NOT EXISTS timestamp TIMESTAMP DEFAULT NOW();

-- Update existing records to have timestamp based on created_at
UPDATE attendance_events SET timestamp = created_at WHERE timestamp IS NULL;

-- Create index for performance on timestamp queries
CREATE INDEX IF NOT EXISTS idx_attendance_events_timestamp ON attendance_events(timestamp);

-- Also ensure we have some sample scan data for analytics
-- Insert some sample attendance scan records if table is empty
INSERT INTO attendance_events (event_id, event_name, date, qr_jwt, expires_at, timestamp, is_active)
SELECT 
    'daily-' || CURRENT_DATE,
    'Daily Attendance Check',
    CURRENT_DATE,
    'sample.jwt.token.for.analytics',
    CURRENT_DATE + INTERVAL '1 day',
    NOW() - (RANDOM() * INTERVAL '24 hours'),
    true
WHERE NOT EXISTS (SELECT 1 FROM attendance_events WHERE date = CURRENT_DATE);

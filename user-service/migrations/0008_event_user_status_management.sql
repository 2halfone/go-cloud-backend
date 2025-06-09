-- user-service/migrations/0008_event_user_status_management.sql
-- Add comprehensive status management for attendance events

-- ============================================================================
-- 1. Enhance dynamic attendance tables structure 
-- ============================================================================

-- Since we use dynamic tables, we'll update the createAttendanceTable function
-- But first, let's create a function to alter existing tables

-- Function to add status management columns to existing attendance tables
CREATE OR REPLACE FUNCTION update_attendance_tables_for_status_management()
RETURNS VOID AS $$
DECLARE
    table_name TEXT;
    table_cursor CURSOR FOR
        SELECT tablename 
        FROM pg_tables 
        WHERE tablename LIKE 'attendance_%' 
        AND tablename != 'attendance_events'
        AND schemaname = 'public';
BEGIN
    -- Loop through all existing attendance tables
    FOR table_record IN table_cursor LOOP
        table_name := table_record.tablename;
        
        -- Add updated_by column if it doesn't exist
        EXECUTE format('ALTER TABLE %I ADD COLUMN IF NOT EXISTS updated_by INTEGER REFERENCES users(id)', table_name);
        
        -- Add updated_at column if it doesn't exist  
        EXECUTE format('ALTER TABLE %I ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW()', table_name);
        
        -- Update status column to use new enum values
        EXECUTE format('ALTER TABLE %I ALTER COLUMN status TYPE VARCHAR(50)', table_name);
        EXECUTE format('ALTER TABLE %I ALTER COLUMN status SET DEFAULT ''not_registered''', table_name);
        
        -- Add constraint for valid status values
        EXECUTE format('ALTER TABLE %I DROP CONSTRAINT IF EXISTS chk_%I_status', table_name, table_name);
        EXECUTE format('ALTER TABLE %I ADD CONSTRAINT chk_%I_status CHECK (status IN (''present'', ''hospital'', ''family'', ''emergency'', ''vacancy'', ''personal'', ''not_registered''))', table_name, table_name);
        
        -- Create indexes for new columns
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%I_status ON %I(status)', table_name, table_name);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%I_updated_at ON %I(updated_at)', table_name, table_name);
        
        RAISE NOTICE 'Updated table: %', table_name;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- Execute the function to update existing tables
SELECT update_attendance_tables_for_status_management();

-- ============================================================================
-- 2. Create user population function for new events
-- ============================================================================

-- Function to populate all users when a new event is created
CREATE OR REPLACE FUNCTION populate_event_users(event_table_name TEXT)
RETURNS VOID AS $$
DECLARE
    user_record RECORD;
    user_cursor CURSOR FOR
        SELECT id, name, last_name 
        FROM users 
        WHERE status = 'active';
BEGIN
    -- Insert all active users into the event table with default status
    FOR user_record IN user_cursor LOOP
        EXECUTE format(
            'INSERT INTO %I (user_id, name, surname, status, timestamp, updated_at) 
             VALUES ($1, $2, $3, $4, NULL, NOW()) 
             ON CONFLICT (user_id) DO NOTHING',
            event_table_name
        ) USING user_record.id, user_record.name, user_record.last_name, 'not_registered';
    END LOOP;
    
    RAISE NOTICE 'Populated % users in table %', (SELECT COUNT(*) FROM users WHERE status = 'active'), event_table_name;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 3. Create trigger function for QR scan status update
-- ============================================================================

-- Function to automatically set status to 'present' when QR is scanned
CREATE OR REPLACE FUNCTION update_status_on_scan()
RETURNS TRIGGER AS $$
BEGIN
    -- When a record is inserted with a timestamp (QR scan), set status to present
    IF NEW.timestamp IS NOT NULL AND (OLD.timestamp IS NULL OR OLD.timestamp != NEW.timestamp) THEN
        NEW.status := 'present';
        NEW.updated_at := NOW();
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 4. Update attendance_events table for better tracking
-- ============================================================================

-- Add user count tracking to attendance_events
ALTER TABLE attendance_events ADD COLUMN IF NOT EXISTS total_users INTEGER DEFAULT 0;
ALTER TABLE attendance_events ADD COLUMN IF NOT EXISTS present_count INTEGER DEFAULT 0;
ALTER TABLE attendance_events ADD COLUMN IF NOT EXISTS absent_count INTEGER DEFAULT 0;

-- Add index for better performance
CREATE INDEX IF NOT EXISTS idx_attendance_events_created_by ON attendance_events(created_by);
CREATE INDEX IF NOT EXISTS idx_attendance_events_date ON attendance_events(date);
CREATE INDEX IF NOT EXISTS idx_attendance_events_is_active ON attendance_events(is_active);

-- ============================================================================
-- 5. Create view for event statistics
-- ============================================================================

-- Create a view to easily get event statistics
CREATE OR REPLACE VIEW event_attendance_stats AS
SELECT 
    ae.id,
    ae.event_id,
    ae.event_name,
    ae.date,
    ae.created_by,
    u.name || ' ' || u.last_name AS creator_name,
    ae.total_users,
    ae.present_count,
    ae.absent_count,
    ae.created_at,
    ae.is_active
FROM attendance_events ae
LEFT JOIN users u ON ae.created_by = u.id
ORDER BY ae.created_at DESC;

-- ============================================================================
-- 6. Cleanup function
-- ============================================================================

-- Drop the temporary function (no longer needed)
DROP FUNCTION IF EXISTS update_attendance_tables_for_status_management();

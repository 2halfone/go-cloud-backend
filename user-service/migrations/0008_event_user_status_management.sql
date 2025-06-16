-- user-service/migrations/0008_event_user_status_management.sql
-- Align attendance system with automatic QR-only presence tracking

-- ============================================================================
-- 1. Enhance dynamic attendance tables for automatic system
-- ============================================================================

-- Function to update existing attendance tables for automatic presence system
CREATE OR REPLACE FUNCTION update_attendance_tables_for_automatic_system()
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
        
        -- Add name column if it doesn't exist
        EXECUTE format('ALTER TABLE %I ADD COLUMN IF NOT EXISTS name VARCHAR(255)', table_name);
        
        -- Add surname column if it doesn't exist
        EXECUTE format('ALTER TABLE %I ADD COLUMN IF NOT EXISTS surname VARCHAR(255)', table_name);
        
        -- Add updated_at column if it doesn't exist  
        EXECUTE format('ALTER TABLE %I ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW()', table_name);
        
        -- Update status column for automatic system (only 'present' and 'not_registered')
        EXECUTE format('ALTER TABLE %I ALTER COLUMN status TYPE VARCHAR(50)', table_name);
        EXECUTE format('ALTER TABLE %I ALTER COLUMN status SET DEFAULT ''not_registered''', table_name);
        
        -- Update constraint for automatic system - only two status values needed
        EXECUTE format('ALTER TABLE %I DROP CONSTRAINT IF EXISTS chk_%I_status', table_name, table_name);
        EXECUTE format('ALTER TABLE %I ADD CONSTRAINT chk_%I_status CHECK (status IN (''present'', ''not_registered''))', table_name, table_name);
        
        -- Clean up obsolete status values to align with automatic system
        EXECUTE format('UPDATE %I SET status = ''not_registered'' WHERE status NOT IN (''present'', ''not_registered'')', table_name);
        
        -- Create indexes for performance
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%I_status ON %I(status)', table_name, table_name);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%I_updated_at ON %I(updated_at)', table_name, table_name);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%I_scanned_at ON %I(scanned_at)', table_name, table_name);
        
        RAISE NOTICE 'Updated table for automatic system: %', table_name;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- Execute the function to update existing tables
SELECT update_attendance_tables_for_automatic_system();

-- ============================================================================
-- 2. Create user population function for automatic system
-- ============================================================================

-- Function to populate all users when a new event is created (automatic system)
CREATE OR REPLACE FUNCTION populate_event_users_automatic(event_table_name TEXT)
RETURNS VOID AS $$
DECLARE
    user_record RECORD;
    user_cursor CURSOR FOR
        SELECT id, name, last_name 
        FROM users 
        ORDER BY name, last_name;
BEGIN
    -- Insert ALL authenticated users into the event table with 'not_registered' status
    -- Users become 'present' only when they scan QR code
    FOR user_record IN user_cursor LOOP
        EXECUTE format(
            'INSERT INTO %I (user_id, name, surname, status, scanned_at, updated_at) 
             VALUES ($1, $2, $3, $4, NULL, NOW()) 
             ON CONFLICT (user_id) DO NOTHING',
            event_table_name
        ) USING user_record.id, user_record.name, user_record.last_name, 'not_registered';
    END LOOP;
    
    RAISE NOTICE 'Populated % users in table % (automatic QR system)', (SELECT COUNT(*) FROM users), event_table_name;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 3. Update attendance_events table for automatic system tracking
-- ============================================================================

-- Add success/error tracking for admin monitoring
ALTER TABLE attendance_events ADD COLUMN IF NOT EXISTS total_users INTEGER DEFAULT 0;
ALTER TABLE attendance_events ADD COLUMN IF NOT EXISTS present_count INTEGER DEFAULT 0;
ALTER TABLE attendance_events ADD COLUMN IF NOT EXISTS scan_success_count INTEGER DEFAULT 0;
ALTER TABLE attendance_events ADD COLUMN IF NOT EXISTS scan_error_count INTEGER DEFAULT 0;
ALTER TABLE attendance_events ADD COLUMN IF NOT EXISTS last_scan_at TIMESTAMPTZ;
ALTER TABLE attendance_events ADD COLUMN IF NOT EXISTS system_notes TEXT;

-- Add performance indexes
CREATE INDEX IF NOT EXISTS idx_attendance_events_created_by ON attendance_events(created_by);
CREATE INDEX IF NOT EXISTS idx_attendance_events_date ON attendance_events(date);
CREATE INDEX IF NOT EXISTS idx_attendance_events_is_active ON attendance_events(is_active);
CREATE INDEX IF NOT EXISTS idx_attendance_events_last_scan ON attendance_events(last_scan_at);

-- ============================================================================
-- 4. Create view for automatic system statistics
-- ============================================================================

-- Create view for event statistics with success/error tracking
CREATE OR REPLACE VIEW event_attendance_stats_automatic AS
SELECT 
    ae.id,
    ae.event_id,
    ae.event_name,
    ae.date,
    ae.created_by,
    u.name || ' ' || u.last_name AS creator_name,
    ae.total_users,
    ae.present_count,
    ae.scan_success_count,
    ae.scan_error_count,
    CASE 
        WHEN ae.total_users > 0 THEN ROUND((ae.present_count::DECIMAL / ae.total_users) * 100, 2)
        ELSE 0
    END AS attendance_percentage,
    CASE 
        WHEN ae.scan_success_count + ae.scan_error_count > 0 THEN 
            ROUND((ae.scan_success_count::DECIMAL / (ae.scan_success_count + ae.scan_error_count)) * 100, 2)
        ELSE 100
    END AS scan_success_rate,
    ae.last_scan_at,
    ae.system_notes,
    ae.created_at,
    ae.is_active
FROM attendance_events ae
LEFT JOIN users u ON ae.created_by = u.id
ORDER BY ae.created_at DESC;

-- ============================================================================
-- 5. Cleanup function
-- ============================================================================

-- Drop the temporary function (no longer needed)
DROP FUNCTION IF EXISTS update_attendance_tables_for_automatic_system();

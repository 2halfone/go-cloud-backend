-- user-service/migrations/0012_automatic_qr_system_final.sql
-- Final setup for clean automatic QR attendance system with admin reporting

-- ============================================================================
-- 1. Clean up any remaining problematic functions and triggers
-- ============================================================================

-- Remove any existing triggers that might conflict with backend logic
DO $$
DECLARE 
    table_record RECORD;
BEGIN
    FOR table_record IN 
        SELECT tablename 
        FROM pg_tables 
        WHERE tablename LIKE 'attendance_%' 
        AND tablename != 'attendance_events'
        AND schemaname = 'public'
    LOOP
        -- Drop any existing triggers
        EXECUTE format('DROP TRIGGER IF EXISTS tr_%I_auto_present ON %I', table_record.tablename, table_record.tablename);
        EXECUTE format('DROP TRIGGER IF EXISTS tr_%I_update_timestamp ON %I', table_record.tablename, table_record.tablename);
        
        RAISE NOTICE 'Cleaned triggers from table: %', table_record.tablename;
    END LOOP;
END $$;

-- ============================================================================
-- 2. Create final table setup function for automatic QR system
-- ============================================================================

-- Function to create new attendance table with correct structure for automatic system
CREATE OR REPLACE FUNCTION create_attendance_table_automatic(table_name TEXT)
RETURNS VOID AS $$
BEGIN
    -- Create the table with all required columns for automatic system
    EXECUTE format('
        CREATE TABLE IF NOT EXISTS %I (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            name VARCHAR(255),
            surname VARCHAR(255),
            status VARCHAR(50) DEFAULT ''not_registered'' CHECK (status IN (''present'', ''not_registered'')),
            scanned_at TIMESTAMPTZ,
            updated_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(user_id)
        )', table_name);
    
    -- Add performance indexes
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%I_user_id ON %I(user_id)', table_name, table_name);
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%I_status ON %I(status)', table_name, table_name);
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%I_scanned_at ON %I(scanned_at)', table_name, table_name);
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%I_updated_at ON %I(updated_at)', table_name, table_name);
    
    RAISE NOTICE 'Created attendance table with automatic QR system structure: %', table_name;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 3. Function to populate new event table with all users
-- ============================================================================

-- Function to populate event table with all authenticated users (for automatic system)
CREATE OR REPLACE FUNCTION populate_automatic_event_users(event_table_name TEXT)
RETURNS INTEGER AS $$
DECLARE
    user_count INTEGER := 0;
    user_record RECORD;
BEGIN
    -- Insert ALL authenticated users with 'not_registered' status
    -- They become 'present' only when backend processes their QR scan
    FOR user_record IN 
        SELECT id, name, last_name
        FROM users 
        ORDER BY name, last_name
    LOOP
        EXECUTE format(
            'INSERT INTO %I (user_id, name, surname, status, scanned_at, updated_at) 
             VALUES ($1, $2, $3, ''not_registered'', NULL, NOW())
             ON CONFLICT (user_id) DO NOTHING',
            event_table_name
        ) USING user_record.id, user_record.name, user_record.last_name;
        
        user_count := user_count + 1;
    END LOOP;
    
    RAISE NOTICE 'Populated % users in automatic QR table: %', user_count, event_table_name;
    RETURN user_count;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 4. Master function for complete automatic event setup
-- ============================================================================

-- Complete setup function for new automatic QR attendance events
CREATE OR REPLACE FUNCTION setup_automatic_attendance_event(event_table_name TEXT)
RETURNS TEXT AS $$
DECLARE
    user_count INTEGER;
    result_message TEXT;
BEGIN
    -- Create the table with proper structure
    PERFORM create_attendance_table_automatic(event_table_name);
    
    -- Populate with all users
    user_count := populate_automatic_event_users(event_table_name);
    
    -- Create result message
    result_message := format(
        'Automatic QR attendance table setup complete: %s with %s users', 
        event_table_name, user_count
    );
    
    RAISE NOTICE '%', result_message;
    RETURN result_message;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 5. Function to update event statistics (for admin monitoring)
-- ============================================================================

-- Function to update attendance_events table with current statistics
CREATE OR REPLACE FUNCTION update_event_statistics(event_table_name TEXT, event_id INTEGER)
RETURNS VOID AS $$
DECLARE
    total_users_count INTEGER;
    present_count INTEGER;
    last_scan TIMESTAMPTZ;
BEGIN
    -- Get current counts from the event table
    EXECUTE format('SELECT COUNT(*) FROM %I', event_table_name) INTO total_users_count;
    EXECUTE format('SELECT COUNT(*) FROM %I WHERE status = ''present''', event_table_name) INTO present_count;
    EXECUTE format('SELECT MAX(scanned_at) FROM %I WHERE scanned_at IS NOT NULL', event_table_name) INTO last_scan;
    
    -- Update attendance_events table with current statistics
    UPDATE attendance_events 
    SET 
        total_users = total_users_count,
        present_count = present_count,
        last_scan_at = last_scan,
        updated_at = NOW()
    WHERE id = event_id;
    
    RAISE NOTICE 'Updated statistics for event %: % present out of % total users', 
                 event_id, present_count, total_users_count;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 6. Function for QR scan success/error tracking
-- ============================================================================

-- Function to track QR scan results for admin monitoring
CREATE OR REPLACE FUNCTION track_qr_scan_result(event_id INTEGER, scan_success BOOLEAN, error_message TEXT DEFAULT NULL)
RETURNS VOID AS $$
BEGIN
    IF scan_success THEN
        -- Increment success count
        UPDATE attendance_events 
        SET 
            scan_success_count = COALESCE(scan_success_count, 0) + 1,
            last_scan_at = NOW(),
            updated_at = NOW()
        WHERE id = event_id;
    ELSE
        -- Increment error count and log error
        UPDATE attendance_events 
        SET 
            scan_error_count = COALESCE(scan_error_count, 0) + 1,
            system_notes = CASE 
                WHEN system_notes IS NULL THEN error_message
                ELSE system_notes || '; ' || error_message
            END,
            updated_at = NOW()
        WHERE id = event_id;
    END IF;
    
    RAISE NOTICE 'Tracked QR scan result for event %: success=%, error=%', 
                 event_id, scan_success, error_message;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 7. Clean up obsolete functions from previous migrations
-- ============================================================================

-- Remove functions that are no longer needed or conflict with automatic system
DROP FUNCTION IF EXISTS auto_set_present_on_scan() CASCADE;
DROP FUNCTION IF EXISTS update_status_on_scan() CASCADE;
DROP FUNCTION IF EXISTS create_attendance_trigger(TEXT) CASCADE;
DROP FUNCTION IF EXISTS create_attendance_trigger_no_autoset(TEXT) CASCADE;
DROP FUNCTION IF EXISTS setup_new_attendance_table(TEXT) CASCADE;
DROP FUNCTION IF EXISTS add_attendance_performance_indexes(TEXT) CASCADE;

-- ============================================================================
-- 8. Update existing tables to conform to automatic system
-- ============================================================================

-- Ensure all existing attendance tables have the correct constraints
DO $$
DECLARE 
    table_record RECORD;
BEGIN
    FOR table_record IN 
        SELECT tablename 
        FROM pg_tables 
        WHERE tablename LIKE 'attendance_%' 
        AND tablename != 'attendance_events'
        AND schemaname = 'public'
    LOOP
        -- Update constraint to only allow 'present' and 'not_registered'
        EXECUTE format('ALTER TABLE %I DROP CONSTRAINT IF EXISTS chk_%I_status', table_record.tablename, table_record.tablename);
        EXECUTE format('ALTER TABLE %I ADD CONSTRAINT chk_%I_status CHECK (status IN (''present'', ''not_registered''))', table_record.tablename, table_record.tablename);
        
        -- Clean up any obsolete status values
        EXECUTE format('UPDATE %I SET status = ''not_registered'' WHERE status NOT IN (''present'', ''not_registered'')', table_record.tablename);
        
        RAISE NOTICE 'Updated constraints for automatic system: %', table_record.tablename;
    END LOOP;
END $$;

-- ============================================================================
-- 9. Create admin monitoring view for the clean automatic system
-- ============================================================================

-- Create comprehensive view for admin monitoring of automatic QR system
CREATE OR REPLACE VIEW automatic_qr_admin_monitoring AS
SELECT 
    ae.id as event_id,
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
        WHEN (ae.scan_success_count + ae.scan_error_count) > 0 THEN 
            ROUND((ae.scan_success_count::DECIMAL / (ae.scan_success_count + ae.scan_error_count)) * 100, 2)
        ELSE NULL
    END AS scan_success_rate,
    ae.last_scan_at,
    CASE 
        WHEN ae.last_scan_at IS NULL THEN 'No scans yet'
        WHEN ae.last_scan_at < NOW() - INTERVAL '1 hour' THEN 'Inactive'
        ELSE 'Active'
    END AS event_status,
    ae.system_notes,
    ae.created_at,
    ae.is_active
FROM attendance_events ae
LEFT JOIN users u ON ae.created_by = u.id
WHERE ae.created_at >= NOW() - INTERVAL '30 days'  -- Only show events from last 30 days
ORDER BY ae.created_at DESC;

-- Success message
SELECT 'Migration 0012: Clean automatic QR attendance system with admin monitoring setup complete!' as result;

-- user-service/migrations/0009_create_attendance_triggers.sql
-- DISABLED: This migration conflicts with automatic QR system
-- Migration disabled to prevent conflicts with backend-driven automatic presence

-- ============================================================================
-- MIGRATION DISABLED NOTICE
-- ============================================================================

/*
This migration has been DISABLED because:

1. It creates database triggers that conflict with backend logic
2. The automatic QR system is now handled entirely by Go backend code
3. Database triggers were causing inconsistent status updates
4. Backend provides better error handling and success/failure tracking

The functionality this migration intended to provide is now handled by:
- user-service/qr_handlers.go: ScanQRHandler function
- Automatic status setting to 'present' when QR code is scanned
- Success/error tracking in attendance_events table
- Admin monitoring through event statistics
*/

-- This migration is intentionally left as NO-OP to maintain migration sequence

SELECT 'Migration 0009: DISABLED - Functionality moved to backend QR system' as result;
        FROM users 
        WHERE status = 'active'
    LOOP
        EXECUTE format(
            'INSERT INTO %I (user_id, name, surname, status, scanned_at, updated_at) 
             VALUES ($1, $2, $3, $4, NULL, NOW())
             ON CONFLICT (user_id) DO NOTHING',
            event_table_name
        ) USING user_record.id, user_record.name, user_record.last_name, 'not_registered';
        
        user_count := user_count + 1;
    END LOOP;
    
    RAISE NOTICE 'Populated % users in table %', user_count, event_table_name;
    RETURN user_count;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 3. PERFORMANCE INDEXES: Add indexes for fast status queries
-- ============================================================================

-- Function to add performance indexes to attendance tables
CREATE OR REPLACE FUNCTION add_attendance_performance_indexes(table_name TEXT)
RETURNS VOID AS $$
BEGIN
    -- Index on status for fast filtering
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%I_status ON %I(status)', table_name, table_name);
    
    -- Index on updated_at for chronological queries
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%I_updated_at ON %I(updated_at)', table_name, table_name);
    
    -- Composite index for common queries (status + updated_at)
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%I_status_updated ON %I(status, updated_at)', table_name, table_name);
    
    -- Index on scanned_at for attendance tracking
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%I_scanned_at ON %I(scanned_at)', table_name, table_name);
    
    RAISE NOTICE 'Added performance indexes to table %', table_name;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 4. MASTER SETUP FUNCTION: Complete setup for new attendance tables
-- ============================================================================

-- Create a master function to setup a new attendance table completely
CREATE OR REPLACE FUNCTION setup_new_attendance_table(table_name TEXT)
RETURNS VOID AS $$
BEGIN
    -- Add trigger for auto-present on scan
    PERFORM create_attendance_trigger(table_name);
    
    -- Add performance indexes
    PERFORM add_attendance_performance_indexes(table_name);
    
    -- Populate with all users
    PERFORM populate_event_users(table_name);
    
    RAISE NOTICE 'Completed setup for attendance table: %', table_name;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 5. APPLY TO EXISTING TABLES: Upgrade existing attendance tables
-- ============================================================================

-- Apply triggers to existing attendance tables
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
        -- Add trigger
        PERFORM create_attendance_trigger(table_record.tablename);
        
        -- Add performance indexes
        PERFORM add_attendance_performance_indexes(table_record.tablename);
        
        RAISE NOTICE 'Upgraded existing table: %', table_record.tablename;
    END LOOP;
END $$;

-- ============================================================================
-- 6. UPDATE EXISTING RECORDS: Fix scanned records to have 'present' status
-- ============================================================================

-- Update existing scanned records to have 'present' status
DO $$
DECLARE 
    table_record RECORD;
    update_count INTEGER;
BEGIN
    FOR table_record IN 
        SELECT tablename 
        FROM pg_tables 
        WHERE tablename LIKE 'attendance_%' 
        AND tablename != 'attendance_events'
        AND schemaname = 'public'
    LOOP
        -- Update records that have scanned_at but wrong status
        EXECUTE format(
            'UPDATE %I SET status = ''present'', updated_at = NOW() 
             WHERE scanned_at IS NOT NULL AND status != ''present''',
            table_record.tablename
        );
        
        GET DIAGNOSTICS update_count = ROW_COUNT;
        
        IF update_count > 0 THEN
            RAISE NOTICE 'Updated % existing scanned records in table %', update_count, table_record.tablename;
        END IF;
    END LOOP;
END $$;

-- Success message
SELECT 'Migration 0009: Attendance triggers and automation functions created successfully!' as result;

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

-- =====================
-- ORIGINAL LOGIC BELOW (commented out for reference)
-- =====================
--
-- The following code is preserved for reference and should not be executed automatically in batch migrations.
-- If you need to re-enable, copy this code into a psql session and fix delimiters as needed.
--
/*
-- Function to populate event users
CREATE OR REPLACE FUNCTION populate_event_users(event_table_name TEXT)
RETURNS INTEGER AS $$
DECLARE
    user_count INTEGER := 0;
    user_record RECORD;
BEGIN
    FOR user_record IN 
        SELECT id, name, surname
        FROM users 
        WHERE status = 'active'
    LOOP
        EXECUTE format(
            'INSERT INTO %I (user_id, name, surname, status, scanned_at, updated_at) 
             VALUES ($1, $2, $3, $4, NULL, NOW())
             ON CONFLICT (user_id) DO NOTHING',
            event_table_name
        ) USING user_record.id, user_record.name, user_record.surname, 'not_registered';
        user_count := user_count + 1;
    END LOOP;
    RAISE NOTICE 'Populated % users in table %', user_count, event_table_name;
    RETURN user_count;
END;
$$ LANGUAGE plpgsql;
*/

-- user-service/migrations/0011_fix_status_trigger.sql
-- Fix trigger to not auto-set status to 'present' on scan
-- This allows users to manually choose their status after scanning

-- ============================================================================
-- 1. Remove auto-present triggers from existing tables
-- ============================================================================

-- Drop existing triggers that auto-set status to present
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
        -- Drop the auto-present trigger
        EXECUTE format('DROP TRIGGER IF EXISTS tr_%I_auto_present ON %I', table_record.tablename, table_record.tablename);
        
        RAISE NOTICE 'Dropped auto-present trigger from table: %', table_record.tablename;
    END LOOP;
END $$;

-- ============================================================================
-- 2. Update trigger function to NOT auto-set status
-- ============================================================================

-- Replace the auto-present function with one that doesn't change status
CREATE OR REPLACE FUNCTION auto_set_present_on_scan()
RETURNS TRIGGER AS $$
BEGIN
    -- Only update timestamp fields, don't touch status
    -- Status will be set manually by user choice
    IF NEW.scanned_at IS NOT NULL AND OLD.scanned_at IS NULL THEN
        NEW.updated_at = NOW();
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 3. Recreate triggers with new behavior (optional, for future tables)
-- ============================================================================

-- Function to create trigger that DOESN'T auto-set status
CREATE OR REPLACE FUNCTION create_attendance_trigger_no_autoset(table_name TEXT)
RETURNS VOID AS $$
BEGIN
    -- Create trigger that only updates timestamps, not status
    EXECUTE format(
        'CREATE OR REPLACE TRIGGER tr_%I_update_timestamp 
         BEFORE INSERT OR UPDATE ON %I
         FOR EACH ROW 
         EXECUTE FUNCTION auto_set_present_on_scan()',
        table_name, table_name
    );
    
    RAISE NOTICE 'Created timestamp-only trigger for table %', table_name;
END;
$$ LANGUAGE plpgsql;

-- Success message
SELECT 'Migration 0011: Fixed auto-present trigger - status now set manually by user choice!' as result;

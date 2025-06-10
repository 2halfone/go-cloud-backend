-- user-service/migrations/0010_ensure_name_surname_columns.sql
-- Ensure all dynamic attendance tables have name and surname columns

-- ============================================================================
-- 1. Add name and surname columns to existing attendance tables
-- ============================================================================

-- Function to add name and surname columns to existing attendance tables
CREATE OR REPLACE FUNCTION ensure_name_surname_columns()
RETURNS VOID AS $$
DECLARE
    table_name TEXT;
    table_record RECORD;
    update_count INTEGER;
BEGIN
    -- Loop through all existing attendance tables
    FOR table_record IN 
        SELECT tablename 
        FROM pg_tables 
        WHERE tablename LIKE 'attendance_%' 
        AND tablename != 'attendance_events'
        AND schemaname = 'public'
    LOOP
        table_name := table_record.tablename;
        
        -- Add name column if it doesn't exist
        EXECUTE format('ALTER TABLE %I ADD COLUMN IF NOT EXISTS name VARCHAR(255)', table_name);
        
        -- Add surname column if it doesn't exist  
        EXECUTE format('ALTER TABLE %I ADD COLUMN IF NOT EXISTS surname VARCHAR(255)', table_name);
        
        -- Update existing records to populate name and surname from users table
        EXECUTE format(
            'UPDATE %I SET 
                name = u.name,
                surname = u.last_name,
                updated_at = NOW()
             FROM users u 
             WHERE %I.user_id = u.id 
             AND (%I.name IS NULL OR %I.surname IS NULL)',
            table_name, table_name, table_name, table_name
        );
        
        GET DIAGNOSTICS update_count = ROW_COUNT;
        
        IF update_count > 0 THEN
            RAISE NOTICE 'Updated % records with name/surname in table %', update_count, table_name;
        END IF;
        
        RAISE NOTICE 'Ensured name/surname columns in table: %', table_name;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- Execute the function to ensure columns exist
SELECT ensure_name_surname_columns();

-- ============================================================================
-- 2. Update the attendance table creation function to include these columns
-- ============================================================================

-- This is a note for developers: When creating new attendance tables,
-- ensure they include these columns in the table creation SQL:
-- 
-- CREATE TABLE attendance_<event>_<date> (
--     id SERIAL PRIMARY KEY,
--     user_id INTEGER REFERENCES users(id),
--     name VARCHAR(255),                    -- User's first name
--     surname VARCHAR(255),                 -- User's last name  
--     status VARCHAR(50) DEFAULT 'not_registered',
--     scanned_at TIMESTAMPTZ,             -- When QR was scanned
--     updated_at TIMESTAMPTZ DEFAULT NOW(),
--     updated_by INTEGER REFERENCES users(id),
--     UNIQUE(user_id)
-- );

-- ============================================================================
-- 3. Cleanup
-- ============================================================================

-- Drop the temporary function (no longer needed)
DROP FUNCTION IF EXISTS ensure_name_surname_columns();

-- Success message
SELECT 'Migration 0010: Name and surname columns ensured in all attendance tables!' as result;

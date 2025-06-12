-- user-service/migrations/0010_ensure_name_surname_columns.sql
-- DISABLED: Functionality now handled by migration 0008 automatic system
-- Migration disabled to prevent duplication and conflicts

-- ============================================================================
-- MIGRATION DISABLED NOTICE
-- ============================================================================

/*
This migration has been DISABLED because:

1. Functionality is now fully handled by migration 0008 (automatic system)
2. Migration 0008 already ensures name and surname columns exist
3. Avoiding duplication and potential conflicts
4. The automatic system migration handles all necessary column additions

The functionality this migration intended to provide is now handled by:
- Migration 0008: update_attendance_tables_for_automatic_system() function
- Automatic column creation and data population
- Consistent with the new automatic QR attendance system
*/

-- This migration is intentionally left as NO-OP to maintain migration sequence

SELECT 'Migration 0010: DISABLED - Functionality integrated into 0008 automatic system' as result;
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

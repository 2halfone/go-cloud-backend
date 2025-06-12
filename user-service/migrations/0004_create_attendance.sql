-- user-service/migrations/0004_create_attendance.sql
-- MIGRATION ELIMINATA - Non necessaria per sistema dinamico

-- ============================================================================
-- MIGRATION ELIMINATA: Tabelle statiche rimosse dal sistema
-- ============================================================================

-- Questa migration è stata completamente rimossa perché:
-- 1. Il sistema usa SOLO tabelle dinamiche (attendance_evento_data)
-- 2. Le tabelle statiche causavano problemi di performance
-- 3. Sistema automatico QR non richiede tabelle centrali
--
-- Struttura dinamica gestita in:
-- - services/qr_service.go -> CreateAttendanceTable()
-- - Migration 0008 per setup base
-- - Migration 0012 per sistema automatico finale

-- Status supportati: 'present' (scan automatico), 'not_registered' (default)

-- ============================================================================
-- NO-OP: Questa migration non fa nulla
-- ============================================================================

SELECT 'Migration 0004: Static attendance table removed - using dynamic tables only' as status;
SELECT 'Migration 0004: DISABLED - System uses ONLY dynamic tables (attendance_EVENTNAME_DATE)' as notice;

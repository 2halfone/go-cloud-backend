-- user-service/migrations/0004_create_attendance.sql
-- NOTA: Questa migrazione è DISABILITATA
-- Il sistema usa tabelle dinamiche, non la tabella statica 'attendance'
-- Le tabelle dinamiche sono gestite dalle migrazioni 0008 e 0009

-- ============================================================================
-- QUESTA MIGRAZIONE NON È PIÙ ATTIVA
-- ============================================================================

-- Questa migrazione originariamente creava una tabella statica 'attendance'
-- ma il sistema attuale usa tabelle dinamiche con nome: attendance_EVENTNAME_DATE
-- 
-- Struttura delle tabelle dinamiche:
-- - attendance_poiu_2025_06_11
-- - attendance_daily_attendanc_2025_06_10
-- etc.
--
-- La struttura è definita in:
-- - user-service/services/qr_service.go -> CreateAttendanceTable()
-- - Migrazioni 0008 e 0009 per triggers e automation
--
-- Status values usati: 'not_registered', 'present', 'hospital', 'family', 
--                      'emergency', 'personal', 'vacancy'

-- Questo file è mantenuto per riferimento storico ma non crea più tabelle

-- ============================================================================
-- LEGACY CODE (DISABILITATO)
-- ============================================================================

-- CREATE TABLE IF NOT EXISTS attendance (
--     ...tabella non più usata...
-- );

SELECT 'Migration 0004: DISABLED - System uses dynamic tables instead of static attendance table' as notice;

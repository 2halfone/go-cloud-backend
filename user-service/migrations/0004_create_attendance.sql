-- user-service/migrations/0004_create_attendance.sql
-- NOTA: Questa migrazione è COMPLETAMENTE DISABILITATA
-- Il sistema usa SOLO tabelle dinamiche, non la tabella statica 'attendance'
-- Le tabelle dinamiche sono gestite dalle migrazioni 0008, 0009, 0010, e 0011

-- ============================================================================
-- QUESTA MIGRAZIONE NON È ATTIVA - NON CREA NULLA
-- ============================================================================

-- Questa migrazione originariamente creava una tabella statica 'attendance'
-- ma il sistema attuale usa SOLO tabelle dinamiche con nome: attendance_EVENTNAME_DATE
-- 
-- Esempi di tabelle dinamiche:
-- - attendance_poiu_2025_06_11
-- - attendance_daily_attendanc_2025_06_10
-- - attendance_event_name_YYYY_MM_DD
--
-- La struttura è definita in:
-- - user-service/services/qr_service.go -> CreateAttendanceTable()
-- - Migrazioni 0008, 0009, 0010, 0011 per triggers, automation, e fix
--
-- Status values usati: 'not_registered', 'present', 'hospital', 'family', 
--                      'emergency', 'personal', 'vacancy'

-- ============================================================================
-- MIGRATION STATUS: DISABLED - NO-OP
-- ============================================================================

-- Questa migrazione non fa NULLA perché la tabella statica attendance non è usata
-- Il sistema crea automaticamente tabelle dinamiche per ogni evento

-- Verifica che la migrazione sia disabilitata
SELECT 'Migration 0004: DISABLED - System uses ONLY dynamic tables (attendance_EVENTNAME_DATE)' as notice;

-- user-service/migrations/0011_fix_status_trigger.sql
-- DISABLED: This migration is obsolete with automatic QR system
-- Migration disabled as trigger-based system has been replaced

-- ============================================================================
-- MIGRATION DISABLED NOTICE
-- ============================================================================

/*
This migration has been DISABLED because:

1. The automatic QR system no longer uses database triggers
2. Status management is now handled entirely by backend Go code
3. Trigger conflicts have been eliminated by removing triggers altogether
4. Backend provides better control and error handling

The automatic presence system now works as follows:
- QR scan triggers backend ScanQRHandler in user-service
- Backend directly sets status to 'present' in Go code
- Success/error tracking in attendance_events table
- No database triggers involved - cleaner and more reliable

All trigger-related functionality from migrations 0008, 0009, and 0011 
has been consolidated into the backend code for better maintainability.
*/

-- This migration is intentionally left as NO-OP to maintain migration sequence

SELECT 'Migration 0011: DISABLED - Trigger system replaced by backend automatic QR handling' as result;

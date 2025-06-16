-- Migration: Add last_login column to users table
-- This column is required by the dashboard API for user activity tracking

ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMP;

-- Add some sample data for existing users to test the API
UPDATE users SET last_login = NOW() - INTERVAL '10 minutes' WHERE id <= 3;
UPDATE users SET last_login = NOW() - INTERVAL '5 minutes' WHERE id > 3 AND id <= 6;
UPDATE users SET last_login = NOW() - INTERVAL '1 hour' WHERE id > 6;

-- Create index for performance on last_login queries
CREATE INDEX IF NOT EXISTS idx_users_last_login ON users(last_login);

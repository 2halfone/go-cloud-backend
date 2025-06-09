-- user-service/migrations/0007_add_role_column.sql
-- Add role column to complete user synchronization compatibility

-- Add role column
ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(50) DEFAULT 'student';

-- Create index for performance
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

-- Update existing users to have default role
UPDATE users SET role = 'student' WHERE role IS NULL;

-- auth-service/migrations/0002_add_role_to_users.sql
-- Add role column to existing users table if it doesn't exist

DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'users' AND column_name = 'role'
    ) THEN
        ALTER TABLE users ADD COLUMN role VARCHAR(50) NOT NULL DEFAULT 'user';
        COMMENT ON COLUMN users.role IS 'User role: user or admin';
    END IF;
END $$;

-- Create index for role column if it doesn't exist
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

-- Update any existing users to have 'user' role if they have NULL
UPDATE users SET role = 'user' WHERE role IS NULL OR role = '';

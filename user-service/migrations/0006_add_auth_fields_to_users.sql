-- user-service/migrations/0006_add_auth_fields_to_users.sql
-- Add auth-service compatible fields to support user synchronization

-- Add email and username columns if they don't exist
ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(255) UNIQUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS username VARCHAR(255) UNIQUE;

-- Rename timestamp to created_at to match auth-service
ALTER TABLE users RENAME COLUMN timestamp TO created_at;

-- Add updated_at column for consistency
ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- Set default values for existing users
UPDATE users SET 
    email = CONCAT('user', id, '@local.system'),
    username = CONCAT('user', id)
WHERE email IS NULL OR username IS NULL;

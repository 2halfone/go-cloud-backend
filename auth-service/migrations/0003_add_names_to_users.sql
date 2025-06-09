-- auth-service/migrations/0003_add_names_to_users.sql
-- Add name and surname columns to users table for JWT enrichment

DO $$ 
BEGIN
    -- Add name column if it doesn't exist
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'users' AND column_name = 'name'
    ) THEN
        ALTER TABLE users ADD COLUMN name VARCHAR(100);
        COMMENT ON COLUMN users.name IS 'User first name';
    END IF;
    
    -- Add surname column if it doesn't exist
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'users' AND column_name = 'surname'
    ) THEN
        ALTER TABLE users ADD COLUMN surname VARCHAR(100);
        COMMENT ON COLUMN users.surname IS 'User last name';
    END IF;
END $$;

-- Create indexes for names (useful for searching)
CREATE INDEX IF NOT EXISTS idx_users_name ON users(name);
CREATE INDEX IF NOT EXISTS idx_users_surname ON users(surname);

-- Set default values for existing users (optional - can be updated manually)
UPDATE users SET name = 'User', surname = username WHERE name IS NULL;

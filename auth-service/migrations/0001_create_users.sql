-- auth-service/migrations/0001_create_users.sql
-- Crea la tabella users con tutti i campi richiesti dalle migration successive

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    name VARCHAR(100),
    surname VARCHAR(100),
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

COMMENT ON COLUMN users.role IS 'User role: user or admin';
COMMENT ON COLUMN users.name IS 'User first name';
COMMENT ON COLUMN users.surname IS 'User last name';

-- Indici suggeriti dalle migration successive
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_name ON users(name);
CREATE INDEX IF NOT EXISTS idx_users_surname ON users(surname);
CREATE INDEX IF NOT EXISTS idx_users_last_login ON users(last_login);

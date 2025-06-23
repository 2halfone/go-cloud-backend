-- Migration 0006: Crea tabella auth_logs compatibile con frontend e backend

CREATE TABLE IF NOT EXISTS auth_logs (
    id SERIAL PRIMARY KEY,
    user_email VARCHAR(255) NOT NULL,
    username VARCHAR(255),
    action VARCHAR(64) NOT NULL,
    ip_address VARCHAR(64),
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_auth_logs_user_email ON auth_logs(user_email);
CREATE INDEX IF NOT EXISTS idx_auth_logs_action ON auth_logs(action);
CREATE INDEX IF NOT EXISTS idx_auth_logs_timestamp ON auth_logs(timestamp);

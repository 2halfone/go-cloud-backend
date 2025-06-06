-- auth-service/migrations/0001_create_auth_logs.sql

CREATE TABLE IF NOT EXISTS auth_logs (
  id SERIAL PRIMARY KEY,
  user_email TEXT NOT NULL,
  action TEXT NOT NULL,
  timestamp TIMESTAMPTZ NOT NULL DEFAULT now()
);
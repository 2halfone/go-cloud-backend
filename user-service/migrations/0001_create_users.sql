-- user-service/migrations/0001_create_users.sql

CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  timestamp TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Migration: crea tabella auth_log per tracciare i login/logout
CREATE TABLE IF NOT EXISTS auth_log (
  id SERIAL PRIMARY KEY,
  user_email VARCHAR(255),
  username VARCHAR(100),
  action VARCHAR(50),
  ip VARCHAR(50),
  user_agent TEXT,
  success BOOLEAN,
  created_at TIMESTAMP DEFAULT NOW()
);

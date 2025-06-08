-- user-service/migrations/0005_add_role_to_users.sql
-- Aggiunge il campo role alla tabella users per distinguere user/admin

ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) DEFAULT 'user';

-- Aggiorna eventuali admin esistenti (esempio)
-- UPDATE users SET role = 'admin' WHERE email = 'admin@example.com';

-- Aggiungi constraint per validare i ruoli
ALTER TABLE users ADD CONSTRAINT check_role CHECK (role IN ('user', 'admin'));

CREATE TABLE IF NOT EXISTS social_logs (
    id SERIAL PRIMARY KEY,
    social VARCHAR(50) NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    content TEXT NOT NULL,
    status VARCHAR(20) NOT NULL
);

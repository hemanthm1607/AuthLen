-- 005_target_url_default.sql
-- Ensure default target URL for workspace settings is http://localhost:4000
ALTER TABLE user_settings ALTER COLUMN target_url SET DEFAULT 'http://localhost:4000';
UPDATE user_settings SET target_url = 'http://localhost:4000' WHERE target_url = 'https://demo.authlens.dev';

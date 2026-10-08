-- 004_remediation_source_context.sql
-- Enhance remediations table with verified source context tracking, SHA-256 file fingerprints,
-- and applicability indicators to prevent placeholder patches.

ALTER TABLE remediations ADD COLUMN IF NOT EXISTS file_fingerprint VARCHAR(64);
ALTER TABLE remediations ADD COLUMN IF NOT EXISTS is_applicable BOOLEAN DEFAULT TRUE;
ALTER TABLE remediations ADD COLUMN IF NOT EXISTS source_available BOOLEAN DEFAULT FALSE;

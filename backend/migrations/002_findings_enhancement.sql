-- 002_findings_enhancement.sql
-- Add status, evidence, and is_automated columns to findings table

ALTER TABLE findings ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'FAIL';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS evidence TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS is_automated BOOLEAN DEFAULT TRUE;

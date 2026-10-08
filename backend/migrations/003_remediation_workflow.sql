-- 003_remediation_workflow.sql
-- AuthLens User-Approved AI Code Remediation and Audit Ledger Schema
-- Enforces auditable patch tracking, approval timestamps, backup references, and verification results

CREATE TABLE IF NOT EXISTS remediations (
  id VARCHAR(50) PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  assessment_id VARCHAR(50) NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  finding_id VARCHAR(50) NOT NULL,
  project_path VARCHAR(500),
  target_file VARCHAR(500) NOT NULL,
  patch_version INTEGER DEFAULT 1,
  status VARCHAR(50) NOT NULL DEFAULT 'PATCH_GENERATED',
  problem_summary TEXT,
  recommended_fix TEXT,
  code_before TEXT,
  code_after TEXT,
  affected_components TEXT[],
  potential_side_effects TEXT,
  verification_steps TEXT[],
  confidence_level VARCHAR(20),
  manual_review_required BOOLEAN DEFAULT TRUE,
  user_action VARCHAR(50),
  approved_at TIMESTAMP WITH TIME ZONE,
  applied_at TIMESTAMP WITH TIME ZONE,
  verified_at TIMESTAMP WITH TIME ZONE,
  rolled_back_at TIMESTAMP WITH TIME ZONE,
  backup_id VARCHAR(150),
  verification_output TEXT,
  error_message TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_remediations_user_id ON remediations (user_id);
CREATE INDEX IF NOT EXISTS idx_remediations_assessment ON remediations (assessment_id);
CREATE INDEX IF NOT EXISTS idx_remediations_finding ON remediations (finding_id);
CREATE INDEX IF NOT EXISTS idx_remediations_status ON remediations (status);

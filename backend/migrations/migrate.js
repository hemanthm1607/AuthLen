/**
 * migrations/migrate.js — Safe SQL migration runner
 */
const fs = require('fs');
const path = require('path');
const { pool } = require('../config/db');

const EMBEDDED_MIGRATIONS = [
  {
    version: '001_initial_schema.sql',
    sql: `
      CREATE EXTENSION IF NOT EXISTS "pgcrypto";

      CREATE TABLE IF NOT EXISTS "session" (
        "sid" varchar NOT NULL COLLATE "default",
        "sess" json NOT NULL,
        "expire" timestamp(6) NOT NULL,
        CONSTRAINT "session_pkey" PRIMARY KEY ("sid") NOT DEFERRABLE INITIALLY IMMEDIATE
      );
      CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "session" ("expire");

      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        full_name VARCHAR(150) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        is_verified BOOLEAN DEFAULT FALSE,
        verification_token VARCHAR(255),
        verification_token_expires TIMESTAMP WITH TIME ZONE,
        reset_token VARCHAR(255),
        reset_token_expires TIMESTAMP WITH TIME ZONE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS idx_users_email ON users (LOWER(email));

      CREATE TABLE IF NOT EXISTS user_settings (
        user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        demo_mode BOOLEAN DEFAULT TRUE,
        dark_mode BOOLEAN DEFAULT TRUE,
        verbose_findings BOOLEAN DEFAULT FALSE,
        auto_retest BOOLEAN DEFAULT FALSE,
        notifications BOOLEAN DEFAULT TRUE,
        show_code_snippets BOOLEAN DEFAULT TRUE,
        wcag_level VARCHAR(10) DEFAULT 'AA',
        target_url VARCHAR(500) DEFAULT 'https://demo.authlens.dev',
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS assessments (
        id VARCHAR(50) PRIMARY KEY,
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        target VARCHAR(255) NOT NULL,
        date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        overall_score INTEGER NOT NULL CHECK (overall_score >= 0 AND overall_score <= 100),
        critical INTEGER DEFAULT 0,
        high INTEGER DEFAULT 0,
        medium INTEGER DEFAULT 0,
        low INTEGER DEFAULT 0,
        duration VARCHAR(50) DEFAULT '1.4s',
        status VARCHAR(50) DEFAULT 'completed',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS idx_assessments_user_id ON assessments (user_id);

      CREATE TABLE IF NOT EXISTS findings (
        id VARCHAR(50) NOT NULL,
        assessment_id VARCHAR(50) REFERENCES assessments(id) ON DELETE CASCADE,
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(255) NOT NULL,
        category VARCHAR(100) NOT NULL,
        severity VARCHAR(50) NOT NULL,
        risk TEXT,
        recommendation TEXT,
        code_before TEXT,
        code_after TEXT,
        is_fixed BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id, assessment_id)
      );
      CREATE INDEX IF NOT EXISTS idx_findings_user_id ON findings (user_id);
    `,
  },
  {
    version: '002_findings_enhancement.sql',
    sql: `
      ALTER TABLE findings ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'FAIL';
      ALTER TABLE findings ADD COLUMN IF NOT EXISTS evidence TEXT;
      ALTER TABLE findings ADD COLUMN IF NOT EXISTS is_automated BOOLEAN DEFAULT TRUE;
    `,
  },
  {
    version: '003_remediation_workflow.sql',
    sql: `
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
    `,
  },
  {
    version: '004_remediation_source_context.sql',
    sql: `
      ALTER TABLE remediations ADD COLUMN IF NOT EXISTS file_fingerprint VARCHAR(64);
      ALTER TABLE remediations ADD COLUMN IF NOT EXISTS is_applicable BOOLEAN DEFAULT TRUE;
      ALTER TABLE remediations ADD COLUMN IF NOT EXISTS source_available BOOLEAN DEFAULT FALSE;
    `,
  },
];

async function runMigrations() {
  const client = await pool.connect();
  try {
    console.log('[MIGRATION] Checking database schema status...');
    await client.query('BEGIN');

    // Create migrations tracker table if not exists
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version VARCHAR(100) PRIMARY KEY,
        applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Determine migrations to run: filesystem first, fallback to embedded
    let migrationList = [];
    try {
      if (fs.existsSync(__dirname)) {
        const files = fs
          .readdirSync(__dirname)
          .filter((f) => f.endsWith('.sql'))
          .sort();
        if (files.length > 0) {
          migrationList = files.map((file) => ({
            version: file,
            sql: fs.readFileSync(path.join(__dirname, file), 'utf8'),
          }));
        }
      }
    } catch (_) {
      // Filesystem read failed (common in bundled serverless environments)
    }

    if (migrationList.length === 0) {
      migrationList = EMBEDDED_MIGRATIONS;
    }

    for (const item of migrationList) {
      const alreadyApplied = await client.query(
        'SELECT 1 FROM schema_migrations WHERE version = $1',
        [item.version]
      );

      if (alreadyApplied.rows.length === 0) {
        console.log(`[MIGRATION] Applying: ${item.version}...`);
        await client.query(item.sql);
        await client.query(
          'INSERT INTO schema_migrations (version) VALUES ($1)',
          [item.version]
        );
        console.log(`[MIGRATION] Successfully applied: ${item.version}`);
      }
    }

    await client.query('COMMIT');
    console.log('[MIGRATION] Database schema verified & ready.');
    return { success: true };
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[MIGRATION ERROR]:', {
      message: err.message,
      code: err.code,
    });
    return { success: false, error: err.message };
  } finally {
    client.release();
  }
}

if (require.main === module) {
  runMigrations()
    .then((res) => {
      if (!res.success) process.exit(1);
      process.exit(0);
    })
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}

module.exports = { runMigrations };

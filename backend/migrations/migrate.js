/**
 * migrations/migrate.js — Safe SQL migration runner
 */
const fs = require('fs');
const path = require('path');
const { pool } = require('../config/db');

async function runMigrations() {
  const client = await pool.connect();
  try {
    console.log('Beginning database migration check...');
    await client.query('BEGIN');

    // Create migrations tracker table if not exists
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version VARCHAR(100) PRIMARY KEY,
        applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);

    const files = fs.readdirSync(__dirname)
      .filter((f) => f.endsWith('.sql'))
      .sort();

    for (const file of files) {
      const alreadyApplied = await client.query(
        'SELECT 1 FROM schema_migrations WHERE version = $1',
        [file]
      );

      if (alreadyApplied.rows.length === 0) {
        console.log(`Applying migration: ${file}...`);
        const sql = fs.readFileSync(path.join(__dirname, file), 'utf8');
        await client.query(sql);
        await client.query(
          'INSERT INTO schema_migrations (version) VALUES ($1)',
          [file]
        );
        console.log(`Successfully applied: ${file}`);
      } else {
        console.log(`Migration ${file} is already applied.`);
      }
    }

    await client.query('COMMIT');
    console.log('Database migrations completed successfully.');
    return { success: true };
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Migration failed, rolled back changes:', err.message);
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

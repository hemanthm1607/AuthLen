/**
 * server.js — AuthLens Express Backend Entry Point
 * Starts HTTP listener for local development and integration testing.
 */
const app = require('./app');
const { testConnection } = require('./config/db');
const { runMigrations } = require('./migrations/migrate');

const PORT = parseInt(process.env.PORT, 10) || 4000;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';

const server = app.listen(PORT, async () => {
  console.log(`\n======================================================`);
  console.log(`  AuthLens Backend Server running on port ${PORT}`);
  console.log(`  Frontend URL: ${FRONTEND_URL}`);
  console.log(`  Environment:  ${process.env.NODE_ENV || 'development'}`);
  console.log(`======================================================\n`);

  // Test database connection and initialize migrations
  const dbCheck = await testConnection();
  if (dbCheck.success) {
    console.log(`[DB CONNECTED] Connected to PostgreSQL "${dbCheck.database}" as user "${dbCheck.user}"`);
    await runMigrations();
  } else {
    console.warn(`[DB WARNING] Could not connect to PostgreSQL: ${dbCheck.error}`);
    console.warn(`[DB ACTION REQUIRED] Please verify DB_USER and DB_PASSWORD or DATABASE_URL in backend/.env`);
  }
});

module.exports = { app, server };

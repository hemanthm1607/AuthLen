/**
 * config/db.js — PostgreSQL Database Connection Pool
 * Supports local configuration, Vercel Serverless environment,
 * and cloud PostgreSQL providers (Neon, Supabase, Vercel Postgres, AWS RDS).
 */
const path = require('path');
// Load local .env if present (in serverless/cloud, env vars are injected by platform)
try {
  require('dotenv').config({ path: path.resolve(__dirname, '../.env') });
} catch (_) {}

const { Pool } = require('pg');

const connectionString = process.env.DATABASE_URL || process.env.POSTGRES_URL;
const isServerless = Boolean(process.env.VERCEL);

let poolConfig;

if (connectionString) {
  const isLocal = connectionString.includes('localhost') || connectionString.includes('127.0.0.1');
  poolConfig = {
    connectionString,
    ssl: isLocal || process.env.DB_SSL === 'false' ? false : { rejectUnauthorized: false },
    max: parseInt(process.env.DB_POOL_MAX, 10) || (isServerless ? 5 : 20),
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
  };
} else {
  poolConfig = {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT, 10) || 5432,
    database: process.env.DB_NAME || 'authlens_db',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD !== undefined ? String(process.env.DB_PASSWORD) : '',
    ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
    max: parseInt(process.env.DB_POOL_MAX, 10) || (isServerless ? 5 : 20),
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
  };
}

const pool = new Pool(poolConfig);

pool.on('error', (err) => {
  console.error('Unexpected error on idle PostgreSQL client:', err.message);
});

async function testConnection() {
  let client;
  try {
    client = await pool.connect();
    const res = await client.query('SELECT current_database(), current_user, version()');
    return {
      success: true,
      database: res.rows[0].current_database,
      user: res.rows[0].current_user,
      version: res.rows[0].version.split(' ')[0] + ' ' + res.rows[0].version.split(' ')[1],
    };
  } catch (err) {
    return {
      success: false,
      error: err.message,
      code: err.code,
    };
  } finally {
    if (client) client.release();
  }
}

module.exports = {
  pool,
  query: (text, params) => pool.query(text, params),
  testConnection,
};

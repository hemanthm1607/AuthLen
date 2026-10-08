/**
 * config/db.js — PostgreSQL Database Connection Pool
 */
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });
const { Pool } = require('pg');

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT, 10) || 5432,
  database: process.env.DB_NAME || 'authlens_db',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD !== undefined ? String(process.env.DB_PASSWORD) : '',
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

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

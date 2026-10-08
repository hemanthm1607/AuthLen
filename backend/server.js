/**
 * server.js — AuthLens Express Backend Entry Point
 */
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '.env') });
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);

const { pool, testConnection } = require('./config/db');
const { runMigrations } = require('./migrations/migrate');

const authRoutes = require('./routes/authRoutes');
const assessmentRoutes = require('./routes/assessmentRoutes');
const settingsRoutes = require('./routes/settingsRoutes');
const aiRoutes = require('./routes/aiRoutes');

const app = express();
const PORT = parseInt(process.env.PORT, 10) || 4000;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';
const isProd = process.env.NODE_ENV === 'production';

// Security Headers via Helmet
app.use(
  helmet({
    contentSecurityPolicy: false, // Managed by frontend bundle
    crossOriginEmbedderPolicy: false,
  })
);

// CORS configuration for credentials (session cookies)
app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (curl, mobile apps, same-origin)
      if (!origin) return callback(null, true);
      if (
        origin === FRONTEND_URL ||
        /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)
      ) {
        return callback(null, true);
      }
      return callback(new Error(`Origin ${origin} not allowed by CORS`));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  })
);

// Body parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session Store Configuration
let sessionStore;
try {
  sessionStore = new PgSession({
    pool: pool,
    tableName: 'session',
    createTableIfMissing: true,
    pruneSessionInterval: 60 * 15, // Prune expired sessions every 15 mins
  });
} catch (err) {
  console.warn('[SESSION STORE] Falling back to MemoryStore (PG pool unavailable):', err.message);
}

app.use(
  session({
    name: 'authlens_session',
    store: sessionStore,
    secret: process.env.SESSION_SECRET || 'authlens_dev_secret_change_in_production',
    resave: false,
    saveUninitialized: false,
    rolling: true, // Refresh cookie expiry on activity
    cookie: {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? 'strict' : 'lax',
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      path: '/',
    },
  })
);

// Health check endpoint
app.get('/api/health', async (req, res) => {
  const dbStatus = await testConnection();
  return res.json({
    status: 'ok',
    serverTime: new Date().toISOString(),
    database: {
      connected: dbStatus.success,
      name: dbStatus.database || process.env.DB_NAME,
      user: dbStatus.user,
      version: dbStatus.version,
      error: dbStatus.error,
    },
  });
});

// Mount API Routes
app.use('/api/auth', authRoutes);
app.use('/api/assessments', assessmentRoutes);
app.use('/api/settings', settingsRoutes);
app.use('/api/ai', aiRoutes);

// Non-production test helper to clear rate limits between test runs
if (!isProd) {
  const { resetLoginRateLimit } = require('./middleware/rateLimiter');
  app.post('/api/auth/reset-rate-limit', (req, res) => {
    resetLoginRateLimit();
    return res.json({ success: true, message: 'Rate limits reset for test/dev environment.' });
  });
}

// Centralized safe error handler (never leaks stack traces to client)
app.use((err, req, res, next) => {
  console.error('[UNHANDLED SERVER ERROR]:', err.message);
  return res.status(err.status || 500).json({
    error: isProd ? 'Internal server error.' : err.message,
    code: err.code || 'SERVER_ERROR',
  });
});

// Start Express server
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
    console.warn(`[DB ACTION REQUIRED] Please verify DB_USER and DB_PASSWORD in backend/.env`);
  }
});

module.exports = { app, server };

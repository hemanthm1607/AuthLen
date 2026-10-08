/**
 * app.js — AuthLens Express Application Configuration
 * Adaptable for both persistent server runs and Vercel serverless functions.
 */
const path = require('path');
// Load local .env if present (in cloud/serverless, env vars are injected by platform)
try {
  require('dotenv').config({ path: path.resolve(__dirname, '.env') });
} catch (_) {}

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
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';
const isProd = process.env.NODE_ENV === 'production';
const isServerless = Boolean(process.env.VERCEL);

// Crucial for Vercel & reverse proxies: allows Express to trust X-Forwarded-* headers for HTTPS cookies & rate limiting
app.set('trust proxy', 1);

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
      // Allow requests with no origin (curl, same-origin fetch, mobile apps)
      if (!origin) return callback(null, true);
      if (
        origin === FRONTEND_URL ||
        origin.endsWith('.vercel.app') ||
        /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin) ||
        (process.env.ALLOWED_ORIGINS && process.env.ALLOWED_ORIGINS.split(',').map((s) => s.trim()).includes(origin))
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
    pruneSessionInterval: isServerless ? false : 60 * 15, // Disable background timers on serverless to avoid unhandled exits
  });

  sessionStore.on('error', (err) => {
    console.error('[SESSION STORE ERROR]:', {
      message: err.message,
      code: err.code,
    });
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
      sameSite: 'lax', // Compatible with same-origin and top-level navigation
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      path: '/',
    },
  })
);

// Safe request logging (never logs sensitive body fields, headers, tokens, or cookies)
app.use((req, res, next) => {
  if (isServerless || isProd) {
    console.log(`[REQUEST] ${req.method} ${req.path}`);
  }
  next();
});

// Lazy migration guarantee on cold starts
let migrationPromise = null;
async function ensureMigrations() {
  if (!migrationPromise) {
    migrationPromise = runMigrations()
      .then((res) => {
        if (!res.success) {
          migrationPromise = null;
          console.error('[DB MIGRATIONS FAILED]:', res.error);
        }
        return res;
      })
      .catch((err) => {
        console.error('[DB MIGRATIONS EXCEPTION]:', err.message);
        migrationPromise = null;
        return { success: false, error: err.message };
      });
  }
  return migrationPromise;
}

// Automatically ensure migrations exist before servicing API requests
app.use(async (req, res, next) => {
  if (req.path === '/api/health' || req.path === '/health') {
    return next();
  }

  try {
    await ensureMigrations();
  } catch (err) {
    console.error(`[DB INIT ERROR on ${req.method} ${req.path}]:`, err.message);
  }
  next();
});

// Health check endpoint (matches both /api/health and /health)
app.get(['/api/health', '/health'], async (req, res) => {
  const dbStatus = await testConnection();
  if (dbStatus.success && isServerless) {
    // Ensure migrations exist on cloud database if not already run
    await ensureMigrations();
  }

  return res.json({
    status: 'ok',
    serverTime: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    serverless: isServerless,
    database: {
      connected: dbStatus.success,
      name: dbStatus.database || process.env.DB_NAME,
      user: dbStatus.user,
      version: dbStatus.version,
      error: dbStatus.error,
    },
  });
});

// Mount API Routes under both /api/* and /* for full Vercel rewrite resilience
app.use(['/api/auth', '/auth'], authRoutes);
app.use(['/api/assessments', '/assessments'], assessmentRoutes);
app.use(['/api/settings', '/settings'], settingsRoutes);
app.use(['/api/ai', '/ai'], aiRoutes);

// Non-production test helper to clear rate limits between test runs
if (!isProd) {
  const { resetLoginRateLimit } = require('./middleware/rateLimiter');
  app.post(['/api/auth/reset-rate-limit', '/auth/reset-rate-limit'], (req, res) => {
    resetLoginRateLimit();
    return res.json({ success: true, message: 'Rate limits reset for test/dev environment.' });
  });
}

// Centralized safe error handler (never leaks stack traces or credentials to client)
app.use((err, req, res, next) => {
  console.error('[UNHANDLED SERVER ERROR]:', {
    method: req.method,
    path: req.path,
    message: err.message,
    code: err.code,
    stack: isProd ? undefined : err.stack,
  });
  return res.status(err.status || 500).json({
    error: isProd ? 'Internal server error.' : err.message,
    code: err.code || 'SERVER_ERROR',
  });
});

module.exports = app;

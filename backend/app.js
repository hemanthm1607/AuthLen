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
const remediationRoutes = require('./routes/remediationRoutes');

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

// Serve accessible interactive authentication portal on root and login paths
app.get(['/', '/login'], (req, res) => {
  return res.type('html').send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AuthLens — Authentication Portal</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: rgba(18, 24, 38, 0.85);
      --border: rgba(255, 255, 255, 0.08);
      --accent: #6366f1;
      --text: #f8fafc;
      --text-muted: #94a3b8;
    }
    body {
      margin: 0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
    }
    .auth-card {
      width: 100%;
      max-width: 420px;
      padding: 2.5rem;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 1rem;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
    }
    .form-group {
      margin-bottom: 1.25rem;
    }
    label {
      display: block;
      margin-bottom: 0.5rem;
      font-size: 0.875rem;
      font-weight: 500;
      color: var(--text-muted);
    }
    input[type="email"], input[type="password"] {
      width: 100%;
      box-sizing: border-box;
      padding: 0.75rem 1rem;
      border: 1px solid var(--border);
      border-radius: 0.5rem;
      background: rgba(15, 23, 42, 0.6);
      color: #fff;
      font-size: 0.95rem;
    }
    input:focus-visible, button:focus-visible {
      outline: 2px solid var(--accent);
      outline-offset: 2px;
    }
    .password-wrapper {
      position: relative;
    }
    .auth-password-toggle {
      position: absolute;
      right: 0.75rem;
      top: 50%;
      transform: translateY(-50%);
      background: none;
      border: none;
      color: var(--text-muted);
      cursor: pointer;
      font-size: 0.8rem;
    }
    .form-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1.5rem;
      font-size: 0.85rem;
    }
    .btn-submit {
      width: 100%;
      padding: 0.75rem 1.5rem;
      background: var(--accent);
      color: #fff;
      border: none;
      border-radius: 0.5rem;
      font-weight: 600;
      cursor: pointer;
    }
    .btn-submit:disabled {
      opacity: 0.6;
      cursor: not-allowed;
    }
    .alert-region {
      min-height: 1.5rem;
      margin-bottom: 1rem;
      font-size: 0.85rem;
      color: #ef4444;
    }
    a {
      color: #818cf8;
      text-decoration: none;
    }
    a:hover {
      text-decoration: underline;
    }
  </style>
</head>
<body>
  <div class="auth-card">
    <h1>Sign In</h1>
    <div id="auth-alert" class="alert-region" role="alert" aria-live="polite"></div>
    <form id="auth-form" action="/api/auth/login" method="POST">
      <div class="form-group">
        <label for="email">Work Email</label>
        <input id="email" name="email" type="email" autocomplete="username" required placeholder="name@company.com" />
      </div>
      <div class="form-group">
        <label for="password">Password</label>
        <div class="password-wrapper">
          <input id="password" name="password" type="password" autocomplete="current-password" required placeholder="••••••••" />
          <button type="button" id="toggle-password" class="auth-password-toggle" aria-label="Toggle password visibility">Show password</button>
        </div>
      </div>
      <div class="form-row">
        <label for="remember-me" style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer; margin-bottom: 0;">
          <input id="remember-me" name="remember" type="checkbox" />
          <span>Remember me on this device</span>
        </label>
        <a href="/api/auth/forgot-password" id="forgot-password-link">Forgot password?</a>
      </div>
      <button type="submit" id="submit-btn" class="btn-submit" disabled={loading} data-loading-text="Authenticating...">Sign In</button>
    </form>
  </div>
  <script>
    const toggleBtn = document.getElementById('toggle-password');
    const pwdInput = document.getElementById('password');
    if (toggleBtn && pwdInput) {
      toggleBtn.addEventListener('click', () => {
        const isPwd = pwdInput.type === 'password';
        pwdInput.type = isPwd ? 'text' : 'password';
        toggleBtn.textContent = isPwd ? 'Hide password' : 'Show password';
      });
    }
  </script>
</body>
</html>`);
});

// Mount API Routes under both /api/* and /* for full Vercel rewrite resilience
app.use(['/api/auth', '/auth'], authRoutes);
app.use(['/api/assessments', '/assessments'], assessmentRoutes);
app.use(['/api/settings', '/settings'], settingsRoutes);
app.use(['/api/ai', '/ai'], aiRoutes);
app.use(['/api/remediations', '/remediations'], remediationRoutes);

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

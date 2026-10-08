/**
 * middleware/rateLimiter.js — Rate Limiting Middleware for Auth Endpoints
 */
const { rateLimit, ipKeyGenerator } = require('express-rate-limit');

// Configurable time window and maximum attempt thresholds
const LOGIN_WINDOW_MS = parseInt(process.env.LOGIN_RATE_LIMIT_WINDOW_MS, 10) || 15 * 60 * 1000; // 15 mins default
const LOGIN_MAX_ATTEMPTS = parseInt(process.env.LOGIN_RATE_LIMIT_MAX, 10) || 5; // 5 attempts default

/**
 * Dedicated Rate Limiter for Login Endpoint (SEC-001)
 * Enforces strict limits against automated brute-force password spraying.
 * - Uses sliding window and strict request limit from config.
 * - Returns HTTP 429 after configured limit is exceeded.
 * - Sets Retry-After header and standard RateLimit headers.
 * - Returns generic non-sensitive error message.
 * - Skips successful logins so legitimate users are not penalized.
 * - Does not trust arbitrary forwarded IP headers (uses socket IP safely).
 */
const loginLimiter = rateLimit({
  windowMs: LOGIN_WINDOW_MS,
  max: LOGIN_MAX_ATTEMPTS,
  standardHeaders: true, // Sends standard RateLimit-* headers
  legacyHeaders: false,
  skipSuccessfulRequests: true, // Legitimate logins do not consume the brute-force failure allowance
  validate: {
    xForwardedForHeader: false, // Safely ignore arbitrary forwarded headers when trust proxy is disabled
    default: true,
  },
  handler: (req, res, next, options) => {
    const retryAfterSec = Math.ceil(options.windowMs / 1000);
    res.setHeader('Retry-After', retryAfterSec);
    return res.status(429).json({
      error: 'Too many failed login attempts. Please try again later.',
      code: 'LOGIN_RATE_LIMIT_EXCEEDED',
      retryAfter: retryAfterSec,
    });
  },
});

/**
 * General Auth Limiter (for forgot password and reset password flows)
 */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  validate: {
    xForwardedForHeader: false,
    default: true,
  },
  handler: (req, res, next, options) => {
    const retryAfterSec = Math.ceil(options.windowMs / 1000);
    res.setHeader('Retry-After', retryAfterSec);
    return res.status(429).json({
      error: 'Too many authentication requests. Please try again later.',
      code: 'RATE_LIMIT_EXCEEDED',
      retryAfter: retryAfterSec,
    });
  },
});

/**
 * Registration Limiter (prevents account generation spam)
 */
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // Max 10 registrations per hour per IP
  standardHeaders: true,
  legacyHeaders: false,
  validate: {
    xForwardedForHeader: false,
    default: true,
  },
  handler: (req, res, next, options) => {
    const retryAfterSec = Math.ceil(options.windowMs / 1000);
    res.setHeader('Retry-After', retryAfterSec);
    return res.status(429).json({
      error: 'Too many accounts created from this IP. Please try again later.',
      code: 'RATE_LIMIT_EXCEEDED',
      retryAfter: retryAfterSec,
    });
  },
});

/**
 * AI Generation Limiter (prevents quota exhaustion)
 */
const aiLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 10, // Max 10 requests per 5 minutes per IP
  standardHeaders: true,
  legacyHeaders: false,
  validate: {
    xForwardedForHeader: false,
    default: true,
  },
  handler: (req, res, next, options) => {
    const retryAfterSec = Math.ceil(options.windowMs / 1000);
    res.setHeader('Retry-After', retryAfterSec);
    return res.status(429).json({
      error: 'Too many AI recommendation requests. Please wait a few minutes before trying again.',
      code: 'AI_RATE_LIMIT_EXCEEDED',
      retryAfter: retryAfterSec,
    });
  },
});

/**
 * Safe helper to reset rate limit store for local loopback during automated test runs
 */
function resetLoginRateLimit(ip) {
  try {
    const limiters = [loginLimiter, authLimiter, registerLimiter, aiLimiter];
    const targetIps = ip ? [ip] : ['127.0.0.1', '::1', '::ffff:127.0.0.1'];

    for (const limiter of limiters) {
      if (limiter && typeof limiter.resetKey === 'function') {
        for (const rawIp of targetIps) {
          limiter.resetKey(rawIp);
          if (typeof ipKeyGenerator === 'function') {
            try {
              limiter.resetKey(ipKeyGenerator(rawIp));
            } catch (_) {}
          }
        }
      }
    }
  } catch (_) {
    // Non-fatal cleanup fallback
  }
}

module.exports = {
  loginLimiter,
  authLimiter,
  registerLimiter,
  aiLimiter,
  resetLoginRateLimit,
};



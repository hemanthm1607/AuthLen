/**
 * controllers/authController.js — Authentication Controller
 * Provides secure registration, login, logout, password recovery, and email verification.
 */
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const db = require('../config/db');
const emailService = require('../services/emailService');

const BCRYPT_SALT_ROUNDS = 12;

// Password complexity check
function validatePasswordComplexity(password) {
  if (!password || password.length < 8) return false;
  const hasUpper = /[A-Z]/.test(password);
  const hasNumberOrSpecial = /[\d\W_]/.test(password);
  return hasUpper && hasNumberOrSpecial;
}

/**
 * Register new user
 * POST /api/auth/register
 */
async function register(req, res) {
  try {
    const { fullName, email, password } = req.body;

    // Validate inputs
    if (!fullName || !fullName.trim()) {
      return res.status(400).json({ error: 'Full name is required.', field: 'fullName' });
    }

    if (!email || !email.trim()) {
      return res.status(400).json({ error: 'Email address is required.', field: 'email' });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(normalizedEmail)) {
      return res.status(400).json({ error: 'Please enter a valid email address.', field: 'email' });
    }

    if (!validatePasswordComplexity(password)) {
      return res.status(400).json({
        error: 'Password must be at least 8 characters long and contain at least one uppercase letter and one number or special character.',
        field: 'password',
      });
    }

    // Check if user already exists
    const existing = await db.query('SELECT id FROM users WHERE LOWER(email) = $1', [normalizedEmail]);
    if (existing.rows.length > 0) {
      return res.status(409).json({
        error: 'An account with this email address already exists.',
        field: 'email',
      });
    }

    // Hash password with bcrypt
    const passwordHash = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

    // Generate email verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Insert user
    const insertUserSql = `
      INSERT INTO users (full_name, email, password_hash, is_verified, verification_token, verification_token_expires)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING id, full_name, email, is_verified, created_at;
    `;
    const userResult = await db.query(insertUserSql, [
      fullName.trim(),
      normalizedEmail,
      passwordHash,
      false,
      verificationToken,
      verificationExpires,
    ]);

    const newUser = userResult.rows[0];

    // Initialize user settings
    await db.query(
      `INSERT INTO user_settings (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING;`,
      [newUser.id]
    );

    // Send verification email
    await emailService.sendVerificationEmail(newUser.email, verificationToken);

    // Establish session
    req.session.regenerate((err) => {
      if (err) {
        console.error('Session regeneration error on register:', err);
      }
      req.session.userId = newUser.id;
      req.session.email = newUser.email;
      req.session.fullName = newUser.full_name;

      return res.status(201).json({
        message: 'Registration successful.',
        user: {
          id: newUser.id,
          fullName: newUser.full_name,
          email: newUser.email,
          isVerified: newUser.is_verified,
        },
      });
    });
  } catch (err) {
    console.error('Error during registration:', err.message);
    return res.status(500).json({ error: 'An unexpected error occurred. Please try again.' });
  }
}

/**
 * Sign In
 * POST /api/auth/login
 */
async function login(req, res) {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const normalizedEmail = email.trim().toLowerCase();

    // Query user by email
    const result = await db.query(
      'SELECT id, full_name, email, password_hash, is_verified FROM users WHERE LOWER(email) = $1',
      [normalizedEmail]
    );

    if (result.rows.length === 0) {
      // Safe timing-equalized error to prevent email enumeration
      await bcrypt.compare(password, '$2a$12$e8Y76Uu38a39B7Jz5m1RGea27UaN9hK85hZ5H3N5N2R6V2M8n8j8e');
      return res.status(401).json({ error: 'Invalid email address or password.' });
    }

    const user = result.rows[0];

    // Verify password
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid email address or password.' });
    }

    // Regenerate session to prevent session fixation attacks
    req.session.regenerate((err) => {
      if (err) {
        console.error('Session regeneration error on login:', err);
        return res.status(500).json({ error: 'Could not establish secure session.' });
      }

      req.session.userId = user.id;
      req.session.email = user.email;
      req.session.fullName = user.full_name;

      return res.json({
        message: 'Authentication successful.',
        user: {
          id: user.id,
          fullName: user.full_name,
          email: user.email,
          isVerified: user.is_verified,
        },
      });
    });
  } catch (err) {
    console.error('Error during login:', err.message);
    return res.status(500).json({ error: 'An unexpected server error occurred.' });
  }
}

/**
 * Sign Out
 * POST /api/auth/logout
 */
function logout(req, res) {
  if (req.session) {
    req.session.destroy((err) => {
      if (err) {
        console.error('Error destroying session:', err);
        return res.status(500).json({ error: 'Could not log out.' });
      }
      res.clearCookie('authlens_session', { path: '/' });
      res.clearCookie('connect.sid', { path: '/' });
      return res.json({ message: 'Logged out successfully.' });
    });
  } else {
    return res.json({ message: 'Logged out successfully.' });
  }
}

/**
 * Get current session user
 * GET /api/auth/me
 */
async function me(req, res) {
  try {
    if (!req.session || !req.session.userId) {
      return res.status(401).json({ error: 'No active authenticated session.', user: null });
    }

    const result = await db.query(
      'SELECT id, full_name, email, is_verified, created_at FROM users WHERE id = $1',
      [req.session.userId]
    );

    if (result.rows.length === 0) {
      req.session.destroy();
      return res.status(401).json({ error: 'User record no longer exists.', user: null });
    }

    const user = result.rows[0];
    return res.json({
      user: {
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        isVerified: user.is_verified,
        createdAt: user.created_at,
      },
    });
  } catch (err) {
    console.error('Error in /me endpoint:', err.message);
    return res.status(500).json({ error: 'Internal server error.' });
  }
}

/**
 * Forgot password request
 * POST /api/auth/forgot-password
 */
async function forgotPassword(req, res) {
  try {
    const { email } = req.body;
    if (!email || !email.trim()) {
      return res.status(400).json({ error: 'Email address is required.' });
    }

    const normalizedEmail = email.trim().toLowerCase();

    // Uniform safe message: prevents email enumeration
    const safeResponse = {
      message: 'If an account exists for this email address, password recovery instructions have been sent.',
    };

    const userRes = await db.query(
      'SELECT id, email FROM users WHERE LOWER(email) = $1',
      [normalizedEmail]
    );

    if (userRes.rows.length === 0) {
      return res.json(safeResponse);
    }

    const user = userRes.rows[0];

    // Generate single-use reset token valid for 15 minutes
    const resetToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 mins

    await db.query(
      `UPDATE users
       SET reset_token = $1, reset_token_expires = $2, updated_at = CURRENT_TIMESTAMP
       WHERE id = $3`,
      [resetToken, expiresAt, user.id]
    );

    // Dispatch email
    await emailService.sendPasswordResetEmail(user.email, resetToken);

    return res.json(safeResponse);
  } catch (err) {
    console.error('Error in forgot-password:', err.message);
    return res.status(500).json({ error: 'Internal server error.' });
  }
}

/**
 * Reset password using token
 * POST /api/auth/reset-password
 */
async function resetPassword(req, res) {
  try {
    const { token, newPassword } = req.body;

    if (!token) {
      return res.status(400).json({ error: 'Reset token is required.' });
    }

    if (!validatePasswordComplexity(newPassword)) {
      return res.status(400).json({
        error: 'Password must be at least 8 characters long and contain at least one uppercase letter and one number or special character.',
      });
    }

    // Verify token validity and expiration
    const userRes = await db.query(
      `SELECT id, email FROM users
       WHERE reset_token = $1 AND reset_token_expires > CURRENT_TIMESTAMP`,
      [token]
    );

    if (userRes.rows.length === 0) {
      return res.status(400).json({
        error: 'Password reset link is invalid or has expired. Please request a new link.',
      });
    }

    const user = userRes.rows[0];
    const newHash = await bcrypt.hash(newPassword, BCRYPT_SALT_ROUNDS);

    // Update password and burn reset token immediately
    await db.query(
      `UPDATE users
       SET password_hash = $1, reset_token = NULL, reset_token_expires = NULL, updated_at = CURRENT_TIMESTAMP
       WHERE id = $2`,
      [newHash, user.id]
    );

    // Invalidate existing active sessions across all devices for this user
    try {
      await db.query(`DELETE FROM session WHERE sess::text LIKE $1`, [`%"userId":"${user.id}"%`]);
    } catch (sessionErr) {
      // Non-fatal if session table is using alternative format
    }

    return res.json({
      message: 'Password has been reset successfully. You may now sign in with your new credentials.',
    });
  } catch (err) {
    console.error('Error in reset-password:', err.message);
    return res.status(500).json({ error: 'Internal server error.' });
  }
}

/**
 * Verify account email
 * POST /api/auth/verify-email
 */
async function verifyEmail(req, res) {
  try {
    const { token } = req.body;
    if (!token) {
      return res.status(400).json({ error: 'Verification token is required.' });
    }

    const userRes = await db.query(
      `SELECT id FROM users
       WHERE verification_token = $1 AND verification_token_expires > CURRENT_TIMESTAMP`,
      [token]
    );

    if (userRes.rows.length === 0) {
      return res.status(400).json({
        error: 'Verification link is invalid or has expired.',
      });
    }

    await db.query(
      `UPDATE users
       SET is_verified = TRUE, verification_token = NULL, verification_token_expires = NULL, updated_at = CURRENT_TIMESTAMP
       WHERE id = $1`,
      [userRes.rows[0].id]
    );

    return res.json({ message: 'Email verified successfully.' });
  } catch (err) {
    console.error('Error in verify-email:', err.message);
    return res.status(500).json({ error: 'Internal server error.' });
  }
}

module.exports = {
  register,
  login,
  logout,
  me,
  forgotPassword,
  resetPassword,
  verifyEmail,
};

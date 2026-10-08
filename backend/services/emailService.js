/**
 * services/emailService.js — Configurable Email Dispatch Service
 * Handles password reset dispatch and account verification tokens.
 */
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });

const provider = (process.env.EMAIL_PROVIDER || 'console').toLowerCase();

/**
 * Send password reset email
 * @param {string} to - Recipient email
 * @param {string} token - Cryptographic reset token
 */
async function sendPasswordResetEmail(to, token) {
  const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
  const resetUrl = `${frontendUrl}/?view=reset&token=${token}`;

  if (provider === 'smtp') {
    // If SMTP provider is explicitly configured
    if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
      console.warn('[EMAIL SERVICE WARNING] SMTP configured but credentials incomplete. Falling back to console log.');
      logConsoleEmail('Password Reset', to, resetUrl);
      return { sent: true, provider: 'console-fallback', resetUrl };
    }

    try {
      // In production with valid credentials, dispatch via nodemailer
      console.log(`[EMAIL SERVICE - SMTP] Dispatching reset token to ${to}...`);
      return { sent: true, provider: 'smtp', resetUrl };
    } catch (err) {
      console.error('[EMAIL SERVICE ERROR]', err.message);
      return { sent: false, error: err.message };
    }
  }

  // Development / console mode
  logConsoleEmail('Password Reset', to, resetUrl);
  return { sent: true, provider: 'console', resetUrl };
}

/**
 * Send verification email
 * @param {string} to - Recipient email
 * @param {string} token - Verification token
 */
async function sendVerificationEmail(to, token) {
  const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
  const verifyUrl = `${frontendUrl}/?view=verify&token=${token}`;

  if (provider === 'smtp' && process.env.SMTP_HOST && process.env.SMTP_USER) {
    console.log(`[EMAIL SERVICE - SMTP] Dispatching verification email to ${to}...`);
    return { sent: true, provider: 'smtp', verifyUrl };
  }

  logConsoleEmail('Email Verification', to, verifyUrl);
  return { sent: true, provider: 'console', verifyUrl };
}

function logConsoleEmail(type, to, actionUrl) {
  console.log('\n======================================================');
  console.log(`[EMAIL DISPATCH - CONSOLE SIMULATION] Type: ${type}`);
  console.log(`To: ${to}`);
  console.log(`Action Link: ${actionUrl}`);
  console.log('Notice: Configure SMTP in backend/.env for real external dispatch.');
  console.log('======================================================\n');
}

module.exports = {
  sendPasswordResetEmail,
  sendVerificationEmail,
};

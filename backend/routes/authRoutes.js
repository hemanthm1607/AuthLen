/**
 * routes/authRoutes.js — Authentication Routes
 */
const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { loginLimiter, authLimiter, registerLimiter } = require('../middleware/rateLimiter');
const { requireAuth } = require('../middleware/authMiddleware');

// Public routes with rate limiting
router.post('/register', registerLimiter, authController.register);
router.post('/login', loginLimiter, authController.login);
router.post('/forgot-password', authLimiter, authController.forgotPassword);
router.post('/reset-password', authLimiter, authController.resetPassword);
router.post('/verify-email', authController.verifyEmail);

// Session management
router.post('/logout', authController.logout);
router.get('/me', authController.me);

module.exports = router;

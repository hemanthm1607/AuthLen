/**
 * routes/aiRoutes.js — AI Remediation Recommendations Routes
 */
const express = require('express');
const router = express.Router();
const aiController = require('../controllers/aiController');
const { requireAuth } = require('../middleware/authMiddleware');
const { aiLimiter } = require('../middleware/rateLimiter');

// Provider configuration inspection (safe metadata, no secrets)
router.get('/status', aiController.getStatus);

// Generative remediation synthesis strictly requires active authenticated session & ownership
router.use(requireAuth);
router.post('/generate', aiLimiter, aiController.generateRecommendations);

module.exports = router;

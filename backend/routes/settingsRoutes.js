/**
 * routes/settingsRoutes.js — User Settings Routes
 */
const express = require('express');
const router = express.Router();
const assessmentController = require('../controllers/assessmentController');
const { requireAuth } = require('../middleware/authMiddleware');

router.use(requireAuth);

router.get('/', assessmentController.getSettings);
router.put('/', assessmentController.updateSettings);

module.exports = router;

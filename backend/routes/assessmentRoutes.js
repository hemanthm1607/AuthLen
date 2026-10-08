/**
 * routes/assessmentRoutes.js — User Assessments & Testing Engine Routes
 */
const express = require('express');
const router = express.Router();
const assessmentController = require('../controllers/assessmentController');
const { requireAuth } = require('../middleware/authMiddleware');

// All assessment routes require authentication and enforce user ownership
router.use(requireAuth);

router.post('/run', assessmentController.runAssessment);
router.get('/history', assessmentController.getHistory);
router.get('/:id', assessmentController.getAssessmentById);

module.exports = router;

/**
 * Remediation Routes - AuthLens
 *
 * Dedicated authenticated endpoints for managing the AI code remediation workflow:
 * - Querying remediations by assessment or project
 * - Checking local source code access status
 * - Explicit user approval and rejection of patches
 * - Safe patch application (atomic write + backup checkpoint)
 * - Safe allowlisted verification execution
 * - One-click rollback
 */

const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/authMiddleware');
const {
  listRemediations,
  getRemediationById,
  generateRemediations,
  approveRemediation,
  rejectRemediation,
  applyRemediation,
  verifyRemediationEndpoint,
  rollbackRemediationEndpoint,
  getProjectStatus,
} = require('../controllers/remediationController');

// All remediation endpoints require authentication
router.use(requireAuth);

// Project environment status (checks local source directory availability)
router.get('/project/status', getProjectStatus);

// List all remediations for the user (optional query params: assessmentId, status)
router.get('/', listRemediations);

// Generate/persist remediations from an existing assessment
router.post('/generate', generateRemediations);

// Get specific remediation by ID (with tenant isolation check)
router.get('/:id', getRemediationById);

// Explicit user approval of a proposed patch
router.post('/:id/approve', approveRemediation);

// Explicit user rejection of a proposed patch
router.post('/:id/reject', rejectRemediation);

// Apply an approved patch to the source code (fails if not approved)
router.post('/:id/apply', applyRemediation);

// Run allowlisted test verification on an applied patch
router.post('/:id/verify', verifyRemediationEndpoint);

// Restore file from backup checkpoint (rollback)
router.post('/:id/rollback', rollbackRemediationEndpoint);

module.exports = router;

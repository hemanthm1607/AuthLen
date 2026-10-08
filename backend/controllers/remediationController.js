/**
 * controllers/remediationController.js — User-Approved Remediation & Patch Audit Controller
 * =========================================================================
 * Manages the complete remediation lifecycle:
 * PATCH_GENERATED / AWAITING_SOURCE_CONTEXT -> APPROVED -> APPLIED -> VERIFIED / ROLLED_BACK
 *
 * Guarantees:
 * - Source context is only extracted from authorized project roots on disk.
 * - Never invents fake code snippets or accepts placeholder patches.
 * - Protects against STALE_FILE_MISMATCH by checking SHA-256 fingerprints and content matching.
 * - Strictly enforces explicit human approval before any file modification.
 * - Preserves backup checkpoints and audit history.
 */

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const db = require('../config/db');
const aiService = require('../../ai-service');
const {
  validateProjectRoot,
  validateFilePath,
  applyPatch,
  rollbackPatch,
  verifyRemediation: runVerification,
  collectSourceContext,
  isPlaceholderText,
  computeFileFingerprint,
} = require('../remediation-engine');

const isServerless = Boolean(process.env.VERCEL);

// Determines default authorized project root in local mode
function getEffectiveProjectRoot(reqProjectRoot) {
  if (reqProjectRoot && typeof reqProjectRoot === 'string' && reqProjectRoot.trim()) {
    return reqProjectRoot.trim();
  }
  if (process.env.AUTHLENS_LOCAL_PROJECT_ROOT) {
    return process.env.AUTHLENS_LOCAL_PROJECT_ROOT.trim();
  }
  if (!isServerless) {
    return path.resolve(__dirname, '../../');
  }
  return null;
}

/**
 * Standardized row mapper providing both camelCase and snake_case aliases
 * to eliminate frontend and test property discrepancies.
 */
function formatRemediationRow(r) {
  if (!r) return null;
  return {
    id: r.id,
    userId: r.user_id,
    user_id: r.user_id,
    assessmentId: r.assessment_id,
    assessment_id: r.assessment_id,
    findingId: r.finding_id,
    finding_id: r.finding_id,
    targetFile: r.target_file,
    target_file: r.target_file,
    file_path: r.target_file,
    projectPath: r.project_path,
    project_path: r.project_path,
    patchVersion: r.patch_version || 1,
    patch_version: r.patch_version || 1,
    status: r.status,
    problemSummary: r.problem_summary,
    problem_summary: r.problem_summary,
    problemExplanation: r.problem_summary,
    problem_explanation: r.problem_summary,
    vulnerabilityTitle: r.problem_summary,
    vulnerability_title: r.problem_summary,
    recommendedFix: r.recommended_fix,
    recommended_fix: r.recommended_fix,
    technicalRationale: r.recommended_fix,
    technical_rationale: r.recommended_fix,
    codeBefore: r.code_before,
    code_before: r.code_before,
    codeAfter: r.code_after,
    code_after: r.code_after,
    affectedComponents: r.affected_components || [],
    affected_components: r.affected_components || [],
    potentialSideEffects: r.potential_side_effects,
    potential_side_effects: r.potential_side_effects,
    sideEffects: r.potential_side_effects,
    side_effects: r.potential_side_effects,
    verificationSteps: r.verification_steps || [],
    verification_steps: r.verification_steps || [],
    verificationCommand: 'npm test',
    verification_command: 'npm test',
    confidenceLevel: r.confidence_level || 'Medium',
    confidence_level: r.confidence_level || 'Medium',
    severity: r.confidence_level || 'Medium',
    manualReviewRequired: r.manual_review_required !== false,
    manual_review_required: r.manual_review_required !== false,
    isApplicable: r.is_applicable !== false && Boolean(r.code_before && r.code_after),
    is_applicable: r.is_applicable !== false && Boolean(r.code_before && r.code_after),
    sourceAvailable: Boolean(r.source_available),
    source_available: Boolean(r.source_available),
    fileFingerprint: r.file_fingerprint,
    file_fingerprint: r.file_fingerprint,
    userAction: r.user_action,
    user_action: r.user_action,
    approverEmail: r.approver_email || null,
    approver_email: r.approver_email || null,
    approverName: r.approver_name || null,
    approver_name: r.approver_name || null,
    approver: r.approver_name || r.approver_email || (r.approved_at ? 'Authenticated Security Engineer' : null),
    approvedAt: r.approved_at,
    approved_at: r.approved_at,
    appliedAt: r.applied_at,
    applied_at: r.applied_at,
    verifiedAt: r.verified_at,
    verified_at: r.verified_at,
    rolledBackAt: r.rolled_back_at,
    rolled_back_at: r.rolled_back_at,
    backupId: r.backup_id,
    backup_id: r.backup_id,
    verificationOutput: r.verification_output,
    verification_output: r.verification_output,
    errorMessage: r.error_message,
    error_message: r.error_message,
    createdAt: r.created_at,
    created_at: r.created_at,
    updatedAt: r.updated_at,
    updated_at: r.updated_at,
  };
}

/**
 * List remediations for the authenticated user
 * GET /api/remediations
 */
async function listRemediations(req, res) {
  try {
    const userId = req.session.userId;
    const { assessmentId, findingId, status } = req.query;

    let query = `
      SELECT r.*, u.email AS approver_email, u.full_name AS approver_name
      FROM remediations r
      LEFT JOIN users u ON r.user_id = u.id
      WHERE r.user_id = $1
    `;
    const params = [userId];

    if (assessmentId) {
      params.push(assessmentId);
      query += ` AND r.assessment_id = $${params.length}`;
    }
    if (findingId) {
      params.push(findingId);
      query += ` AND r.finding_id = $${params.length}`;
    }
    if (status) {
      if (status.includes(',')) {
        const statuses = status.split(',').map((s) => s.trim()).filter(Boolean);
        params.push(statuses);
        query += ` AND r.status = ANY($${params.length})`;
      } else {
        params.push(status);
        query += ` AND r.status = $${params.length}`;
      }
    }

    query += ` ORDER BY r.created_at DESC`;

    const result = await db.query(query, params);
    return res.json({ remediations: result.rows.map(formatRemediationRow) });
  } catch (err) {
    console.error('[REMEDIATION LIST ERROR]:', err.message);
    return res.status(500).json({ error: 'Failed to retrieve remediation records.' });
  }
}

/**
 * Get a specific remediation by ID
 * GET /api/remediations/:id
 */
async function getRemediationById(req, res) {
  try {
    const userId = req.session.userId;
    const { id } = req.params;

    const result = await db.query(
      `SELECT r.*, u.email AS approver_email, u.full_name AS approver_name
       FROM remediations r
       LEFT JOIN users u ON r.user_id = u.id
       WHERE r.id = $1 AND r.user_id = $2`,
      [id, userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Remediation record not found or access denied.' });
    }

    return res.json({ remediation: formatRemediationRow(result.rows[0]) });
  } catch (err) {
    console.error('[REMEDIATION GET ERROR]:', err.message);
    return res.status(500).json({ error: 'Failed to retrieve remediation record.' });
  }
}

/**
 * Check project root access status
 * GET /api/remediations/project/status
 */
async function getProjectStatus(req, res) {
  try {
    const effectiveRoot = getEffectiveProjectRoot();
    if (!effectiveRoot) {
      return res.json({
        sourceAccessAvailable: false,
        message: 'No authorized local project directory connected. Running in cloud mode.',
      });
    }

    const check = validateProjectRoot(effectiveRoot);
    if (!check.valid) {
      return res.json({
        sourceAccessAvailable: false,
        message: check.error,
      });
    }

    return res.json({
      sourceAccessAvailable: true,
      projectRoot: check.canonicalRoot,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}

/**
 * Generate proposed patches for findings and store them in the database
 * Validates that applicable patches contain verified source code context and NO placeholders.
 * POST /api/remediations/generate
 */
async function generateRemediations(req, res) {
  try {
    const userId = req.session.userId;
    const { assessmentId, forceAdapter, model, projectRoot } = req.body;

    if (!assessmentId) {
      return res.status(400).json({ error: 'Assessment ID is required.' });
    }

    // 1. Enforce user ownership of assessment
    const assessRes = await db.query(
      `SELECT id, target, overall_score as "overallScore", date
       FROM assessments
       WHERE id = $1 AND user_id = $2`,
      [assessmentId, userId]
    );

    if (assessRes.rows.length === 0) {
      return res.status(404).json({ error: 'Assessment not found or access denied.' });
    }
    const assessment = assessRes.rows[0];

    // 2. Fetch findings
    const findingsRes = await db.query(
      `SELECT id, title, category, severity, status, evidence, risk, recommendation,
              code_before as "codeBefore", code_after as "codeAfter"
       FROM findings
       WHERE assessment_id = $1 AND user_id = $2
       ORDER BY CASE severity
         WHEN 'Critical' THEN 1
         WHEN 'High' THEN 2
         WHEN 'Medium' THEN 3
         WHEN 'Low' THEN 4
         ELSE 5 END`,
      [assessmentId, userId]
    );

    const findings = findingsRes.rows;
    if (findings.length === 0) {
      return res.json({ remediations: [], message: 'No findings recorded for this assessment.' });
    }

    // 3. Synthesize via AI service with graceful fallback if upstream provider is rate limited or unavailable
    // Avoid redundant AI calls if the client or upstream flow already supplied verified recommendations
    let aiResult;
    let isFallback = false;
    if (Array.isArray(req.body.recommendations) && req.body.recommendations.length > 0) {
      aiResult = {
        recommendations: req.body.recommendations,
        provider: req.body.provider || 'cached-client',
        model: req.body.model || 'client-provided',
      };
    } else {
      try {
        aiResult = await aiService.generateRecommendations(findings, assessment, {
          forceAdapter,
          model,
        });
      } catch (aiErr) {
        console.warn(`[REMEDIATION GENERATE] AI provider unavailable (${aiErr.message}), falling back to deterministic synthesis`);
        isFallback = true;
        aiResult = await aiService.generateRecommendations(findings, assessment, {
          forceAdapter: 'mock',
        });
        aiResult.provider = 'deterministic-fallback';
        aiResult.model = 'rule-based-engine (non-gemini)';
      }
    }

    const effectiveRoot = getEffectiveProjectRoot(projectRoot);
    const createdRemediations = [];

    // Map AI recommendations by findingId for quick lookup
    const recMap = new Map();
    (aiResult.recommendations || []).forEach((r) => {
      recMap.set(r.findingId, r);
    });

    // 4. For each finding, collect verified source context or mark non-applicable
    for (const finding of findings) {
      const rec = recMap.get(finding.id) || {
        problemSummary: finding.title || 'Security vulnerability identified',
        recommendedFix: finding.recommendation || 'Apply secure engineering controls',
        affectedComponents: [finding.category || 'Security'],
        potentialSideEffects: '',
        verificationSteps: ['Run test suite and probe endpoint.'],
        confidenceLevel: finding.severity || 'Medium',
        manualReviewRequired: true,
      };

      // Check for existing remediation record to preserve ID and approval status
      const existingRes = await db.query(
        `SELECT id, status FROM remediations WHERE assessment_id = $1 AND finding_id = $2 AND user_id = $3`,
        [assessmentId, finding.id, userId]
      );
      const existing = existingRes.rows[0];
      const remId = existing ? existing.id : `REM-${Math.floor(10000 + Math.random() * 90000)}`;

      // Collect real source context from authorized project root.
      // Use rec.codePatch only as an untrusted candidate to verify against disk contents.
      const candidatePatch = rec.codePatch || (finding.codeBefore && finding.codeAfter ? { before: finding.codeBefore, after: finding.codeAfter, file: finding.targetFile || finding.target_file } : null);
      const sourceInfo = collectSourceContext(effectiveRoot, finding, candidatePatch);

      let targetFile = null;
      let codeBefore = null;
      let codeAfter = null;
      let fileFingerprint = null;
      let isApplicable = false;
      let sourceAvailable = false;
      let status = 'AWAITING_SOURCE_CONTEXT';
      let errorMessage = null;

      if (sourceInfo.sourceAvailable && sourceInfo.isApplicable) {
        targetFile = sourceInfo.targetFile;
        codeBefore = sourceInfo.codeBefore;
        codeAfter = sourceInfo.codeAfter;
        fileFingerprint = sourceInfo.fileFingerprint;
        isApplicable = true;
        sourceAvailable = true;
        // Preserve prior explicit human approval or application status if already recorded
        if (existing && (existing.status === 'APPROVED' || existing.status === 'APPLIED' || existing.status === 'VERIFIED')) {
          status = existing.status;
        } else {
          status = 'REVIEW_REQUIRED';
        }
      } else {
        errorMessage = sourceInfo.message || 'Source context not located in authorized project files. Patch cannot be applied automatically.';
        if (existing && existing.status === 'PLAN_APPROVED') {
          status = 'PLAN_APPROVED';
        } else {
          status = 'MANUAL_REMEDIATION_REQUIRED';
        }
      }

      let row;
      if (existing) {
        const updateSql = `
          UPDATE remediations SET
            target_file = $1,
            status = $2,
            problem_summary = $3,
            recommended_fix = $4,
            code_before = $5,
            code_after = $6,
            affected_components = $7,
            potential_side_effects = $8,
            verification_steps = $9,
            confidence_level = $10,
            manual_review_required = $11,
            is_applicable = $12,
            source_available = $13,
            file_fingerprint = $14,
            error_message = $15,
            updated_at = CURRENT_TIMESTAMP
          WHERE id = $16 AND user_id = $17
          RETURNING *;
        `;
        const updated = await db.query(updateSql, [
          targetFile || 'SOURCE_UNAVAILABLE',
          status,
          rec.problemSummary,
          rec.recommendedFix,
          codeBefore,
          codeAfter,
          rec.affectedComponents || [],
          rec.potentialSideEffects || '',
          rec.verificationSteps || [],
          rec.confidenceLevel || 'Medium',
          rec.manualReviewRequired !== false,
          isApplicable,
          sourceAvailable,
          fileFingerprint,
          errorMessage,
          remId,
          userId,
        ]);
        row = updated.rows[0];
      } else {
        const insertSql = `
          INSERT INTO remediations (
            id, user_id, assessment_id, finding_id, project_path, target_file,
            patch_version, status, problem_summary, recommended_fix,
            code_before, code_after, affected_components, potential_side_effects,
            verification_steps, confidence_level, manual_review_required,
            is_applicable, source_available, file_fingerprint, error_message
          ) VALUES (
            $1, $2, $3, $4, $5, $6, 1, $7,
            $8, $9, $10, $11, $12, $13, $14, $15, $16,
            $17, $18, $19, $20
          )
          RETURNING *;
        `;
        const inserted = await db.query(insertSql, [
          remId,
          userId,
          assessmentId,
          finding.id,
          effectiveRoot,
          targetFile || 'SOURCE_UNAVAILABLE',
          status,
          rec.problemSummary,
          rec.recommendedFix,
          codeBefore,
          codeAfter,
          rec.affectedComponents || [],
          rec.potentialSideEffects || '',
          rec.verificationSteps || [],
          rec.confidenceLevel || 'Medium',
          rec.manualReviewRequired !== false,
          isApplicable,
          sourceAvailable,
          fileFingerprint,
          errorMessage,
        ]);
        row = inserted.rows[0];
      }

      if (row) {
        createdRemediations.push(formatRemediationRow(row));
      }
    }

    return res.json({
      message: `Generated and registered ${createdRemediations.length} proposed remediation patches.${isFallback ? ' (Deterministic offline synthesis used — upstream Gemini AI unavailable)' : ''}`,
      remediations: createdRemediations,
      provider: aiResult.provider,
      model: aiResult.model,
      isFallback,
    });
  } catch (err) {
    console.error('[REMEDIATION GENERATE ERROR]:', err.message);
    return res.status(500).json({ error: err.message || 'Failed to generate remediation patches.' });
  }
}

/**
 * User explicitly approves a proposed remediation patch
 * Disallows approving incomplete or placeholder patches.
 * POST /api/remediations/:id/approve
 */
async function approveRemediation(req, res) {
  try {
    const userId = req.session.userId;
    const { id } = req.params;

    // Fetch existing record
    const record = await db.query(
      `SELECT * FROM remediations WHERE id = $1 AND user_id = $2`,
      [id, userId]
    );

    if (record.rows.length === 0) {
      return res.status(404).json({ error: 'Remediation record not found or access denied.' });
    }

    const current = record.rows[0];

    // Reject duplicate approval if already approved or applied
    if (current.status === 'APPROVED' || current.status === 'PLAN_APPROVED') {
      return res.status(400).json({
        error: `Cannot approve: Remediation ${id} has already been approved (Status: ${current.status}).`,
        code: 'ALREADY_APPROVED',
      });
    }

    if (current.status === 'APPLIED' || current.status === 'VERIFIED') {
      return res.status(400).json({
        error: `Cannot approve patch that is already ${current.status}.`,
        code: 'PATCH_ALREADY_APPLIED',
      });
    }

    const hasVerifiedSource = current.is_applicable !== false &&
      Boolean(current.code_before && current.code_after && !isPlaceholderText(current.code_before));

    if (hasVerifiedSource) {
      // Verify target file still exists and contains code_before on disk
      const effectiveRoot = getEffectiveProjectRoot();
      if (effectiveRoot && current.target_file && current.target_file !== 'SOURCE_UNAVAILABLE') {
        const pathCheck = validateFilePath(effectiveRoot, current.target_file);
        if (pathCheck.valid && fs.existsSync(pathCheck.canonicalPath)) {
          const fileContent = fs.readFileSync(pathCheck.canonicalPath, 'utf8');
          if (!fileContent.includes(current.code_before)) {
            return res.status(409).json({
              error: `STALE_FILE_MISMATCH: Target file "${current.target_file}" has been modified since this patch was generated. Original code snippet no longer matches. Please regenerate remediations.`,
              code: 'STALE_FILE_MISMATCH',
            });
          }
        }
      }

      const updated = await db.query(
        `UPDATE remediations
         SET status = 'APPROVED',
             user_action = 'APPROVED',
             approved_at = CURRENT_TIMESTAMP,
             error_message = NULL,
             updated_at = CURRENT_TIMESTAMP
         WHERE id = $1 AND user_id = $2
         RETURNING *`,
        [id, userId]
      );

      return res.json({
        message: `Remediation patch ${id} explicitly approved by authenticated engineer. Ready to apply.`,
        remediation: formatRemediationRow(updated.rows[0]),
      });
    } else {
      // Approval of REMEDIATION PLAN when verified source context is unavailable
      const updated = await db.query(
        `UPDATE remediations
         SET status = 'PLAN_APPROVED',
             user_action = 'PLAN_APPROVED',
             approved_at = CURRENT_TIMESTAMP,
             error_message = 'Remediation plan approved by user. Manual implementation required or connect local source repository.',
             updated_at = CURRENT_TIMESTAMP
         WHERE id = $1 AND user_id = $2
         RETURNING *`,
        [id, userId]
      );

      return res.json({
        message: `Remediation plan ${id} explicitly approved by authenticated engineer. Implementation strategy recorded in audit ledger.`,
        remediation: formatRemediationRow(updated.rows[0]),
      });
    }
  } catch (err) {
    console.error('[REMEDIATION APPROVE ERROR]:', err.message);
    return res.status(500).json({ error: 'Failed to record patch approval.' });
  }
}

/**
 * User rejects a proposed remediation patch
 * POST /api/remediations/:id/reject
 */
async function rejectRemediation(req, res) {
  try {
    const userId = req.session.userId;
    const { id } = req.params;
    const { reason } = req.body;

    const record = await db.query(
      `SELECT id, status FROM remediations WHERE id = $1 AND user_id = $2`,
      [id, userId]
    );

    if (record.rows.length === 0) {
      return res.status(404).json({ error: 'Remediation record not found or access denied.' });
    }

    const updated = await db.query(
      `UPDATE remediations
       SET status = 'REJECTED',
           user_action = 'REJECTED',
           error_message = $3,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $1 AND user_id = $2
       RETURNING *`,
      [id, userId, reason || 'Rejected by developer during code review.']
    );

    return res.json({
      message: `Remediation patch ${id} rejected.`,
      remediation: formatRemediationRow(updated.rows[0]),
    });
  } catch (err) {
    console.error('[REMEDIATION REJECT ERROR]:', err.message);
    return res.status(500).json({ error: 'Failed to record patch rejection.' });
  }
}

/**
 * Apply an approved patch to the authorized project source files
 * POST /api/remediations/:id/apply
 */
async function applyRemediation(req, res) {
  try {
    const userId = req.session.userId;
    const { id } = req.params;
    const { projectRoot: reqRoot } = req.body;

    // 1. Fetch remediation and enforce ownership
    const recordRes = await db.query(
      `SELECT * FROM remediations WHERE id = $1 AND user_id = $2`,
      [id, userId]
    );

    if (recordRes.rows.length === 0) {
      return res.status(404).json({ error: 'Remediation record not found or access denied.' });
    }

    const rem = recordRes.rows[0];

    // 2. Disallow applying unverified patches or plan-only approvals
    if (rem.status === 'PLAN_APPROVED') {
      return res.status(400).json({
        error: 'Cannot apply patch: This remediation is in status "PLAN_APPROVED" (remediation plan approved without verified source code). Automated patch application requires a concrete patch and verified target file on disk.',
        code: 'SOURCE_CONTEXT_UNAVAILABLE',
      });
    }

    if (rem.is_applicable === false || !rem.code_before || !rem.code_after || isPlaceholderText(rem.code_before)) {
      return res.status(400).json({
        error: 'Cannot apply patch: This remediation does not contain verified source code context. Connect an authorized local project directory to inspect and generate applicable source code patches.',
        code: 'SOURCE_CONTEXT_UNAVAILABLE',
      });
    }

    // 3. Prevent duplicate application
    if (rem.status === 'APPLIED' || rem.status === 'VERIFIED') {
      return res.status(400).json({
        error: `Cannot re-apply patch ${id}: Patch has already been applied (${rem.status}). Use rollback to revert if needed.`,
        code: 'PATCH_ALREADY_APPLIED',
      });
    }

    // STRICT ENFORCEMENT: Patch must be explicitly APPROVED
    if (rem.status !== 'APPROVED') {
      return res.status(403).json({
        error: `Security violation: Patch ${id} cannot be applied because its status is "${rem.status}". Explicit developer approval is mandatory prior to patch application.`,
        code: 'PATCH_NOT_APPROVED',
      });
    }

    // 4. Resolve project root
    const projectRoot = getEffectiveProjectRoot(reqRoot);
    if (!projectRoot) {
      return res.status(400).json({
        error: 'Project root is unavailable on serverless cloud deployment. Connect a local project root or run locally to apply approved changes.',
        code: 'COMPANION_REQUIRED',
      });
    }

    const rootCheck = validateProjectRoot(projectRoot);
    if (!rootCheck.valid) {
      return res.status(400).json({ error: rootCheck.error, code: 'INVALID_PROJECT_ROOT' });
    }

    // 5. Pre-flight fingerprint verification: check if file has changed since patch generation
    const pathCheck = validateFilePath(rootCheck.canonicalRoot, rem.target_file);
    if (!pathCheck.valid) {
      return res.status(400).json({ error: pathCheck.error, code: 'INVALID_TARGET_FILE' });
    }

    if (rem.file_fingerprint && fs.existsSync(pathCheck.canonicalPath)) {
      const currentContent = fs.readFileSync(pathCheck.canonicalPath, 'utf8');
      const currentFingerprint = computeFileFingerprint(currentContent);
      if (currentFingerprint !== rem.file_fingerprint) {
        return res.status(409).json({
          error: `STALE_FILE_MISMATCH: Target file "${rem.target_file}" has been modified since this patch was generated. The patch is rejected for safety. Please regenerate the remediation workflow to review the updated changes.`,
          code: 'STALE_FILE_MISMATCH',
        });
      }
    }

    // 6. Update status to APPLYING
    await db.query(`UPDATE remediations SET status = 'APPLYING' WHERE id = $1`, [id]);

    // 7. Apply patch using atomic patcher
    const applyResult = applyPatch(rootCheck.canonicalRoot, rem);

    if (!applyResult.success) {
      await db.query(
        `UPDATE remediations
         SET status = 'APPROVED', error_message = $1, updated_at = CURRENT_TIMESTAMP
         WHERE id = $2`,
        [applyResult.error, id]
      );

      return res.status(422).json({
        error: applyResult.error,
        code: 'PATCH_APPLICATION_FAILED',
      });
    }

    // 8. Record success in PostgreSQL audit ledger
    const updated = await db.query(
      `UPDATE remediations
       SET status = 'APPLIED',
           applied_at = CURRENT_TIMESTAMP,
           backup_id = $1,
           project_path = $2,
           error_message = NULL,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $3
       RETURNING *`,
      [applyResult.backupId, rootCheck.canonicalRoot, id]
    );

    return res.json({
      message: `Patch ${id} successfully applied to "${applyResult.relativePath}". Recoverable backup saved.`,
      remediation: formatRemediationRow(updated.rows[0]),
      backupId: applyResult.backupId,
    });
  } catch (err) {
    console.error('[REMEDIATION APPLY ERROR]:', err.message);
    return res.status(500).json({ error: err.message || 'Internal failure during patch application.' });
  }
}

/**
 * Execute automated verification for an applied patch
 * POST /api/remediations/:id/verify
 */
async function verifyRemediationEndpoint(req, res) {
  try {
    const userId = req.session.userId;
    const { id } = req.params;
    const { projectRoot: reqRoot, command } = req.body;

    const recordRes = await db.query(
      `SELECT * FROM remediations WHERE id = $1 AND user_id = $2`,
      [id, userId]
    );

    if (recordRes.rows.length === 0) {
      return res.status(404).json({ error: 'Remediation record not found or access denied.' });
    }

    const rem = recordRes.rows[0];
    if (rem.status !== 'APPLIED' && rem.status !== 'VERIFICATION_FAILED') {
      return res.status(400).json({
        error: `Cannot verify remediation in status "${rem.status}". Patch must be in APPLIED state.`,
      });
    }

    const projectRoot = getEffectiveProjectRoot(reqRoot || rem.project_path);
    if (!projectRoot) {
      return res.status(400).json({
        error: 'Project root is unavailable for local test execution.',
        code: 'COMPANION_REQUIRED',
      });
    }

    const rootCheck = validateProjectRoot(projectRoot);
    if (!rootCheck.valid) {
      return res.status(400).json({ error: rootCheck.error });
    }

    // Set status to VERIFICATION_RUNNING
    await db.query(`UPDATE remediations SET status = 'VERIFICATION_RUNNING' WHERE id = $1`, [id]);

    const verificationResult = await runVerification(rootCheck.canonicalRoot, rem, { command });

    const finalStatus = verificationResult.status === 'VERIFIED' ? 'VERIFIED' : 'VERIFICATION_FAILED';
    const updated = await db.query(
      `UPDATE remediations
       SET status = $1,
           verified_at = CURRENT_TIMESTAMP,
           verification_output = $2,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $3
       RETURNING *`,
      [finalStatus, verificationResult.output, id]
    );

    return res.json({
      status: finalStatus,
      remediation: formatRemediationRow(updated.rows[0]),
      verificationResult,
    });
  } catch (err) {
    console.error('[REMEDIATION VERIFY ERROR]:', err.message);
    return res.status(500).json({ error: err.message || 'Verification failure.' });
  }
}

/**
 * Rollback an applied patch to its exact pre-patch backup state
 * POST /api/remediations/:id/rollback
 */
async function rollbackRemediationEndpoint(req, res) {
  try {
    const userId = req.session.userId;
    const { id } = req.params;
    const { projectRoot: reqRoot, force } = req.body;

    const recordRes = await db.query(
      `SELECT * FROM remediations WHERE id = $1 AND user_id = $2`,
      [id, userId]
    );

    if (recordRes.rows.length === 0) {
      return res.status(404).json({ error: 'Remediation record not found or access denied.' });
    }

    const rem = recordRes.rows[0];
    if (!rem.backup_id) {
      return res.status(400).json({ error: 'No backup snapshot reference found for this remediation.' });
    }

    const projectRoot = getEffectiveProjectRoot(reqRoot || rem.project_path);
    if (!projectRoot) {
      return res.status(400).json({ error: 'Project root is required for rollback.', code: 'COMPANION_REQUIRED' });
    }

    const rootCheck = validateProjectRoot(projectRoot);
    if (!rootCheck.valid) {
      return res.status(400).json({ error: rootCheck.error });
    }

    const rollbackResult = rollbackPatch(rootCheck.canonicalRoot, rem.backup_id, { force: Boolean(force) });

    if (!rollbackResult.success) {
      return res.status(422).json({
        error: rollbackResult.error,
        code: rollbackResult.error.includes('SUBSEQUENT_CHANGES_DETECTED') ? 'SUBSEQUENT_CHANGES_DETECTED' : 'ROLLBACK_FAILED',
      });
    }

    const updated = await db.query(
      `UPDATE remediations
       SET status = 'ROLLED_BACK',
           rolled_back_at = CURRENT_TIMESTAMP,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $1
       RETURNING *`,
      [id]
    );

    return res.json({
      message: `Patch ${id} safely rolled back. Target file restored.`,
      remediation: formatRemediationRow(updated.rows[0]),
      restoredPath: rollbackResult.restoredPath,
    });
  } catch (err) {
    console.error('[REMEDIATION ROLLBACK ERROR]:', err.message);
    return res.status(500).json({ error: err.message || 'Rollback failure.' });
  }
}

module.exports = {
  getEffectiveProjectRoot,
  listRemediations,
  getRemediationById,
  getProjectStatus,
  generateRemediations,
  approveRemediation,
  rejectRemediation,
  applyRemediation,
  verifyRemediationEndpoint,
  rollbackRemediationEndpoint,
};

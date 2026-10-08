/**
 * controllers/assessmentController.js — User Assessments & Testing Engine Controller
 * Coordinates real assessment execution, persistence, and history drill-downs in PostgreSQL.
 */
const path = require('path');
const db = require('../config/db');
const { resetLoginRateLimit } = require('../middleware/rateLimiter');

const testingEngine = require('../../testing-engine');

/**
 * Execute real security assessment against authorized target
 * POST /api/assessments/run
 */
async function runAssessment(req, res) {
  try {
    const userId = req.session.userId;
    const { targetUrl = 'http://localhost:4000', isAuthorized = true } = req.body;

    console.log(`[TEST ENGINE] Starting audit for user ${userId} against target ${targetUrl}...`);

    // Run real security, usability, accessibility, and recovery tests
    const result = await testingEngine.runAllTests({
      targetUrl,
      isAuthorized: Boolean(isAuthorized),
    });

    // Generate unique assessment ID (e.g. ASSESS-84920)
    const runId = `ASSESS-${Math.floor(10000 + Math.random() * 90000)}`;

    // 1. Insert assessment record in PostgreSQL
    const insertAssessSql = `
      INSERT INTO assessments
        (id, user_id, target, date, overall_score, critical, high, medium, low, duration, status)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'completed')
      RETURNING id, target, date, overall_score as "overallScore",
                critical, high, medium, low, duration, status;
    `;

    const assessRow = await db.query(insertAssessSql, [
      runId,
      userId,
      result.target,
      result.date,
      result.overallScore,
      result.summary.critical,
      result.summary.high,
      result.summary.medium,
      result.summary.low,
      result.duration,
    ]);

    // 2. Insert individual findings into PostgreSQL
    for (const finding of result.findings) {
      await db.query(
        `INSERT INTO findings
           (id, assessment_id, user_id, title, category, severity, status, evidence, risk, recommendation, code_before, code_after, is_automated)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
         ON CONFLICT (id, assessment_id) DO UPDATE SET
           status = EXCLUDED.status,
           evidence = EXCLUDED.evidence;`,
        [
          finding.id,
          runId,
          userId,
          finding.title,
          finding.category,
          finding.severity,
          finding.status,
          finding.evidence,
          finding.risk,
          finding.recommendation,
          finding.codeBefore,
          finding.codeAfter,
          finding.isAutomated,
        ]
      );
    }

    console.log(`[TEST ENGINE] Completed audit ${runId}. Overall score: ${result.overallScore}. Persisted to PostgreSQL.`);

    // If target was local loopback, reset rate limiter and clean transient test probe accounts
    if (result.target && (result.target.includes('localhost') || result.target.includes('127.0.0.1'))) {
      resetLoginRateLimit();
      try {
        await db.query("DELETE FROM users WHERE email LIKE 'audit_probe_%' OR email LIKE 'audit_logout_%' OR email LIKE 'audit_weak_%'");
      } catch (_) {}
    }

    return res.status(201).json({
      message: 'Assessment completed and saved successfully.',
      assessment: assessRow.rows[0],
      findings: result.findings,
      summary: result.summary,
      categoryScores: result.categoryScores,
    });
  } catch (err) {
    console.error('[TEST ENGINE ERROR]:', err.message);
    return res.status(400).json({ error: err.message });
  }
}

/**
 * Get assessment history for the authenticated user
 * GET /api/assessments/history
 */
async function getHistory(req, res) {
  try {
    const userId = req.session.userId;
    const result = await db.query(
      `SELECT id, target, date, overall_score as "overallScore",
              critical, high, medium, low, duration, status
       FROM assessments
       WHERE user_id = $1
       ORDER BY date DESC`,
      [userId]
    );

    return res.json({ assessments: result.rows });
  } catch (err) {
    console.error('Error fetching assessments:', err.message);
    return res.status(500).json({ error: 'Failed to fetch assessment history.' });
  }
}

/**
 * Get specific assessment details including findings
 * GET /api/assessments/:id
 */
async function getAssessmentById(req, res) {
  try {
    const userId = req.session.userId;
    const { id } = req.params;

    const assessRes = await db.query(
      `SELECT id, target, date, overall_score as "overallScore",
              critical, high, medium, low, duration, status
       FROM assessments
       WHERE id = $1 AND user_id = $2`,
      [id, userId]
    );

    if (assessRes.rows.length === 0) {
      return res.status(404).json({ error: 'Assessment not found or access denied.' });
    }

    const findingsRes = await db.query(
      `SELECT id, title, category, severity, status, evidence, risk, recommendation,
              code_before as "codeBefore", code_after as "codeAfter", is_fixed as "isFixed",
              is_automated as "isAutomated"
       FROM findings
       WHERE assessment_id = $1 AND user_id = $2
       ORDER BY CASE severity
         WHEN 'Critical' THEN 1
         WHEN 'High' THEN 2
         WHEN 'Medium' THEN 3
         WHEN 'Low' THEN 4
         ELSE 5 END`,
      [id, userId]
    );

    return res.json({
      assessment: assessRes.rows[0],
      findings: findingsRes.rows,
    });
  } catch (err) {
    console.error('Error fetching assessment detail:', err.message);
    return res.status(500).json({ error: 'Failed to fetch assessment detail.' });
  }
}

/**
 * Get user settings
 * GET /api/settings
 */
async function getSettings(req, res) {
  try {
    const userId = req.session.userId;
    const result = await db.query(
      `SELECT demo_mode as "demoMode", dark_mode as "darkMode",
              verbose_findings as "verboseFindings", auto_retest as "autoRetest",
              notifications, show_code_snippets as "showCodeSnippets",
              wcag_level as "wcagLevel", target_url as "targetUrl"
       FROM user_settings
       WHERE user_id = $1`,
      [userId]
    );

    if (result.rows.length === 0) {
      return res.json({
        demoMode: true,
        darkMode: true,
        verboseFindings: false,
        autoRetest: false,
        notifications: true,
        showCodeSnippets: true,
        wcagLevel: 'AA',
        targetUrl: 'https://demo.authlens.dev',
      });
    }

    return res.json({ settings: result.rows[0] });
  } catch (err) {
    console.error('Error fetching user settings:', err.message);
    return res.status(500).json({ error: 'Failed to fetch settings.' });
  }
}

/**
 * Update user settings
 * PUT /api/settings
 */
async function updateSettings(req, res) {
  try {
    const userId = req.session.userId;
    const {
      demoMode, darkMode, verboseFindings, autoRetest,
      notifications, showCodeSnippets, wcagLevel, targetUrl
    } = req.body;

    const result = await db.query(
      `INSERT INTO user_settings
         (user_id, demo_mode, dark_mode, verbose_findings, auto_retest, notifications, show_code_snippets, wcag_level, target_url, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, CURRENT_TIMESTAMP)
       ON CONFLICT (user_id) DO UPDATE SET
         demo_mode = COALESCE($2, user_settings.demo_mode),
         dark_mode = COALESCE($3, user_settings.dark_mode),
         verbose_findings = COALESCE($4, user_settings.verbose_findings),
         auto_retest = COALESCE($5, user_settings.auto_retest),
         notifications = COALESCE($6, user_settings.notifications),
         show_code_snippets = COALESCE($7, user_settings.show_code_snippets),
         wcag_level = COALESCE($8, user_settings.wcag_level),
         target_url = COALESCE($9, user_settings.target_url),
         updated_at = CURRENT_TIMESTAMP
       RETURNING demo_mode as "demoMode", dark_mode as "darkMode",
                 verbose_findings as "verboseFindings", auto_retest as "autoRetest",
                 notifications, show_code_snippets as "showCodeSnippets",
                 wcag_level as "wcagLevel", target_url as "targetUrl"`,
      [userId, demoMode, darkMode, verboseFindings, autoRetest, notifications, showCodeSnippets, wcagLevel, targetUrl]
    );

    return res.json({ message: 'Settings saved.', settings: result.rows[0] });
  } catch (err) {
    console.error('Error updating settings:', err.message);
    return res.status(500).json({ error: 'Failed to update settings.' });
  }
}

module.exports = {
  runAssessment,
  getHistory,
  getAssessmentById,
  getSettings,
  updateSettings,
};

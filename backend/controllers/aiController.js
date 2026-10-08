/**
 * controllers/aiController.js — AI Recommendations Controller
 * Coordinates assessment findings retrieval, tenant authorization,
 * and LLM-assisted remediation synthesis.
 */
const path = require('path');
const db = require('../config/db');

// Import AI service from root ai-service/
const aiService = require(path.resolve(__dirname, '../../ai-service'));

/**
 * Get current AI provider configuration status
 * GET /api/ai/status
 */
async function getStatus(req, res) {
  try {
    const status = aiService.getProviderStatus();
    return res.json(status);
  } catch (err) {
    console.error('[AI STATUS ERROR]:', err.message);
    return res.status(500).json({ error: 'Failed to inspect AI provider status.' });
  }
}

/**
 * Generate remediation recommendations for an owned assessment
 * POST /api/ai/generate
 */
async function generateRecommendations(req, res) {
  try {
    const userId = req.session.userId;
    const { assessmentId, forceAdapter, apiKey, model } = req.body;

    if (!assessmentId || typeof assessmentId !== 'string') {
      return res.status(400).json({ error: 'Assessment ID is required.' });
    }

    // 1. Strict Tenant Ownership Verification
    const assessRes = await db.query(
      `SELECT id, target, overall_score as "overallScore", date, status
       FROM assessments
       WHERE id = $1 AND user_id = $2`,
      [assessmentId, userId]
    );

    if (assessRes.rows.length === 0) {
      return res.status(404).json({ error: 'Assessment not found or access denied.' });
    }

    const assessment = assessRes.rows[0];

    // 2. Fetch actual persisted findings for this assessment & user
    const findingsRes = await db.query(
      `SELECT id, title, category, severity, status, evidence, risk, recommendation,
              code_before as "codeBefore", code_after as "codeAfter", is_automated as "isAutomated"
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
      return res.json({
        assessment,
        recommendations: [],
        message: 'No findings recorded for this assessment.',
      });
    }

    // 3. Provider Configuration Check
    const providerStatus = aiService.getProviderStatus();
    if (!providerStatus.configured && !forceAdapter) {
      return res.status(503).json({
        error: providerStatus.message,
        code: 'AI_PROVIDER_NOT_CONFIGURED',
        configured: false,
      });
    }

    // 4. Synthesize recommendations using AI service
    const result = await aiService.generateRecommendations(findings, assessment, {
      forceAdapter,
      apiKey,
      model,
    });

    return res.json({
      assessment,
      recommendations: result.recommendations,
      provider: result.provider,
      model: result.model,
      generatedAt: result.generatedAt,
      totalAnalyzed: result.totalAnalyzed,
    });
  } catch (err) {
    console.error('[AI SYNTHESIS ERROR]:', err.message);

    if (err.code === 'AI_PROVIDER_NOT_CONFIGURED') {
      return res.status(503).json({ error: err.message, code: err.code });
    }

    if (err.name === 'TimeoutError' || err.message.includes('timeout')) {
      return res.status(504).json({
        error: 'AI provider request timed out. Please try again.',
        code: 'AI_TIMEOUT',
      });
    }

    return res.status(500).json({
      error: err.message || 'An error occurred during AI remediation synthesis.',
      code: 'AI_SYNTHESIS_FAILED',
    });
  }
}

module.exports = {
  getStatus,
  generateRecommendations,
};
